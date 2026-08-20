import type { FastifyInstance, FastifyRequest } from "fastify";
import type { WebSocket } from "ws";
import {
  registerStatsProvider,
  wsConnectionsTotal,
  wsDisconnectionsTotal,
  heartbeatReapedTotal,
  registerErrorsTotal,
  roomsCreatedTotal,
  signalsRelayedTotal,
  bannedIpConnectionsRejectedTotal,
  chatMessagesBlockedTotal,
} from "./metrics.js";
import { signToken, verifyToken, requireAdmin } from "./auth.js";
import {
  createAccount,
  verifyAccountLogin,
  getPublicAccountById,
  isNameReserved,
  USERNAME_RE,
} from "./accountStore.js";
import {
  loadPersistedChat,
  savePersistedChat,
  deletePersistedChat,
  type ChatMessage,
} from "./chatStore.js";
import {
  loadPersistedAnnouncement,
  savePersistedAnnouncement,
  deletePersistedAnnouncement,
  type Announcement,
  type AnnouncementButtonAction,
  type AnnouncementColor,
  type AnnouncementVisibility,
  type AnnouncementSound,
} from "./announcementStore.js";
import {
  isIpBanned,
  isValidIp,
  listBans,
  banIp,
  unbanIp,
  listBannedWords,
  setBannedWords,
  findBannedWord,
} from "./moderationStore.js";
import { MONGO_ENABLED, isMongoConnected } from "./mongo.js";
import {
  wsGlobalLimiter,
  wsRegisterLimiter,
  wsJoinLimiter,
  wsChatLimiter,
  wsSignalLimiter,
  wsToggleLimiter,
  consumeRateLimit,
} from "./rateLimiter.js";

const HANDLE_RE = /^[a-zA-Z0-9_-]{1,32}$/;
const CLIENT_ID_RE = /^[a-zA-Z0-9-]{8,64}$/;
const HEARTBEAT_INTERVAL_MS = 25_000;
const CHAT_MAX_LEN = 500;
const ANNOUNCEMENT_TEXT_MAX_LEN = 300;
const ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN = 40;
const BAN_REASON_MAX_LEN = 200;
// Close code used to reject a connection from a banned IP — distinct from
// SUPERSEDED_CLOSE_CODE below so the client can tell them apart and show the
// right message instead of quietly retrying (see signalingClient.ts).
const BANNED_CLOSE_CODE = 4003;
// Chat history is kept in memory for the room's lifetime (until it empties
// out — see leaveRoom) and mirrored via chatStore.ts (Redis if configured,
// otherwise a per-room disk file) so it also survives the signaling process
// itself restarting (deploy, crash) while the room stays populated. Capped
// so a long-lived room's history can't grow forever.
const ROOM_CHAT_HISTORY_LIMIT = 300;

// Any handle starting with this is private: excluded from the public /rooms
// listing. This is the only thing that makes a room private — there's no
// separate flag to keep in sync, so it can't drift from the handle itself.
const PRIVATE_PREFIX = "priv-";

function isPrivateRoom(room: string): boolean {
  return room.startsWith(PRIVATE_PREFIX);
}

// A non-updated ("old format") client — and any guest before its very first
// guest-token round-trip — never presents a token at all, so the only thing
// it can offer to reclaim a stale connection is the plain clientId it was
// given (see the "register" handler's existingProtected check below). That
// bare match is inherently spoofable by anyone who has merely seen that id
// (it's visible in every room's peer list), which is exactly the attack the
// token system exists to close — but *only once a session has actually
// verified a token*. Set this to "false" to close that residual gap
// entirely: reclaiming an existing session then always requires proving it
// via a matching account/guest token (see isSameOwner), full stop. The
// trade-off is that a non-updated client — which will never have such a
// token to present — loses seamless reconnect: a reload or a rename no
// longer reclaims its old spot, it just starts over as a new guest each
// time. Registration itself is never refused either way; this only governs
// how strictly *reclaiming* an existing one is guarded. Defaults to "true"
// so existing, non-updated clients keep working exactly as they always
// have.
const ALLOW_OLD_CLIENTS_GUEST_SYSTEM = process.env.ALLOW_OLD_CLIENTS_GUEST_SYSTEM !== "false";

interface ClientInfo {
  id: string;
  name: string | null;
  room: string | null;
  sharing: boolean;
  mic: boolean;
  isAlive: boolean;
  socket: WebSocket;
  // The connecting IP (see request.ip in the "/ws" handler below). Never
  // sent to regular participants — only /admin/rooms exposes it, so a
  // moderator can ban whoever's misbehaving straight from the room list.
  ip: string;
  // Set for a moderator connection opened via "admin-join" (see
  // registerAdminRoutes below). Moderator sockets ride the exact same room
  // machinery as a real participant — they're added to the room's socket
  // set and included unfiltered in the peers array sent to real
  // participants, which is what makes broadcasters' existing
  // "open a connection to every peer I see" logic transparently push them
  // an offer too. The `role: "moderator"` tag on that peer entry (see
  // peerSummary) is what the *client* then uses to hide it from the visible
  // participant list and count — nothing server-side ever filters a
  // moderator out of a room, only out of numbers/lists real users see.
  isModerator?: boolean;
  // Set when this connection registered with a valid account JWT (see the
  // "register" case below) — lets the reserved-name check tell a genuine
  // account owner apart from anyone else trying to use their name, and is
  // what admin-join checks in place of a separate admin token system.
  accountId?: string;
  flags?: string[];
  // Every non-account connection gets a guest identity (see "register"
  // below) — either freshly minted for this connection, or recovered from a
  // guest token the client already had. `guestVerified` is what separates
  // the two: true only when `guestId` came from a token this connection
  // actually presented (proof it's the same guest as before), false when it
  // was just made up now because nothing was presented. That distinction is
  // the whole point of isSameOwner below — a freshly-made-up id never
  // matches anyone else's, guessed or not, so it can't be used to claim
  // someone else's session.
  guestId?: string;
  guestVerified?: boolean;
  // Stable per-connection key for the message-rate limiters in
  // rateLimiter.ts — set once at connect time and never touched again.
  // Deliberately *not* the same as `id`: `id` can be reassigned mid-life
  // when this connection reclaims a previous session's clientId (see
  // "register" below), and a rate-limit bucket should stay tied to this one
  // physical socket regardless of what identity it's currently wearing —
  // otherwise reclaiming an id would also silently inherit (or hand off)
  // whatever budget that id's bucket happened to have left.
  rateLimitKey: string;
}

interface RoomInfo {
  sockets: Set<WebSocket>;
  createdAt: number;
  messages: ChatMessage[];
  // Room-scoped display-name reservations — separate from any other room,
  // so the same name can be used freely in two different rooms at once (see
  // isSameOwner and the "join"/"register" handlers). Keyed the same way the
  // old global `namesInUse` map used to be (lowercased name -> holder).
  names: Map<string, WebSocket>;
}

// Whether `challenger` may take over `existing`'s session/room slot — used
// wherever that has to be told apart from a stranger merely presenting the
// same display name or a guessed/observed connection id (see the "register"
// and "join" handlers). Only `challenger`'s side of the proof matters: for
// an account, its accountId (always proven — it only ever comes from a
// verified account JWT); for a guest, a *verified* guestId matching
// `existing`'s (proven by having just presented the exact token that was
// privately handed to whoever `existing` is — nobody else could produce
// it). `existing` itself doesn't need to be verified — plenty of live
// sessions never re-prove themselves after their first connection, and
// that's fine, since it's `challenger` making the claim here. What must
// never count is an *unverified* guestId on the challenger's side, freshly
// made up for this connection: unlike a verified one, that proves nothing
// about who's on the other end.
function isSameOwner(existing: ClientInfo, challenger: ClientInfo): boolean {
  if (existing.accountId || challenger.accountId) {
    return Boolean(challenger.accountId) && existing.accountId === challenger.accountId;
  }
  return Boolean(challenger.guestVerified) && existing.guestId === challenger.guestId;
}

// Announcement/AnnouncementButtonAction/AnnouncementColor/
// AnnouncementVisibility/AnnouncementSound come from announcementStore.js
// (imported above) — that's also where the persisted copy lives, so both
// sides of the load/save round-trip share one type definition.
const ANNOUNCEMENT_ACTIONS = new Set<AnnouncementButtonAction>([
  "open-new-tab",
  "open-same-tab",
  "reload",
]);
const ANNOUNCEMENT_COLORS = new Set<AnnouncementColor>(["green", "red", "blue"]);
const ANNOUNCEMENT_VISIBILITIES = new Set<AnnouncementVisibility>(["online-only", "all"]);
const ANNOUNCEMENT_SOUNDS = new Set<AnnouncementSound>(["always", "live-only", "off"]);
// Custom admin-chosen announcement id (see POST /admin/announcement) — kept
// distinct from HANDLE_RE/CLIENT_ID_RE since it's a different namespace, but
// the same conservative charset.
const ANNOUNCEMENT_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Real-time engagement counters for whichever announcement is currently
// active — intentionally not history: replaced/cleared wholesale alongside
// currentAnnouncement (see setAnnouncement/clearAnnouncementStats below), so
// there's exactly one bucket to reason about and nothing to sweep. `viewerIds`
// dedupes by connection id so one visitor toggling tabs/focus repeatedly
// can't inflate the view count — a "view" only counts once per connection,
// the first time its tab is actually visible while the banner is showing
// (see the "announcement-view" case and AnnouncementBanner.tsx).
interface AnnouncementStatsEntry {
  viewerIds: Set<string>;
  buttonClicks: number;
  xClicks: number;
}
let announcementStats: AnnouncementStatsEntry | null = null;

function announcementStatsSummary() {
  if (!announcementStats) return null;
  return {
    views: announcementStats.viewerIds.size,
    buttonClicks: announcementStats.buttonClicks,
    xClicks: announcementStats.xClicks,
  };
}

const clients = new Map<WebSocket, ClientInfo>();
const clientsById = new Map<string, ClientInfo>();
const rooms = new Map<string, RoomInfo>();
// Pending "really delete this now-empty room" timers, keyed by room — see
// scheduleRoomDeletion.
const roomDeletionTimers = new Map<string, NodeJS.Timeout>();
// A page reload (Ctrl+R) closes the old socket and opens a new one a moment
// later — long enough that an *immediate* delete-on-empty would wipe the
// room's chat history out from under that reconnect. This grace period
// covers a reload/brief network drop; only if the room is still empty once
// it elapses do we actually tear it down.
const ROOM_DELETION_GRACE_MS = 20_000;
// Single site-wide banner, independent of any room — broadcastToAll below
// pushes it to every open socket regardless of what room (if any) they're
// in, and a fresh connection gets whatever's currently active appended
// right after "welcome" so it isn't missed by someone who (re)connects
// while it's up.
let currentAnnouncement: Announcement | null = null;

// A WebRTC offer/answer/ICE candidate is only useful for a few seconds, but
// `send()` below silently drops it if the target's socket isn't OPEN right
// then — which happens constantly on mobile (screen lock, wifi/cell
// handoff, a brief signal drop triggering a reconnect). A dropped offer is
// never resent by anything else, so it permanently stranded that one
// viewer's connection (peer shows in the room, but no video ever arrives).
// Queuing briefly and flushing once the target (re)joins closes that gap.
interface PendingSignal {
  from: string;
  data: unknown;
  queuedAt: number;
}
const PENDING_SIGNAL_TTL_MS = 15_000;
const MAX_PENDING_SIGNALS_PER_TARGET = 32;
const pendingSignals = new Map<string, PendingSignal[]>();

registerStatsProvider(() => {
  const registeredPeers = [...clients.values()].filter((c) => c.name !== null && !c.isModerator);
  const identities = { accounts: 0, guestsWithToken: 0, guestsWithoutToken: 0 };
  for (const c of registeredPeers) {
    if (c.accountId) identities.accounts += 1;
    else if (c.guestVerified) identities.guestsWithToken += 1;
    else identities.guestsWithoutToken += 1;
  }
  return {
    connectedSockets: clients.size,
    registeredPeers: registeredPeers.length,
    identities,
    rooms: [...rooms.entries()].map(([handle, info]) => ({
      handle,
      peopleCount: realPeopleCount(info),
      sharingCount: realSharingCount(info),
      isPrivate: isPrivateRoom(handle),
    })),
  };
});

function isValidDisplayName(name: string): boolean {
  if (name.length < 1 || name.length > 24) return false;
  for (let i = 0; i < name.length; i += 1) {
    const code = name.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Same control-character guard as isValidDisplayName, but newlines (10) are
// allowed since chat text is reasonably multi-line.
function isValidChatText(text: string): boolean {
  if (text.length < 1 || text.length > CHAT_MAX_LEN) return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 10) continue;
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Restricted to Giphy's own domain since this URL is trusted straight into
// an <img src> on every client in the room — accepting arbitrary URLs here
// would turn chat into an open image/tracking-pixel relay.
function isValidGifUrl(url: string): boolean {
  if (url.length > 500) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return parsed.protocol === "https:" && parsed.hostname.endsWith(".giphy.com");
}

// Same control-character guard as isValidDisplayName (no newlines — the
// banner is meant to be short), parameterized on max length since it's
// reused for both the announcement text and its button label.
function isValidAnnouncementField(text: string, maxLen: number): boolean {
  if (text.length < 1 || text.length > maxLen) return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Restricted to http(s) so a "javascript:" (or other) URL scheme can never
// reach the button's href/window.open target — this URL comes straight from
// an admin-supplied form field and gets used client-side without further
// sanitization.
function isValidAnnouncementUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

type ParsedAnnouncementFields = Omit<Announcement, "id" | "version">;

// Shared body-parsing/validation for POST (create) and PUT (edit) — both
// take the exact same editable fields, just differ in what happens to
// id/version/stats around the result (see the two route handlers below).
function parseAnnouncementBody(
  body: Record<string, unknown>
): ParsedAnnouncementFields | { error: string } {
  const text = typeof body.text === "string" ? body.text.trim().slice(0, ANNOUNCEMENT_TEXT_MAX_LEN) : "";
  if (!isValidAnnouncementField(text, ANNOUNCEMENT_TEXT_MAX_LEN)) {
    return { error: "Texto inválido." };
  }
  const color = typeof body.color === "string" ? body.color : "";
  if (!ANNOUNCEMENT_COLORS.has(color as AnnouncementColor)) {
    return { error: "Cor inválida." };
  }
  const visibility = typeof body.visibility === "string" ? body.visibility : "all";
  if (!ANNOUNCEMENT_VISIBILITIES.has(visibility as AnnouncementVisibility)) {
    return { error: "Visibilidade inválida." };
  }
  const sound = typeof body.sound === "string" ? body.sound : "always";
  if (!ANNOUNCEMENT_SOUNDS.has(sound as AnnouncementSound)) {
    return { error: "Opção de som inválida." };
  }
  const dismissible = Boolean(body.dismissible);
  const persistent = Boolean(body.persistent);
  // Defaults to true (button shown) when omitted, so an old admin client
  // that's never heard of this field keeps behaving exactly as before.
  const hasButton = body.hasButton !== false;

  if (!hasButton) {
    return {
      text,
      hasButton: false,
      buttonLabel: "",
      buttonAction: "reload",
      buttonUrl: null,
      color: color as AnnouncementColor,
      dismissible,
      visibility: visibility as AnnouncementVisibility,
      sound: sound as AnnouncementSound,
      persistent,
    };
  }

  const buttonLabel =
    typeof body.buttonLabel === "string"
      ? body.buttonLabel.trim().slice(0, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)
      : "";
  if (!isValidAnnouncementField(buttonLabel, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)) {
    return { error: "Label do botão inválido." };
  }
  const buttonAction = typeof body.buttonAction === "string" ? body.buttonAction : "";
  if (!ANNOUNCEMENT_ACTIONS.has(buttonAction as AnnouncementButtonAction)) {
    return { error: "Ação do botão inválida." };
  }
  const needsUrl = buttonAction !== "reload";
  const rawUrl = typeof body.buttonUrl === "string" ? body.buttonUrl.trim() : "";
  if (needsUrl && !isValidAnnouncementUrl(rawUrl)) {
    return { error: "Link inválido — use uma URL http(s) completa." };
  }

  return {
    text,
    hasButton: true,
    buttonLabel,
    buttonAction: buttonAction as AnnouncementButtonAction,
    buttonUrl: needsUrl ? rawUrl : null,
    color: color as AnnouncementColor,
    dismissible,
    visibility: visibility as AnnouncementVisibility,
    sound: sound as AnnouncementSound,
    persistent,
  };
}

function send(socket: WebSocket, msg: unknown) {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify(msg));
  }
}

function broadcastToRoom(room: string, msg: unknown, exclude?: WebSocket) {
  const roomInfo = rooms.get(room);
  if (!roomInfo) return;
  for (const s of roomInfo.sockets) {
    if (s !== exclude) send(s, msg);
  }
}

// Every open socket on the signaling server, regardless of room — used only
// for the site-wide announcement banner, which is deliberately not
// room-scoped.
function broadcastToAll(msg: unknown) {
  for (const s of clients.keys()) send(s, msg);
}

function queueSignal(targetId: string, from: string, data: unknown) {
  const queue = pendingSignals.get(targetId) ?? [];
  queue.push({ from, data, queuedAt: Date.now() });
  while (queue.length > MAX_PENDING_SIGNALS_PER_TARGET) queue.shift();
  pendingSignals.set(targetId, queue);
}

// Delivers a relayed signal immediately if the target is reachable in the
// same room right now; otherwise queues it for flushPendingSignals to
// deliver once that peer (re)joins. Deliberately keyed by client id (not
// looked up via clientsById), since a silently-watching moderator socket
// (see "admin-join") never registers a name and so never gets a clientsById
// entry at all.
function deliverOrQueueSignal(room: string, targetId: string, from: string, data: unknown) {
  const roomInfo = rooms.get(room);
  const target = roomInfo
    ? [...roomInfo.sockets].map((s) => clients.get(s)).find((c) => c?.id === targetId)
    : undefined;
  if (target && target.socket.readyState === target.socket.OPEN) {
    send(target.socket, { type: "signal", from, data });
    return;
  }
  queueSignal(targetId, from, data);
}

function flushPendingSignals(info: ClientInfo) {
  const queue = pendingSignals.get(info.id);
  if (!queue) return;
  pendingSignals.delete(info.id);
  const now = Date.now();
  for (const item of queue) {
    if (now - item.queuedAt > PENDING_SIGNAL_TTL_MS) continue;
    send(info.socket, { type: "signal", from: item.from, data: item.data });
  }
}

function peerSummary(info: ClientInfo) {
  return {
    id: info.id,
    name: info.name,
    sharing: info.sharing,
    mic: info.mic,
    ...(info.isModerator ? { role: "moderator" as const } : {}),
  };
}

// Real (non-moderator) headcount for a room — used everywhere a number or
// list is shown to an ordinary user, so a moderator watching never inflates
// what participants see.
function realPeopleCount(roomInfo: RoomInfo): number {
  let count = 0;
  for (const s of roomInfo.sockets) {
    if (!clients.get(s)?.isModerator) count += 1;
  }
  return count;
}

// Same real-people rule as realPeopleCount, but counting only those actually
// broadcasting their screen/camera right now (info.sharing), for the
// sharescreen_room_sharing_screen / sharescreen_sharing_screen_total metrics.
function realSharingCount(roomInfo: RoomInfo): number {
  let count = 0;
  for (const s of roomInfo.sockets) {
    const client = clients.get(s);
    if (client && !client.isModerator && client.sharing) count += 1;
  }
  return count;
}

// Cancels a pending scheduleRoomDeletion for `room`, if any — called
// whenever someone (re)joins it, since that proves it didn't really empty
// out for good.
function clearRoomDeletionTimer(room: string) {
  const timer = roomDeletionTimers.get(room);
  if (timer) {
    clearTimeout(timer);
    roomDeletionTimers.delete(room);
  }
}

// Tears the room down — both in memory and its persisted chat file — only
// if it's still empty once ROOM_DELETION_GRACE_MS has elapsed, giving a
// reload/brief drop time to reconnect and reclaim it first.
function scheduleRoomDeletion(room: string) {
  clearRoomDeletionTimer(room);
  const timer = setTimeout(() => {
    roomDeletionTimers.delete(room);
    const roomInfo = rooms.get(room);
    if (roomInfo && roomInfo.sockets.size === 0) {
      rooms.delete(room);
      deletePersistedChat(room);
    }
  }, ROOM_DELETION_GRACE_MS);
  roomDeletionTimers.set(room, timer);
}

function leaveRoom(info: ClientInfo) {
  if (!info.room) return;
  const room = info.room;
  const roomInfo = rooms.get(room);
  if (roomInfo) {
    roomInfo.sockets.delete(info.socket);
    if (info.name && roomInfo.names.get(info.name.toLowerCase()) === info.socket) {
      roomInfo.names.delete(info.name.toLowerCase());
    }
    if (roomInfo.sockets.size === 0) {
      // The room *looks* empty, but don't wipe its chat history yet — see
      // scheduleRoomDeletion. (A same-identity reconnect that briefly
      // overlaps the old socket goes through detachSession instead, which
      // deliberately does NOT delete the file either, since that's not a
      // real departure — see detachSession's comment.)
      scheduleRoomDeletion(room);
    }
  }
  info.room = null;
  info.sharing = false;
  info.mic = false;
  broadcastToRoom(room, { type: "peer-left", id: info.id }, info.socket);
}

// Close code used when a second connection reclaims a client id out from
// under a still-live socket (see detachSession below) — lets the displaced
// client tell "I was intentionally superseded" apart from an ordinary
// network drop, so it knows not to reconnect and reclaim the id right back.
// Without this distinction the two sockets would keep alternately kicking
// each other off forever (each successful reconnect resets its own
// exponential backoff, so the fight never settles). 4000 is in the
// private-use range reserved by RFC 6455 for application-defined codes.
const SUPERSEDED_CLOSE_CODE = 4000;

// Used when a reconnect (same persisted client id) shows up before the old
// socket has been reaped yet — e.g. a brief network blip, or a second tab.
// Removes the stale session from every bookkeeping structure and closes it
// *without* broadcasting peer-left, since this identity is carried over
// seamlessly to the new socket rather than actually leaving the room.
function detachSession(info: ClientInfo) {
  if (info.room) {
    const roomInfo = rooms.get(info.room);
    if (roomInfo) {
      roomInfo.sockets.delete(info.socket);
      if (info.name && roomInfo.names.get(info.name.toLowerCase()) === info.socket) {
        roomInfo.names.delete(info.name.toLowerCase());
      }
      // Deliberately leaves the persisted chat file alone even if this was
      // the room's last socket: the new connection taking over this
      // identity is about to "join" the same room again, and will reload
      // this exact history from disk when it recreates the RoomInfo.
      if (roomInfo.sockets.size === 0) rooms.delete(info.room);
    }
    info.room = null;
  }
  if (clientsById.get(info.id) === info) clientsById.delete(info.id);
  clients.delete(info.socket);
  // A graceful close (not terminate()) so the close frame with our code
  // actually reaches the displaced client instead of the connection just
  // dying silently.
  info.socket.close(SUPERSEDED_CLOSE_CODE, "superseded-by-new-connection");
}

// Terminates every socket currently connected from `ip` — called right
// after an admin bans it, so the ban takes effect immediately instead of
// only blocking that IP's *next* connection attempt.
function disconnectClientsByIp(ip: string) {
  for (const info of clients.values()) {
    if (info.ip === ip) {
      info.socket.close(BANNED_CLOSE_CODE, "ip-banned");
    }
  }
}

export async function registerSignalingRoutes(app: FastifyInstance, genId: () => string) {
  // Restores whatever topwarn was active before this process last
  // restarted (deploy, crash) — see announcementStore.ts. Awaited before any
  // route/the "/ws" handler below is registered so the very first request
  // this process serves already sees it, same as initModerationStore/
  // initAccountStore in index.ts.
  currentAnnouncement = await loadPersistedAnnouncement();
  if (currentAnnouncement) {
    announcementStats = { viewerIds: new Set(), buttonClicks: 0, xClicks: 0 };
  }

  // Detects and reaps half-dead connections (network dropped without a clean
  // close, e.g. mobile network handoff, sleeping laptop, NAT/proxy silently
  // dropping an idle socket). Without this, a client can vanish for other
  // peers with no "peer-left" until the OS eventually notices the TCP
  // connection is gone, which can take minutes — the pings also generate
  // periodic traffic that keeps idle-timeout proxies from killing the
  // connection in the first place.
  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const [targetId, queue] of pendingSignals) {
      const fresh = queue.filter((item) => now - item.queuedAt <= PENDING_SIGNAL_TTL_MS);
      if (fresh.length === 0) pendingSignals.delete(targetId);
      else if (fresh.length !== queue.length) pendingSignals.set(targetId, fresh);
    }
    for (const info of clients.values()) {
      if (!info.isAlive) {
        heartbeatReapedTotal.inc();
        info.socket.terminate();
        continue;
      }
      info.isAlive = false;
      info.socket.ping();
    }
  }, HEARTBEAT_INTERVAL_MS);

  app.addHook("onClose", (_instance, done) => {
    clearInterval(heartbeat);
    done();
  });

  // Site-wide "people online" counter. Unlike /rooms this includes private
  // rooms — but only ever returns a single aggregate number, never handles
  // or peer detail, so it can't be used to discover a private room's
  // existence the way /admin/rooms can.
  //
  // Public and cheap, and realistically polled by every open tab's UI
  // (people-online widget) — generous limit, well above what one real
  // visitor's polling loop needs, tuned against a scripted hammering loop
  // instead.
  app.get("/stats", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    let peopleOnline = 0;
    for (const info of rooms.values()) peopleOnline += realPeopleCount(info);
    return { peopleOnline };
  });

  // Public room directory. Private rooms (handle starts with "priv-") are
  // filtered out here, server-side — the client never receives them, so
  // there's no separate access-control step to forget on the frontend.
  //
  // Same reasoning/limit as /stats: public, cheap, polled by the room
  // browser UI on a normal cadence.
  app.get("/rooms", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    const publicRooms = [...rooms.entries()]
      .filter(([handle]) => !isPrivateRoom(handle))
      .map(([handle, info]) => ({
        handle,
        peopleCount: realPeopleCount(info),
        createdAt: info.createdAt,
      }))
      .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
    return { rooms: publicRooms };
  });

  // Account system: create/login work for anyone, no auth required going
  // in. Admin is no longer a separate Basic-Auth credential (see the old
  // adminAuth.ts) — it's just an account whose flags include "ADMIN" (see
  // accountStore.ts's initAccountStore bootstrap), checked identically to
  // every other route below via requireAdmin.
  // Account creation — cheap to abuse into a spam/enumeration tool if left
  // uncapped (each attempt tries a password hash + a uniqueness check), and
  // nobody legitimately creates more than a couple of accounts per IP in a
  // sitting, so this stays tight.
  app.post(
    "/auth/register",
    { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } },
    async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = (typeof body.username === "string" ? body.username.trim() : "").toLowerCase();
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!USERNAME_RE.test(username)) {
      return reply.code(400).send({ error: "Usuário inválido — use 3 a 20 letras, números ou _." });
    }
    if (!isValidDisplayName(displayName)) {
      return reply.code(400).send({ error: "Nome de exibição inválido." });
    }
    if (password.length < 6 || password.length > 200) {
      return reply.code(400).send({ error: "Senha deve ter entre 6 e 200 caracteres." });
    }
    try {
      const account = await createAccount(username, displayName, password, request.ip);
      const token = signToken({ sub: account.id, username: account.username, flags: account.flags });
      return { token, account };
    } catch (err) {
      const message = err instanceof Error ? err.message : "Falha ao criar conta.";
      return reply.code(409).send({ error: message });
    }
  });

  // Login is the classic brute-force target — capped tighter than most
  // routes here, but loose enough that someone fat-fingering their own
  // password a few times in a row doesn't get locked out mid-attempt.
  app.post("/auth/login", { config: { rateLimit: { max: 10, timeWindow: "5 minutes" } } }, async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const account = await verifyAccountLogin(username, password, request.ip);
    if (!account) {
      return reply.code(401).send({ error: "Usuário ou senha inválidos." });
    }
    const token = signToken({ sub: account.id, username: account.username, flags: account.flags });
    return { token, account };
  });

  // Just a token verify + in-memory lookup, and realistically called on
  // every page load/focus to confirm the session — generous like /stats.
  app.get("/auth/me", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const payload = verifyToken(request.headers.authorization?.startsWith("Bearer ")
      ? request.headers.authorization.slice(7)
      : null);
    if (!payload) return reply.code(401).send({ error: "unauthorized" });
    const account = getPublicAccountById(payload.sub);
    if (!account) return reply.code(401).send({ error: "unauthorized" });
    return { account };
  });

  // Full room directory for moderators — unlike /rooms, this includes
  // private rooms and per-peer detail, since moderation is the one
  // legitimate reason to need that visibility.
  // Every /admin/* route below is already gated by requireAdmin, so its
  // realistic caller set is just the admin panel itself (a handful of
  // moderators at most) — limits here exist as a backstop against a buggy
  // polling loop or a leaked token, not against a wide pool of untrusted
  // callers, so GETs get a generous per-minute budget...
  app.get("/admin/rooms", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const allRooms = [...rooms.entries()]
      .map(([handle, info]) => ({
        handle,
        isPrivate: isPrivateRoom(handle),
        createdAt: info.createdAt,
        peopleCount: realPeopleCount(info),
        peers: [...info.sockets]
          .map((s) => clients.get(s))
          .filter((c): c is ClientInfo => c !== undefined && !c.isModerator)
          .map((c) => ({ id: c.id, name: c.name, sharing: c.sharing, mic: c.mic, ip: c.ip })),
      }))
      .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
    return { rooms: allRooms };
  });

  // Site-wide banner shown to every connected socket (see broadcastToAll),
  // not scoped to a room. GET lets the admin panel show whether one's
  // already active on load (plus its live engagement stats); POST creates a
  // brand new one (fresh id + stats, see parseAnnouncementBody/genId below);
  // PUT edits the currently active one in place (same id, stats preserved,
  // version bumped — see the Announcement.version doc comment); DELETE ends
  // it for everyone currently connected.
  app.get(
    "/admin/announcement",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
    }
  );

  // ...while mutating admin actions (POST/PUT/DELETE) get a tighter one —
  // still far above what a human clicking a button ever needs, just enough
  // to blunt a runaway script.
  app.post("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const parsed = parseAnnouncementBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }
    const rawId = typeof body.id === "string" ? body.id.trim() : "";
    if (rawId && !ANNOUNCEMENT_ID_RE.test(rawId)) {
      return reply.code(400).send({ error: "ID inválido — use até 64 letras, números, _ ou -." });
    }

    currentAnnouncement = { id: rawId || genId(), version: 1, ...parsed };
    // A brand new announcement always starts its own fresh counters, even if
    // it reuses a previous id on purpose — see the AnnouncementStatsEntry
    // doc comment for why PUT (edit) instead preserves this bucket.
    announcementStats = { viewerIds: new Set(), buttonClicks: 0, xClicks: 0 };
    await savePersistedAnnouncement(currentAnnouncement);
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement, live: true });
    return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
  });

  app.put("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (!currentAnnouncement) {
      return reply.code(404).send({ error: "Nenhum aviso ativo para editar." });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    // Guards against two admin tabs editing stale state — a client that
    // fetched the active announcement before someone else replaced it (a
    // fresh POST, different id) gets told instead of silently overwriting
    // whatever's live now under a stranger's id.
    const bodyId = typeof body.id === "string" ? body.id : "";
    if (bodyId && bodyId !== currentAnnouncement.id) {
      return reply.code(409).send({ error: "O aviso ativo mudou em outra sessão — recarregue e tente de novo." });
    }
    const parsed = parseAnnouncementBody(body);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }

    currentAnnouncement = { ...currentAnnouncement, ...parsed, version: currentAnnouncement.version + 1 };
    await savePersistedAnnouncement(currentAnnouncement);
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement, live: true });
    return { announcement: currentAnnouncement, stats: announcementStatsSummary() };
  });

  app.delete("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    currentAnnouncement = null;
    announcementStats = null;
    await deletePersistedAnnouncement();
    broadcastToAll({ type: "announcement", announcement: null, live: true });
    return reply.code(204).send();
  });

  // Dashboard overview for the admin panel — aggregate numbers only (no
  // room/peer detail, see /admin/rooms for that), so it's cheap to poll.
  app.get("/admin/stats", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    let peopleOnline = 0;
    let sharingCount = 0;
    let publicRooms = 0;
    let privateRooms = 0;
    for (const [handle, info] of rooms) {
      peopleOnline += realPeopleCount(info);
      sharingCount += realSharingCount(info);
      if (isPrivateRoom(handle)) privateRooms += 1;
      else publicRooms += 1;
    }
    return {
      connectedSockets: clients.size,
      peopleOnline,
      sharingCount,
      publicRooms,
      privateRooms,
      bannedIps: listBans().length,
      bannedWords: listBannedWords().length,
      mongo: { enabled: MONGO_ENABLED, connected: isMongoConnected() },
    };
  });

  // IP ban list/management. Banning takes effect immediately: any socket
  // currently connected from that IP is disconnected right away (see
  // disconnectClientsByIp), and every future "/ws" upgrade from it is
  // rejected before it's ever added to `clients` — see the handler below.
  app.get("/admin/bans", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return { bans: listBans() };
  });

  app.post("/admin/bans", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const ip = typeof body.ip === "string" ? body.ip.trim() : "";
    const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, BAN_REASON_MAX_LEN) : "";
    const durationMinutes =
      typeof body.durationMinutes === "number" && Number.isFinite(body.durationMinutes) && body.durationMinutes > 0
        ? body.durationMinutes
        : null;
    if (!isValidIp(ip)) {
      return reply.code(400).send({ error: "IP inválido." });
    }
    const ban = await banIp(ip, reason, durationMinutes);
    disconnectClientsByIp(ip);
    return { ban };
  });

  app.delete("/admin/bans/:ip", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { ip } = request.params as { ip: string };
    await unbanIp(ip);
    return reply.code(204).send();
  });

  // Chat content filter — one flat list of forbidden words/phrases, replaced
  // wholesale on every PUT (see setBannedWords) rather than incremental
  // add/remove endpoints, matching the shape of a single admin textarea.
  app.get(
    "/admin/banned-words",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { words: listBannedWords() };
    }
  );

  app.put("/admin/banned-words", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (!Array.isArray(body.words) || !body.words.every((w) => typeof w === "string")) {
      return reply.code(400).send({ error: "Lista de palavras inválida." });
    }
    const words = await setBannedWords(body.words as string[]);
    return { words };
  });

  app.get(
    "/ws",
    {
      websocket: true,
      // Bounds *connection attempts* per IP, not concurrent connections or
      // anything that happens over an already-open socket (that's the
      // per-message limiters in rateLimiter.ts, applied inside the message
      // handler below). 30/min comfortably covers a real client's
      // reconnect/backoff behavior (network blips, sleep/wake, page
      // reloads) while still bounding a connection-flood attempt.
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    (socket: WebSocket, request: FastifyRequest) => {
    const ip = request.ip;
    if (isIpBanned(ip)) {
      bannedIpConnectionsRejectedTotal.inc();
      socket.close(BANNED_CLOSE_CODE, "ip-banned");
      return;
    }

    const info: ClientInfo = {
      id: genId(),
      name: null,
      room: null,
      sharing: false,
      mic: false,
      isAlive: true,
      socket,
      ip,
      rateLimitKey: genId(),
    };
    clients.set(socket, info);
    wsConnectionsTotal.inc();
    send(socket, { type: "welcome", id: info.id });
    // "online-only" is deliberately never handed to a connection that shows
    // up after it was sent — that's the entire distinction from "all" (see
    // AnnouncementVisibility above). `live: false` tells the client this is
    // a catch-up delivery, not a fresh one (see AnnouncementBanner.tsx's
    // sound handling).
    if (currentAnnouncement && currentAnnouncement.visibility === "all") {
      send(socket, { type: "announcement", announcement: currentAnnouncement, live: false });
    }

    socket.on("pong", () => {
      info.isAlive = true;
    });

    socket.on("message", async (raw: Buffer) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!msg || typeof msg.type !== "string") return;

      // Backstop across every message type combined for this connection —
      // runs before the per-type limiters below so it also catches a flood
      // of a `type` no case here recognizes (which the `default: break`
      // would otherwise process at unlimited rate).
      if (!(await consumeRateLimit(wsGlobalLimiter, info.rateLimitKey, "global"))) return;

      switch (msg.type) {
        case "register": {
          // Covers both the initial registration and every later rename
          // (renaming doesn't re-enter via "join" — see below), so one
          // budget for both is enough to stop a rename-spam loop without
          // getting in the way of a real, occasional name change.
          if (!(await consumeRateLimit(wsRegisterLimiter, info.rateLimitKey, "register"))) {
            send(socket, { type: "register-error", message: "Muitas tentativas. Aguarde um instante." });
            return;
          }
          // A logged-in client passes its account JWT here; a guest passes
          // whatever guest token a previous "registered" response handed it
          // (see below) — same `token` field either way, told apart by the
          // decoded payload's `guest` flag. Neither is required: an old
          // client that only ever knew about plain names/clientIds sends
          // nothing here and still works exactly as before.
          const rawToken = typeof msg.token === "string" ? msg.token : "";
          const authPayload = rawToken ? verifyToken(rawToken) : null;
          const isAccountToken = Boolean(authPayload && !authPayload.guest);

          // A logged-in account's display name always comes from its own
          // account record, never from whatever the client sends alongside
          // the token — otherwise `name` would be the one piece of identity
          // info an account holder could still freely spoof despite a valid
          // token, and it'd let the name drift from what the account
          // actually shows elsewhere (e.g. the admin panel, chat history
          // from other rooms). A guest has no such record, so its name
          // stays exactly what it always was: whatever it types.
          let rawName: string;
          if (isAccountToken) {
            const account = getPublicAccountById(authPayload!.sub);
            if (!account) {
              // The account behind this token doesn't exist anymore
              // (deleted after the token was issued) — treat it like any
              // other invalid token rather than trusting a name for an
              // account that's gone.
              registerErrorsTotal.inc();
              send(socket, { type: "register-error", message: "Conta não encontrada." });
              return;
            }
            rawName = account.displayName;
          } else {
            rawName = typeof msg.name === "string" ? msg.name.trim().slice(0, 24) : "";
          }
          if (!isValidDisplayName(rawName)) {
            registerErrorsTotal.inc();
            send(socket, { type: "register-error", message: "Nome inválido." });
            return;
          }

          let newGuestToken: string | null = null;
          if (isAccountToken) {
            info.accountId = authPayload!.sub;
            info.flags = authPayload!.flags;
            info.guestId = undefined;
            info.guestVerified = false;
          } else {
            info.accountId = undefined;
            info.flags = undefined;
            if (authPayload && authPayload.guest) {
              info.guestId = authPayload.sub;
              info.guestVerified = true;
            } else if (!info.guestId) {
              // No usable token presented: mint a fresh, unverified guest
              // identity for this connection and hand back a token for it,
              // so the client can prove it's still the same guest next time
              // (see isSameOwner). Every connection that shows up without a
              // token gets its own distinct id here — that's what stops a
              // stranger from reusing this guest's publicly-visible name or
              // connection id to hijack the session below or in "join": they
              // can never produce a matching *verified* guestId.
              info.guestId = `guest:${genId()}`;
              info.guestVerified = false;
            }
            if (!info.guestVerified) {
              newGuestToken = signToken({ sub: info.guestId!, username: rawName, flags: [], guest: true });
            }
          }

          const key = rawName.toLowerCase();
          // A name tied to a registered account (its username or display
          // name) is reserved for that account's owner — anyone else, guest
          // or a different account, trying to register under it gets
          // rejected.
          const reservedOwnerId = isNameReserved(key);
          if (reservedOwnerId && reservedOwnerId !== info.accountId) {
            registerErrorsTotal.inc();
            send(socket, {
              type: "register-error",
              message: "Esse nome pertence a uma conta registrada.",
            });
            return;
          }

          // Renaming while already in a room doesn't go through "join"
          // again, so the room-scoped name collision "join" normally checks
          // (see below) has to be checked here instead — the same name
          // could already be held by someone else in *this* room.
          if (info.room) {
            const roomInfo = rooms.get(info.room);
            const holderSocket = roomInfo?.names.get(key);
            const holder = holderSocket && holderSocket !== socket ? clients.get(holderSocket) : undefined;
            if (holder && !isSameOwner(holder, info)) {
              registerErrorsTotal.inc();
              send(socket, { type: "register-error", message: "Esse nome já está em uso nesta sala." });
              return;
            }
          }

          const previousName = info.name;
          info.name = rawName;
          if (info.room) {
            const roomInfo = rooms.get(info.room);
            if (roomInfo) {
              if (previousName) roomInfo.names.delete(previousName.toLowerCase());
              roomInfo.names.set(key, socket);
            }
          }

          // A client-supplied id (persisted client-side across reloads) lets
          // a returning client reclaim its previous connection id instead of
          // showing up as a stranger to everyone else's still-open peer
          // connections. Only actually reclaimed if it's free, already ours,
          // or provably the same owner as whoever currently holds it —
          // otherwise someone merely guessing/observing another live
          // connection's id (it's visible to every peer in its room) could
          // hijack that session by presenting it back. A session that was
          // never given a chance to prove itself (no token ever verified for
          // it — the old, pre-token model) still trusts a bare id match by
          // default, to keep working exactly as it always has for clients
          // that don't know about tokens at all — see
          // ALLOW_OLD_CLIENTS_GUEST_SYSTEM.
          const requestedClientId = typeof msg.clientId === "string" ? msg.clientId : "";
          const clientId = CLIENT_ID_RE.test(requestedClientId) ? requestedClientId : null;
          if (clientId && clientId !== info.id) {
            const existingById = clientsById.get(clientId);
            if (!existingById) {
              if (clientsById.get(info.id) === info) clientsById.delete(info.id);
              info.id = clientId;
            } else if (existingById.socket !== socket) {
              const existingProtected =
                !ALLOW_OLD_CLIENTS_GUEST_SYSTEM || Boolean(existingById.accountId) || existingById.guestVerified;
              if (!existingProtected || isSameOwner(existingById, info)) {
                detachSession(existingById);
                if (clientsById.get(info.id) === info) clientsById.delete(info.id);
                info.id = clientId;
              }
              // else: someone else's protected session — ignore the
              // requested id and keep our own freshly generated one.
            }
          }
          clientsById.set(info.id, info);

          send(socket, {
            type: "registered",
            id: info.id,
            name: rawName,
            account: info.accountId ? { username: authPayload!.username, flags: info.flags ?? [] } : null,
            // Only sent when non-null — a guest whose existing token was
            // just verified above doesn't need a new one. A client that
            // doesn't understand this field simply ignores it, same as any
            // other unrecognized field.
            guestToken: newGuestToken,
          });

          // Renaming while already in a room doesn't go through "join"
          // again, so nothing else would tell the other participants —
          // without this their peer list would keep showing the old name.
          if (info.room && previousName && previousName !== rawName) {
            broadcastToRoom(info.room, { type: "peer-renamed", id: info.id, name: rawName }, socket);
          }
          break;
        }
        case "join": {
          // Shared with "admin-join" below — switching rooms is something a
          // real connection does rarely, never in a tight loop.
          if (!(await consumeRateLimit(wsJoinLimiter, info.rateLimitKey, "join"))) {
            send(socket, { type: "join-error", message: "Muitas tentativas. Aguarde um instante." });
            return;
          }
          if (!info.name) {
            send(socket, { type: "error", message: "Registre um nome antes de entrar em uma sala." });
            return;
          }
          const room = typeof msg.room === "string" ? msg.room : "";
          if (!HANDLE_RE.test(room)) {
            send(socket, { type: "error", message: "Sala inválida." });
            return;
          }
          if (info.room === room) return;

          // A name already held by someone else in *this* room is only ever
          // let through when it's provably the same guest/account already
          // there under another connection (a second tab, or a reload that
          // hasn't reclaimed its old connection id yet) — reclaiming just
          // takes over the slot instead of rejecting, same as a plain
          // clientId collision does in "register". Two different rooms
          // never collide this way (this check is scoped to `room` alone),
          // and a stranger presenting the same name they can see in the
          // room's peer list is turned away without touching the person
          // already there.
          const nameKey = info.name.toLowerCase();
          const existingRoomInfo = rooms.get(room);
          const holderSocket = existingRoomInfo?.names.get(nameKey);
          if (holderSocket && holderSocket !== socket) {
            const holder = clients.get(holderSocket);
            if (holder && isSameOwner(holder, info)) {
              detachSession(holder);
            } else {
              send(socket, { type: "join-error", message: "Esse nome já está em uso nesta sala." });
              return;
            }
          }

          if (info.room) leaveRoom(info);
          clearRoomDeletionTimer(room);
          info.room = room;
          info.sharing = false;
          info.mic = false;
          let roomInfo = rooms.get(room);
          if (!roomInfo) {
            // Reloads any chat history still persisted (chatStore.ts) from
            // before the room last emptied out or the process last
            // restarted. Awaiting here means another client's "join" for
            // this same brand-new room could land while we wait — re-check
            // after, so we don't clobber a RoomInfo that landed first.
            const messages = await loadPersistedChat(room);
            roomInfo = rooms.get(room);
            if (!roomInfo) {
              roomInfo = { sockets: new Set(), createdAt: Date.now(), messages, names: new Map() };
              rooms.set(room, roomInfo);
              roomsCreatedTotal.inc({ visibility: isPrivateRoom(room) ? "private" : "public" });
            }
          }
          // The await above gave this socket's own "leave"/another "join"
          // a chance to run first and move it elsewhere (or the socket
          // could've closed outright) — don't add it to a room it's no
          // longer trying to join.
          if (info.room !== room || !clients.has(socket)) return;
          roomInfo.sockets.add(socket);
          roomInfo.names.set(nameKey, socket);
          const peers = [...roomInfo.sockets]
            .filter((s) => s !== socket)
            .map((s) => clients.get(s))
            .filter((c): c is ClientInfo => c !== undefined)
            .map(peerSummary);
          send(socket, { type: "room-state", room, selfId: info.id, peers, messages: roomInfo.messages });
          flushPendingSignals(info);
          broadcastToRoom(room, { type: "peer-joined", id: info.id, name: info.name }, socket);
          break;
        }
        // A moderator entering a room to watch/listen for moderation.
        // Deliberately mirrors "join" (same room bookkeeping, same
        // room-state/peer-joined messages) so this socket rides the exact
        // same signal-relay and broadcaster-reactivity machinery a real
        // participant does — the only difference is the `role: "moderator"`
        // tag on its peer entry, which is what the client uses to keep it
        // out of the visible participant list/count. Leaving reuses the
        // plain "leave" message (and socket close already calls
        // leaveRoom() regardless), so no separate cleanup path is needed.
        case "admin-join": {
          if (!(await consumeRateLimit(wsJoinLimiter, info.rateLimitKey, "join"))) {
            send(socket, { type: "error", message: "Muitas tentativas. Aguarde um instante." });
            return;
          }
          const token = typeof msg.token === "string" ? msg.token : "";
          const adminPayload = verifyToken(token);
          if (!adminPayload || !adminPayload.flags.includes("ADMIN")) {
            send(socket, { type: "error", message: "Não autorizado." });
            socket.terminate();
            return;
          }
          const room = typeof msg.room === "string" ? msg.room : "";
          if (!HANDLE_RE.test(room)) {
            send(socket, { type: "error", message: "Sala inválida." });
            return;
          }
          const roomInfo = rooms.get(room);
          if (!roomInfo) {
            send(socket, { type: "error", message: "Sala não encontrada ou já encerrada." });
            return;
          }
          if (info.room === room) return;
          if (info.room) leaveRoom(info);
          info.isModerator = true;
          info.name = info.name ?? "Moderador";
          info.room = room;
          info.sharing = false;
          info.mic = false;
          roomInfo.sockets.add(socket);
          const adminPeers = [...roomInfo.sockets]
            .filter((s) => s !== socket)
            .map((s) => clients.get(s))
            .filter((c): c is ClientInfo => c !== undefined)
            .map(peerSummary);
          send(socket, {
            type: "room-state",
            room,
            selfId: info.id,
            peers: adminPeers,
            messages: roomInfo.messages,
          });
          flushPendingSignals(info);
          broadcastToRoom(room, { type: "peer-joined", id: info.id, name: info.name, role: "moderator" }, socket);
          break;
        }
        case "leave": {
          if (info.room) leaveRoom(info);
          break;
        }
        case "sharing": {
          if (!info.room) return;
          // Dropped silently (no client feedback) when over budget: this is
          // transient toggle state, not a one-shot user action — the next
          // real toggle just propagates normally once the window resets.
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          info.sharing = Boolean(msg.sharing);
          broadcastToRoom(info.room, { type: "peer-sharing", id: info.id, sharing: info.sharing });
          break;
        }
        case "mic": {
          if (!info.room) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          info.mic = Boolean(msg.mic);
          broadcastToRoom(info.room, { type: "peer-mic", id: info.id, mic: info.mic });
          break;
        }
        case "chat": {
          if (!info.room) return;
          // Only rate-limited case besides "register"/"join" that gives the
          // client explicit feedback — chat is a deliberate, one-off user
          // action, so silently eating a message (like "signal" below does)
          // would look like a bug rather than a rate limit; reusing
          // "chat-blocked" means the frontend already has UI for this.
          if (!(await consumeRateLimit(wsChatLimiter, info.rateLimitKey, "chat"))) {
            send(socket, {
              type: "chat-blocked",
              message: "Você está enviando mensagens rápido demais. Aguarde um instante.",
            });
            return;
          }
          const isGif = msg.kind === "gif";
          let chatMessage: ChatMessage;
          if (isGif) {
            const url = typeof msg.url === "string" ? msg.url.trim() : "";
            if (!isValidGifUrl(url)) return;
            chatMessage = {
              id: genId(),
              from: info.id,
              name: info.name as string,
              kind: "gif",
              text: "",
              url,
              ts: Date.now(),
            };
          } else {
            const text = typeof msg.text === "string" ? msg.text.trim().slice(0, CHAT_MAX_LEN) : "";
            if (!isValidChatText(text)) return;
            if (findBannedWord(text)) {
              chatMessagesBlockedTotal.inc();
              send(socket, {
                type: "chat-blocked",
                message: "Sua mensagem contém uma palavra não permitida.",
              });
              return;
            }
            chatMessage = {
              id: genId(),
              from: info.id,
              name: info.name as string,
              text,
              ts: Date.now(),
            };
          }
          const roomInfo = rooms.get(info.room);
          if (!roomInfo) return;
          roomInfo.messages.push(chatMessage);
          if (roomInfo.messages.length > ROOM_CHAT_HISTORY_LIMIT) {
            roomInfo.messages.splice(0, roomInfo.messages.length - ROOM_CHAT_HISTORY_LIMIT);
          }
          savePersistedChat(info.room, roomInfo.messages);
          broadcastToRoom(info.room, { type: "chat-message", ...chatMessage });
          break;
        }
        case "signal": {
          if (!info.room) return;
          // Dropped silently, not surfaced to the client: this limiter is
          // sized well above what a real mesh negotiation ever needs (see
          // wsSignalLimiter in rateLimiter.ts), so hitting it means
          // something is already wrong — no UI message would help, and
          // WebRTC's own negotiation/retry logic tolerates an occasional
          // missed signal better than a user-facing error would.
          if (!(await consumeRateLimit(wsSignalLimiter, info.rateLimitKey, "signal"))) return;
          const targetId = typeof msg.to === "string" ? msg.to : "";
          if (!targetId) return;
          const dataKind =
            msg.data && typeof msg.data === "object" && "kind" in msg.data
              ? String((msg.data as { kind: unknown }).kind)
              : "unknown";
          signalsRelayedTotal.inc({ kind: dataKind });
          deliverOrQueueSignal(info.room, targetId, info.id, msg.data);
          break;
        }
        // Real engagement signals for the admin panel's live announcement
        // stats (see announcementStats above) — sent by AnnouncementBanner.tsx
        // only for the announcement it's actually displaying, so a stale/
        // mismatched id here (an edit or a brand new announcement racing the
        // client's report) is simply ignored rather than corrupting the
        // current bucket.
        case "announcement-view": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-view"))) return;
          announcementStats.viewerIds.add(info.id);
          break;
        }
        case "announcement-button-click": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-click"))) return;
          announcementStats.buttonClicks += 1;
          break;
        }
        case "announcement-x-click": {
          const id = typeof msg.id === "string" ? msg.id : "";
          if (!currentAnnouncement || !announcementStats || id !== currentAnnouncement.id) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "announcement-x-click"))) return;
          announcementStats.xClicks += 1;
          break;
        }
        default:
          break;
      }
    });

    socket.on("close", () => {
      wsDisconnectionsTotal.inc();
      // leaveRoom guards its own roomInfo.names cleanup against a
      // stale/superseded session's delayed close event wiping out a newer
      // reconnect that already took over this name/id (it only ever deletes
      // its *own* socket's reservation).
      if (info.room) leaveRoom(info);
      if (clientsById.get(info.id) === info) {
        clientsById.delete(info.id);
        pendingSignals.delete(info.id);
      }
      clients.delete(socket);
    });
  });
}
