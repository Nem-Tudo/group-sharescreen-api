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
  appendPersistedChat,
  deletePersistedChat,
  type ChatMessage,
} from "./chatStore.js";
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
import {
  instanceId as clusterInstanceId,
  getRoomPeers,
  roomCounts,
  listAllRooms,
  upsertRoomPeer,
  removeRoomPeer,
  reserveRoomName,
  releaseRoomName,
  getRoomNameHolder,
  getClientRecord,
  setClientRecord,
  deleteClientRecordIfOwn,
  subscribeRoomChannel,
  unsubscribeRoomChannel,
  publishRoomEvent,
  subscribeAnnouncementChannel,
  publishAnnouncement,
  getStoredAnnouncement,
  subscribeClientChannel,
  unsubscribeClientChannel,
  publishToClient,
  queuePendingSignal,
  flushPendingSignals as flushClusterPendingSignals,
  touchRoomPeerHeartbeat,
  touchClientHeartbeat,
  clearRoomCreatedAt,
  type RoomPeerRecord,
  type ClientChannelMessage,
} from "./cluster.js";

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
  // The epoch this connection last wrote into cluster.ts's global clientId
  // registry (see setClientRecord) — the cross-process equivalent of
  // checking `clientsById.get(info.id) === info`. deleteClientRecordIfOwn
  // uses it to guard against a delayed/stale cleanup deleting a newer
  // owner's fresh registry entry (see "register" and detachSession).
  registryEpoch?: string;
  // The clientId this connection is currently subscribed to on cluster.ts's
  // per-client Redis channel (see subscribeClientChannel) — lets "register"
  // detect when `info.id` changed and needs to move its subscription.
  clientChannelId?: string;
}

// Local, per-instance cache: which of this room's sockets/chat history live
// on *this* process. Room membership, name reservations, and clientId
// ownership are no longer decided from this — cluster.ts's Redis-backed
// roster is now the single cross-instance source of truth for those, so
// there's exactly one place that can ever disagree with itself. This local
// cache exists purely so same-instance delivery (broadcastToRoom) and the
// room-state chat snapshot stay a zero-Redis-hop fast path.
interface RoomInfo {
  sockets: Set<WebSocket>;
  messages: ChatMessage[];
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
// Structural shape shared by ClientInfo (a live local connection) and
// cluster.ts's ClientRecord (the plain JSON read back from the Redis
// clientId registry for a session that lives on a *different* instance) —
// one ownership rule, reused for both the local and cross-instance reclaim
// paths (see resolveOwnerIdentity below) instead of duplicating it.
interface OwnerIdentity {
  accountId?: string;
  guestId?: string;
  guestVerified?: boolean;
}

function isSameOwner(existing: OwnerIdentity, challenger: OwnerIdentity): boolean {
  if (existing.accountId || challenger.accountId) {
    return Boolean(challenger.accountId) && existing.accountId === challenger.accountId;
  }
  return Boolean(challenger.guestVerified) && existing.guestId === challenger.guestId;
}

type AnnouncementButtonAction = "open-new-tab" | "open-same-tab" | "reload";
type AnnouncementColor = "green" | "red" | "blue";
const ANNOUNCEMENT_ACTIONS = new Set<AnnouncementButtonAction>([
  "open-new-tab",
  "open-same-tab",
  "reload",
]);
const ANNOUNCEMENT_COLORS = new Set<AnnouncementColor>(["green", "red", "blue"]);

interface Announcement {
  id: string;
  text: string;
  buttonLabel: string;
  buttonAction: AnnouncementButtonAction;
  buttonUrl: string | null;
  color: AnnouncementColor;
  dismissible: boolean;
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
// while it's up. Every instance keeps its own copy of this in sync via
// cluster.ts's announcement channel (see initClusterSync below) — primed
// once at startup from Redis, then updated in lockstep by every
// instance's subscription handler whenever any instance's admin route
// changes it.
let currentAnnouncement: Announcement | null = null;

// A WebRTC offer/answer/ICE candidate is only useful for a few seconds, but
// `send()` below silently drops it if the target's socket isn't OPEN right
// then — which happens constantly on mobile (screen lock, wifi/cell
// handoff, a brief signal drop triggering a reconnect). A dropped offer is
// never resent by anything else, so it permanently stranded that one
// viewer's connection (peer shows in the room, but no video ever arrives).
// Queuing briefly (in Redis — see cluster.ts's queuePendingSignal) and
// flushing once the target (re)joins, on *any* instance, closes that gap.
const PENDING_SIGNAL_TTL_MS = 15_000;

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

// Delivers a relayed signal immediately if the target is reachable in the
// same room, on *this* instance, right now (zero Redis cost — the common
// case). Otherwise publishes it straight to whichever instance currently
// holds that clientId's per-client channel (see cluster.ts); if nobody's
// subscribed anywhere right now (publish reports 0 subscribers), queues it
// in Redis for flushPendingSignalsFor to deliver once that peer (re)joins,
// on any instance. Deliberately keyed by client id (not looked up via
// clientsById), since a silently-watching moderator socket (see
// "admin-join") never registers a name and so never gets a clientsById
// entry at all.
async function deliverOrQueueSignal(room: string, targetId: string, from: string, data: unknown) {
  const roomInfo = rooms.get(room);
  const target = roomInfo
    ? [...roomInfo.sockets].map((s) => clients.get(s)).find((c) => c?.id === targetId)
    : undefined;
  if (target && target.socket.readyState === target.socket.OPEN) {
    send(target.socket, { type: "signal", from, data });
    return;
  }
  const delivered = await publishToClient(targetId, { type: "signal", from, data });
  if (delivered === 0) {
    await queuePendingSignal(targetId, { from, data, queuedAt: Date.now() });
  }
}

async function flushPendingSignalsFor(info: ClientInfo) {
  const queue = await flushClusterPendingSignals(info.id);
  const now = Date.now();
  for (const item of queue) {
    if (now - item.queuedAt > PENDING_SIGNAL_TTL_MS) continue;
    send(info.socket, { type: "signal", from: item.from, data: item.data });
  }
}

// The identity a peer's *local preferences* (e.g. a client remembering a
// per-peer volume) should be keyed on — stable across reconnects/reloads
// for the same account or guest, unlike `info.id`/`peer.id` which is
// per-connection and gets reissued every time. Guest-side this is the same
// value regardless of `guestVerified`: verification only affects ownership
// claims (see isSameOwner), not the id itself.
function stableUserId(info: ClientInfo): string | undefined {
  return info.accountId ?? info.guestId;
}

// Wire shape sent to clients for each peer in a room — mirrors the old
// local peerSummary()'s output, now sourced from cluster.ts's Redis roster
// (RoomPeerRecord) instead of a local ClientInfo, since peers can live on
// any instance.
function toWirePeer(peer: RoomPeerRecord) {
  return {
    id: peer.id,
    name: peer.name,
    sharing: peer.sharing,
    mic: peer.mic,
    userId: peer.userId,
    ...(peer.isModerator ? { role: "moderator" as const } : {}),
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

// Tears the room down — both this instance's local cache and, if nobody's
// left in it on *any* instance, its persisted chat file — only if it's
// still empty once ROOM_DELETION_GRACE_MS has elapsed, giving a
// reload/brief drop time to reconnect and reclaim it first.
function scheduleRoomDeletion(room: string) {
  clearRoomDeletionTimer(room);
  const timer = setTimeout(() => {
    roomDeletionTimers.delete(room);
    void finalizeRoomDeletion(room);
  }, ROOM_DELETION_GRACE_MS);
  roomDeletionTimers.set(room, timer);
}

async function finalizeRoomDeletion(room: string) {
  const roomInfo = rooms.get(room);
  // Someone rejoined locally while the grace period was running — leave
  // everything alone, same as the original synchronous check.
  if (!roomInfo || roomInfo.sockets.size !== 0) return;
  rooms.delete(room);
  await unsubscribeRoomChannel(room);
  // This instance is done with the room, but another instance could still
  // have peers in it — only wipe the shared chat history once the Redis
  // roster confirms nobody's left anywhere. Safe to run on every instance
  // whose timer fires while empty: deletePersistedChat is an idempotent
  // delete, so two instances racing here can't corrupt anything.
  const peers = await getRoomPeers(room);
  if (peers.length === 0) {
    deletePersistedChat(room);
    void clearRoomCreatedAt(room);
  }
}

async function leaveRoom(info: ClientInfo) {
  if (!info.room) return;
  const room = info.room;
  const roomInfo = rooms.get(room);
  if (roomInfo) {
    roomInfo.sockets.delete(info.socket);
    if (roomInfo.sockets.size === 0) {
      // The room *looks* empty on this instance, but don't wipe its shared
      // chat history yet — see scheduleRoomDeletion/finalizeRoomDeletion.
      // (A same-identity reconnect that briefly overlaps the old socket
      // goes through detachSession instead, which deliberately does NOT
      // delete the room's chat history either, since that's not a real
      // departure — see detachSession's comment.)
      scheduleRoomDeletion(room);
    }
  }
  if (info.name) await releaseRoomName(room, info.name.toLowerCase(), info.id);
  await removeRoomPeer(room, info.id);
  info.room = null;
  info.sharing = false;
  info.mic = false;
  await broadcastToRoomCluster(room, { type: "peer-left", id: info.id }, info.socket);
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
// socket has been reaped yet — e.g. a brief network blip, or a second tab —
// and also as the reclaim handler run on whichever instance actually holds
// `info` when a *different* instance's connection reclaims it (see
// handleClientChannelMessage below: a "reclaim" message just calls this
// directly). Removes the stale session from every bookkeeping structure
// (local and Redis) and closes it *without* broadcasting peer-left, since
// this identity is carried over seamlessly to the new connection rather
// than actually leaving the room.
//
// In the cross-instance case there's a narrow, self-healing race: the
// challenger's own writes (reserveRoomName/upsertRoomPeer, or a fresh
// clientId registry epoch) aren't ordered relative to this cleanup running
// on a different process. deleteClientRecordIfOwn's epoch guard makes the
// registry cleanup race-free either way; a plain name/peerId collision
// between the two is impossible (the challenger never reclaims its *own*
// id's room slot this way — see "join"'s isSameOwner check, which only
// takes this path for a *different* peerId than the challenger's own). The
// one case left is genuinely rare (two instances racing to reclaim the
// exact same identity within milliseconds of each other) and self-corrects
// on that peer's next rename/toggle/rejoin — the same order of accepted
// race this codebase already lives with elsewhere (see the "join" handler's
// loadPersistedChat comment).
async function detachSession(info: ClientInfo) {
  if (info.room) {
    const room = info.room;
    const roomInfo = rooms.get(room);
    if (roomInfo) {
      roomInfo.sockets.delete(info.socket);
      // Deliberately leaves the persisted chat file alone even if this was
      // the room's last local socket: the new connection taking over this
      // identity is about to "join" the same room again, and will reload
      // this exact history when it recreates the local RoomInfo.
      if (roomInfo.sockets.size === 0) {
        rooms.delete(room);
        await unsubscribeRoomChannel(room);
      }
    }
    if (info.name) await releaseRoomName(room, info.name.toLowerCase(), info.id);
    await removeRoomPeer(room, info.id);
    info.room = null;
  }
  if (clientsById.get(info.id) === info) clientsById.delete(info.id);
  await deleteClientRecordIfOwn(info.id, info.registryEpoch);
  if (info.clientChannelId) {
    await unsubscribeClientChannel(info.clientChannelId);
    info.clientChannelId = undefined;
  }
  clients.delete(info.socket);
  // A graceful close (not terminate()) so the close frame with our code
  // actually reaches the displaced client instead of the connection just
  // dying silently.
  info.socket.close(SUPERSEDED_CLOSE_CODE, "superseded-by-new-connection");
}

// Terminates every socket currently connected from `ip` — called right
// after an admin bans it, so the ban takes effect immediately instead of
// only blocking that IP's *next* connection attempt. Deliberately
// local-instance-only (out of scope for the Redis cluster work in
// cluster.ts — see moderationStore.ts's own in-memory cache, which is
// Mongo/disk-synced but not cross-instance-invalidated in real time
// either): a ban still blocks every instance's *next* connection check
// (isIpBanned, at the "/ws" upgrade below) immediately, it just doesn't
// instantly kick an already-open socket on an instance other than the one
// the admin's request happened to land on.
function disconnectClientsByIp(ip: string) {
  for (const info of clients.values()) {
    if (info.ip === ip) {
      info.socket.close(BANNED_CLOSE_CODE, "ip-banned");
    }
  }
}

// Resolves whatever identity currently owns `peerId`, wherever it lives —
// checks this instance's local clientsById first (no Redis round trip for
// the common same-instance case), falling back to cluster.ts's registry
// for a peer hosted elsewhere. Used by both "register"'s and "join"'s
// reclaim checks so the ownership rule (isSameOwner) never has to care
// which instance actually holds the session it's comparing against.
async function resolveOwnerIdentity(peerId: string): Promise<OwnerIdentity | null> {
  const local = clientsById.get(peerId);
  if (local) return local;
  return getClientRecord(peerId);
}

// Takes over `clientId`'s session, wherever it currently lives: detaches it
// immediately if it's local to this instance, or asks whichever instance
// actually holds it to do so via cluster.ts's per-client channel otherwise
// (fire-and-forget — the challenger doesn't wait for that instance's
// cleanup to finish before claiming the id itself, matching how the local
// path's detachSession call was never awaited-to-completion by its
// caller's *own* side-effects either, just sequenced before them).
async function reclaimClient(clientId: string): Promise<void> {
  const local = clientsById.get(clientId);
  if (local) {
    await detachSession(local);
  } else {
    await publishToClient(clientId, { type: "reclaim" });
  }
}

// Creates (or reuses) this instance's local RoomInfo cache for `room` —
// shared by "join" and "admin-join". Loads whatever chat history is
// already persisted (Redis/disk, via chatStore.ts) the first time *this*
// instance sees the room, and subscribes to cluster.ts's room broadcast
// channel so events from peers on other instances get relayed to this
// instance's own local sockets (see handleRoomChannelMessage).
async function ensureLocalRoom(room: string): Promise<RoomInfo> {
  const existing = rooms.get(room);
  if (existing) return existing;
  const messages = await loadPersistedChat(room);
  // The await above gave a concurrent "join" for this same, brand-new room
  // on this instance a chance to land first — don't clobber a RoomInfo
  // that already showed up while we were loading.
  let roomInfo = rooms.get(room);
  if (!roomInfo) {
    roomInfo = { sockets: new Set(), messages };
    rooms.set(room, roomInfo);
    await subscribeRoomChannel(room, (m) => handleRoomChannelMessage(room, m));
  }
  return roomInfo;
}

// Applies one chat message to a room's local history cache, capped at
// ROOM_CHAT_HISTORY_LIMIT — shared by the local "chat" sender path and
// handleRoomChannelMessage below, so the cache stays correct regardless of
// whether a given message originated on this instance or was relayed from
// another one over cluster.ts's room channel.
function applyChatMessageToCache(roomInfo: RoomInfo, chatMessage: ChatMessage) {
  roomInfo.messages.push(chatMessage);
  if (roomInfo.messages.length > ROOM_CHAT_HISTORY_LIMIT) {
    roomInfo.messages.splice(0, roomInfo.messages.length - ROOM_CHAT_HISTORY_LIMIT);
  }
}

// Delivers a room event relayed from another instance to every socket this
// instance has locally in `room` — cluster.ts's subscribeRoomChannel
// already filters out this instance's own publishes (they were delivered
// directly by broadcastToRoomCluster's local call already), so everything
// reaching here genuinely originated elsewhere and needs no exclusion.
function handleRoomChannelMessage(room: string, msg: unknown) {
  const roomInfo = rooms.get(room);
  if (!roomInfo) return;
  if (msg && typeof msg === "object" && (msg as { type?: unknown }).type === "chat-message") {
    const { type: _type, ...chatMessage } = msg as { type: string } & ChatMessage;
    applyChatMessageToCache(roomInfo, chatMessage);
  }
  for (const s of roomInfo.sockets) send(s, msg);
}

// Broadcasts `msg` to this room across every instance: delivers to this
// instance's own local sockets exactly like the old broadcastToRoom always
// did (still excludes the sender's own socket — other instances never have
// that socket anyway, so no exclusion is needed on their side), and
// publishes it for every other instance's handleRoomChannelMessage to
// relay to *their* local sockets.
async function broadcastToRoomCluster(room: string, msg: unknown, exclude?: WebSocket): Promise<void> {
  broadcastToRoom(room, msg, exclude);
  await publishRoomEvent(room, msg);
}

// Applies an incoming message on this connection's per-client Redis
// channel (see subscribeClientChannel in the "register" handler below): a
// relayed WebRTC signal is delivered straight to this socket, and a
// reclaim (another instance's connection taking over this exact clientId)
// detaches this session — see detachSession's comment for why that's safe
// to do unconditionally here.
function handleClientChannelMessage(info: ClientInfo, msg: ClientChannelMessage) {
  if (msg.type === "signal") {
    send(info.socket, { type: "signal", from: msg.from, data: msg.data });
  } else if (msg.type === "reclaim") {
    void detachSession(info);
  }
}

// Primes this instance's local announcement copy from whatever's currently
// persisted in Redis, then keeps it in sync forever after via cluster.ts's
// announcement channel — called once at startup (see server/index.ts)
// after connectCluster resolves.
export async function initClusterAnnouncementSync(): Promise<void> {
  currentAnnouncement = (await getStoredAnnouncement()) as Announcement | null;
  await subscribeAnnouncementChannel((announcement) => {
    currentAnnouncement = announcement as Announcement | null;
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement });
  });
}

export function registerSignalingRoutes(app: FastifyInstance, genId: () => string) {
  // Detects and reaps half-dead connections (network dropped without a clean
  // close, e.g. mobile network handoff, sleeping laptop, NAT/proxy silently
  // dropping an idle socket). Without this, a client can vanish for other
  // peers with no "peer-left" until the OS eventually notices the TCP
  // connection is gone, which can take minutes — the pings also generate
  // periodic traffic that keeps idle-timeout proxies from killing the
  // connection in the first place.
  const heartbeat = setInterval(() => {
    for (const info of clients.values()) {
      if (!info.isAlive) {
        heartbeatReapedTotal.inc();
        info.socket.terminate();
        continue;
      }
      info.isAlive = false;
      info.socket.ping();
      // Piggybacks the Redis presence-TTL renewal (cluster.ts's
      // PRESENCE_TTL_MS) on this same tick, for every client this instance
      // still has alive — fire-and-forget, same as the rest of this
      // file's persistence calls: a missed renewal here just means this
      // peer's roster/registry entry expires a little earlier than usual
      // if the *next* tick also fails, not an immediate problem. This is
      // what makes a peer's presence actually go away within ~90s if this
      // instance dies without ever running leaveRoom/detachSession (crash,
      // OOM-kill, SIGKILL) instead of leaving a permanent "ghost" — see
      // PRESENCE_TTL_MS's comment.
      if (info.name !== null) void touchClientHeartbeat(info.id);
      if (info.room) void touchRoomPeerHeartbeat(info.room, info.id);
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
    const allRooms = await listAllRooms();
    let peopleOnline = 0;
    for (const r of allRooms) peopleOnline += r.peopleCount;
    return { peopleOnline };
  });

  // Public room directory. Private rooms (handle starts with "priv-") are
  // filtered out here, server-side — the client never receives them, so
  // there's no separate access-control step to forget on the frontend.
  // Sourced from cluster.ts's Redis roster (listAllRooms) rather than this
  // instance's local `rooms` Map, so the directory reflects every instance,
  // not just whichever one happened to answer this request.
  //
  // Same reasoning/limit as /stats: public, cheap, polled by the room
  // browser UI on a normal cadence.
  app.get("/rooms", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    const allRooms = await listAllRooms();
    const publicRooms = allRooms
      .filter((r) => !isPrivateRoom(r.handle))
      .map((r) => ({ handle: r.handle, peopleCount: r.peopleCount, createdAt: r.createdAt }))
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
    const allRooms = (await listAllRooms())
      .map((r) => ({
        handle: r.handle,
        isPrivate: isPrivateRoom(r.handle),
        createdAt: r.createdAt,
        peopleCount: r.peopleCount,
        peers: r.peers
          .filter((p) => !p.isModerator)
          .map((p) => ({ id: p.id, name: p.name, sharing: p.sharing, mic: p.mic, ip: p.ip })),
      }))
      .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
    return { rooms: allRooms };
  });

  // Site-wide banner shown to every connected socket (see broadcastToAll),
  // not scoped to a room. GET lets the admin panel show whether one's
  // already active on load; POST replaces it (and re-broadcasts); DELETE
  // ends it for everyone currently connected.
  app.get(
    "/admin/announcement",
    { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
    async (request, reply) => {
      if (!requireAdmin(request)) {
        return reply.code(401).send({ error: "unauthorized" });
      }
      return { announcement: currentAnnouncement };
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
    const text = typeof body.text === "string" ? body.text.trim().slice(0, ANNOUNCEMENT_TEXT_MAX_LEN) : "";
    const buttonLabel =
      typeof body.buttonLabel === "string"
        ? body.buttonLabel.trim().slice(0, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)
        : "";
    const buttonAction = typeof body.buttonAction === "string" ? body.buttonAction : "";
    const color = typeof body.color === "string" ? body.color : "";
    const dismissible = Boolean(body.dismissible);
    const rawUrl = typeof body.buttonUrl === "string" ? body.buttonUrl.trim() : "";

    if (!isValidAnnouncementField(text, ANNOUNCEMENT_TEXT_MAX_LEN)) {
      return reply.code(400).send({ error: "Texto inválido." });
    }
    if (!isValidAnnouncementField(buttonLabel, ANNOUNCEMENT_BUTTON_LABEL_MAX_LEN)) {
      return reply.code(400).send({ error: "Label do botão inválido." });
    }
    if (!ANNOUNCEMENT_ACTIONS.has(buttonAction as AnnouncementButtonAction)) {
      return reply.code(400).send({ error: "Ação do botão inválida." });
    }
    if (!ANNOUNCEMENT_COLORS.has(color as AnnouncementColor)) {
      return reply.code(400).send({ error: "Cor inválida." });
    }
    const needsUrl = buttonAction !== "reload";
    if (needsUrl && !isValidAnnouncementUrl(rawUrl)) {
      return reply.code(400).send({ error: "Link inválido — use uma URL http(s) completa." });
    }

    const announcement: Announcement = {
      id: genId(),
      text,
      buttonLabel,
      buttonAction: buttonAction as AnnouncementButtonAction,
      buttonUrl: needsUrl ? rawUrl : null,
      color: color as AnnouncementColor,
      dismissible,
    };
    // Publishing (rather than assigning currentAnnouncement + broadcastToAll
    // directly here) is deliberately the *only* way an announcement change
    // ever takes effect — see initClusterAnnouncementSync, whose
    // subscription handler is what actually updates currentAnnouncement and
    // broadcasts, on every instance including this one. One code path means
    // there's no way for this instance's own view of currentAnnouncement to
    // ever diverge from what it just published.
    await publishAnnouncement(announcement);
    return { announcement };
  });

  app.delete("/admin/announcement", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    await publishAnnouncement(null);
    return reply.code(204).send();
  });

  // Dashboard overview for the admin panel — aggregate numbers only (no
  // room/peer detail, see /admin/rooms for that), so it's cheap to poll.
  app.get("/admin/stats", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const allRooms = await listAllRooms();
    let peopleOnline = 0;
    let sharingCount = 0;
    let publicRooms = 0;
    let privateRooms = 0;
    for (const r of allRooms) {
      peopleOnline += r.peopleCount;
      sharingCount += r.sharingCount;
      if (isPrivateRoom(r.handle)) privateRooms += 1;
      else publicRooms += 1;
    }
    return {
      // Local to this instance only (unlike every other number in this
      // response) — out of scope for the realtime-state cluster work in
      // cluster.ts, same carve-out as server/metrics.ts. In a multi-instance
      // deployment this reflects only the instance that answered this
      // request, not the whole cluster.
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
    if (currentAnnouncement) {
      send(socket, { type: "announcement", announcement: currentAnnouncement });
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
          // could already be held by someone else in *this* room. Sourced
          // from cluster.ts's Redis room-names hash (not a local Map), since
          // whoever holds it could be on a different instance.
          if (info.room) {
            const holderId = await getRoomNameHolder(info.room, key);
            if (holderId && holderId !== info.id) {
              const holderRecord = await resolveOwnerIdentity(holderId);
              if (holderRecord && !isSameOwner(holderRecord, info)) {
                registerErrorsTotal.inc();
                send(socket, { type: "register-error", message: "Esse nome já está em uso nesta sala." });
                return;
              }
            }
          }

          const previousName = info.name;
          info.name = rawName;
          if (info.room) {
            if (previousName) await releaseRoomName(info.room, previousName.toLowerCase(), info.id);
            await reserveRoomName(info.room, key, info.id);
            await upsertRoomPeer(info.room, {
              id: info.id,
              name: rawName,
              sharing: info.sharing,
              mic: info.mic,
              userId: stableUserId(info),
              ...(info.isModerator ? { isModerator: true as const } : {}),
              ip: info.ip,
              instanceId: clusterInstanceId,
            });
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
          // ALLOW_OLD_CLIENTS_GUEST_SYSTEM. Checked first against this
          // instance's local clientsById (no Redis round trip for the common
          // case), falling back to cluster.ts's registry for a session that
          // lives on a different instance.
          const requestedClientId = typeof msg.clientId === "string" ? msg.clientId : "";
          const clientId = CLIENT_ID_RE.test(requestedClientId) ? requestedClientId : null;
          if (clientId && clientId !== info.id) {
            const existingById = clientsById.get(clientId);
            let claim = false;
            if (existingById) {
              if (existingById.socket !== socket) {
                const existingProtected =
                  !ALLOW_OLD_CLIENTS_GUEST_SYSTEM || Boolean(existingById.accountId) || existingById.guestVerified;
                claim = !existingProtected || isSameOwner(existingById, info);
                if (claim) await detachSession(existingById);
                // else: someone else's protected session — ignore the
                // requested id and keep our own freshly generated one.
              }
            } else {
              const remoteRecord = await getClientRecord(clientId);
              if (!remoteRecord) {
                claim = true;
              } else {
                const existingProtected =
                  !ALLOW_OLD_CLIENTS_GUEST_SYSTEM || Boolean(remoteRecord.accountId) || remoteRecord.guestVerified;
                claim = !existingProtected || isSameOwner(remoteRecord, info);
                if (claim) await publishToClient(clientId, { type: "reclaim" });
              }
            }
            if (claim) {
              if (clientsById.get(info.id) === info) clientsById.delete(info.id);
              await deleteClientRecordIfOwn(info.id, info.registryEpoch);
              if (info.clientChannelId) {
                await unsubscribeClientChannel(info.clientChannelId);
                info.clientChannelId = undefined;
              }
              info.id = clientId;
            }
          }
          clientsById.set(info.id, info);
          if (info.clientChannelId !== info.id) {
            if (info.clientChannelId) await unsubscribeClientChannel(info.clientChannelId);
            await subscribeClientChannel(info.id, (m: ClientChannelMessage) => handleClientChannelMessage(info, m));
            info.clientChannelId = info.id;
          }
          info.registryEpoch = await setClientRecord(info.id, {
            instanceId: clusterInstanceId,
            accountId: info.accountId,
            guestId: info.guestId,
            guestVerified: info.guestVerified,
            room: info.room,
          });

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
            await broadcastToRoomCluster(info.room, { type: "peer-renamed", id: info.id, name: rawName }, socket);
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
          // already there. Sourced from cluster.ts's Redis room-names hash,
          // since the holder could be on a different instance.
          const nameKey = info.name.toLowerCase();
          const holderId = await getRoomNameHolder(room, nameKey);
          if (holderId && holderId !== info.id) {
            const holderRecord = await resolveOwnerIdentity(holderId);
            if (holderRecord && isSameOwner(holderRecord, info)) {
              await reclaimClient(holderId);
            } else {
              send(socket, { type: "join-error", message: "Esse nome já está em uso nesta sala." });
              return;
            }
          }

          if (info.room) await leaveRoom(info);
          clearRoomDeletionTimer(room);
          info.room = room;
          info.sharing = false;
          info.mic = false;

          // Measured before this peer is added below, so a room that only
          // gained a *moderator* presence via admin-join (never counted as
          // "created") still counts as a fresh creation here — matches the
          // original local-RoomInfo-didn't-exist-yet trigger for
          // roomsCreatedTotal, just decided from the cross-instance roster
          // instead of this instance's own local cache.
          const wasEmpty = (await roomCounts(room)).people === 0;
          const roomInfo = await ensureLocalRoom(room);

          // The awaits above gave this socket's own "leave"/another "join"
          // a chance to run first and move it elsewhere (or the socket
          // could've closed outright) — don't add it to a room it's no
          // longer trying to join.
          if (info.room !== room || !clients.has(socket)) return;

          roomInfo.sockets.add(socket);
          await reserveRoomName(room, nameKey, info.id);
          await upsertRoomPeer(room, {
            id: info.id,
            name: info.name,
            sharing: info.sharing,
            mic: info.mic,
            userId: stableUserId(info),
            ip: info.ip,
            instanceId: clusterInstanceId,
          });
          if (wasEmpty) roomsCreatedTotal.inc({ visibility: isPrivateRoom(room) ? "private" : "public" });

          const peers = (await getRoomPeers(room)).filter((p) => p.id !== info.id).map(toWirePeer);
          send(socket, { type: "room-state", room, selfId: info.id, peers, messages: roomInfo.messages });
          await flushPendingSignalsFor(info);
          await broadcastToRoomCluster(
            room,
            { type: "peer-joined", id: info.id, name: info.name, userId: stableUserId(info) },
            socket
          );
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
          // Cross-instance existence check (Redis), not this instance's own
          // local `rooms` Map — a moderator connecting to a different
          // instance than the room's participants can now watch it too.
          // Counts *any* peer, moderators included — a room a real
          // participant created can otherwise keep existing purely because
          // a lingering moderator is still in it (same as the original
          // local-only `rooms.get(room)` check, which never distinguished
          // who was still there), and a second moderator should still be
          // able to join that room too.
          const roomExists = (await getRoomPeers(room)).length > 0;
          if (!roomExists) {
            send(socket, { type: "error", message: "Sala não encontrada ou já encerrada." });
            return;
          }
          if (info.room === room) return;
          if (info.room) await leaveRoom(info);
          info.isModerator = true;
          info.name = info.name ?? "Moderador";
          info.room = room;
          info.sharing = false;
          info.mic = false;
          const roomInfo = await ensureLocalRoom(room);
          if (info.room !== room || !clients.has(socket)) return;
          roomInfo.sockets.add(socket);
          // Moderators ride the same roster as real participants (see the
          // comment above) — they need to appear in every real peer's
          // cross-instance peers list too, tagged isModerator, so
          // broadcasters' "open a connection to every peer I see" logic
          // reaches them the same way it would a real participant.
          await upsertRoomPeer(room, {
            id: info.id,
            name: info.name,
            sharing: false,
            mic: false,
            isModerator: true,
            userId: stableUserId(info),
            ip: info.ip,
            instanceId: clusterInstanceId,
          });
          const adminPeers = (await getRoomPeers(room)).filter((p) => p.id !== info.id).map(toWirePeer);
          send(socket, {
            type: "room-state",
            room,
            selfId: info.id,
            peers: adminPeers,
            messages: roomInfo.messages,
          });
          await flushPendingSignalsFor(info);
          await broadcastToRoomCluster(
            room,
            { type: "peer-joined", id: info.id, name: info.name, role: "moderator", userId: stableUserId(info) },
            socket
          );
          break;
        }
        case "leave": {
          if (info.room) await leaveRoom(info);
          break;
        }
        case "sharing": {
          if (!info.room) return;
          // Dropped silently (no client feedback) when over budget: this is
          // transient toggle state, not a one-shot user action — the next
          // real toggle just propagates normally once the window resets.
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          info.sharing = Boolean(msg.sharing);
          await upsertRoomPeer(info.room, {
            id: info.id,
            name: info.name,
            sharing: info.sharing,
            mic: info.mic,
            userId: stableUserId(info),
            ...(info.isModerator ? { isModerator: true as const } : {}),
            ip: info.ip,
            instanceId: clusterInstanceId,
          });
          await broadcastToRoomCluster(info.room, { type: "peer-sharing", id: info.id, sharing: info.sharing });
          break;
        }
        case "mic": {
          if (!info.room) return;
          if (!(await consumeRateLimit(wsToggleLimiter, info.rateLimitKey, "toggle"))) return;
          info.mic = Boolean(msg.mic);
          await upsertRoomPeer(info.room, {
            id: info.id,
            name: info.name,
            sharing: info.sharing,
            mic: info.mic,
            userId: stableUserId(info),
            ...(info.isModerator ? { isModerator: true as const } : {}),
            ip: info.ip,
            instanceId: clusterInstanceId,
          });
          await broadcastToRoomCluster(info.room, { type: "peer-mic", id: info.id, mic: info.mic });
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
          applyChatMessageToCache(roomInfo, chatMessage);
          // Fire-and-forget, same as the rest of this codebase's
          // persistence calls (see e.g. deletePersistedChat below) — chat
          // already reached every peer via broadcastToRoomCluster below
          // regardless of whether/when this write lands.
          void appendPersistedChat(info.room, chatMessage, ROOM_CHAT_HISTORY_LIMIT);
          await broadcastToRoomCluster(info.room, { type: "chat-message", ...chatMessage });
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
          await deliverOrQueueSignal(info.room, targetId, info.id, msg.data);
          break;
        }
        default:
          break;
      }
    });

    socket.on("close", () => {
      wsDisconnectionsTotal.inc();
      // leaveRoom guards its own name/roster cleanup against a
      // stale/superseded session's delayed close event wiping out a newer
      // reconnect that already took over this name/id (it only ever removes
      // its *own* socket's reservation) — see leaveRoom/detachSession.
      if (info.room) void leaveRoom(info);
      if (clientsById.get(info.id) === info) {
        clientsById.delete(info.id);
        void deleteClientRecordIfOwn(info.id, info.registryEpoch);
      }
      if (info.clientChannelId) {
        void unsubscribeClientChannel(info.clientChannelId);
        info.clientChannelId = undefined;
      }
      clients.delete(socket);
    });
  });
}
