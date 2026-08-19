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
  CLUSTER_ENABLED,
  subscribeRoom,
  unsubscribeRoom,
  publishRoomEvent,
  upsertPeer,
  removePeer,
  listPeers,
  listActiveRooms,
  refreshPeers,
  sweepStalePeers,
  isRoomGloballyEmpty,
  pushPendingSignal,
  popPendingSignals,
  type ClusterEvent,
  type RemotePeer,
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

// How long a peer can go without a heartbeat-refreshed presence entry in
// Redis before sweepStalePeers reaps it — a safety net for an instance that
// vanished without a clean close (crash, OOM kill). The graceful-shutdown
// path (shutdownSignaling) removes its own peers immediately, so in the
// common rollout case this never finds anything to reap.
const STALE_PEER_AFTER_MS = HEARTBEAT_INTERVAL_MS * 3;

// Any handle starting with this is private: excluded from the public /rooms
// listing. This is the only thing that makes a room private — there's no
// separate flag to keep in sync, so it can't drift from the handle itself.
const PRIVATE_PREFIX = "priv-";

function isPrivateRoom(room: string): boolean {
  return room.startsWith(PRIVATE_PREFIX);
}

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
}

interface RoomInfo {
  sockets: Set<WebSocket>;
  createdAt: number;
  messages: ChatMessage[];
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
const namesInUse = new Map<string, WebSocket>();
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

// Set once by registerSignalingRoutes (called a single time at process
// startup) — every cluster.ts call needs to tag its events/presence writes
// with which instance produced them, and shutdownSignaling needs the
// heartbeat timer to stop it during a graceful shutdown.
let instanceId = "";
let heartbeatTimer: NodeJS.Timeout | null = null;

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

registerStatsProvider(() => ({
  connectedSockets: clients.size,
  registeredPeers: [...clients.values()].filter((c) => c.name !== null && !c.isModerator).length,
  rooms: [...rooms.entries()].map(([handle, info]) => ({
    handle,
    peopleCount: realPeopleCount(info),
    sharingCount: realSharingCount(info),
    isPrivate: isPrivateRoom(handle),
  })),
}));

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
// Delivers a relayed signal immediately if the target is reachable locally
// right now. Otherwise, when clustered, publishes it so whichever instance
// currently holds the target socket can deliver it directly, AND queues it
// in Redis in case the target isn't connected anywhere yet (reconnect may
// land on a different instance than the one that queued it, so this can't
// stay in the local pendingSignals map the way it does unclustered).
async function deliverOrQueueSignal(room: string, targetId: string, from: string, data: unknown) {
  const roomInfo = rooms.get(room);
  const target = roomInfo
    ? [...roomInfo.sockets].map((s) => clients.get(s)).find((c) => c?.id === targetId)
    : undefined;
  if (target && target.socket.readyState === target.socket.OPEN) {
    send(target.socket, { type: "signal", from, data });
    return;
  }
  if (CLUSTER_ENABLED) {
    await Promise.all([
      publishRoomEvent(room, instanceId, "signal", { to: targetId, from, data }),
      pushPendingSignal(targetId, { from, data, queuedAt: Date.now() }, Math.ceil(PENDING_SIGNAL_TTL_MS / 1000)),
    ]);
    return;
  }
  queueSignal(targetId, from, data);
}

async function flushPendingSignals(info: ClientInfo) {
  const now = Date.now();
  if (CLUSTER_ENABLED) {
    const remote = await popPendingSignals(info.id);
    for (const item of remote) {
      if (now - item.queuedAt > PENDING_SIGNAL_TTL_MS) continue;
      send(info.socket, { type: "signal", from: item.from, data: item.data });
    }
    return;
  }
  const queue = pendingSignals.get(info.id);
  if (!queue) return;
  pendingSignals.delete(info.id);
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

function toRemotePeer(info: ClientInfo): Omit<RemotePeer, "lastSeen"> {
  return {
    id: info.id,
    name: info.name,
    sharing: info.sharing,
    mic: info.mic,
    instanceId,
    ...(info.isModerator ? { role: "moderator" as const } : {}),
  };
}

function localPeerSummaries(roomInfo: RoomInfo, excludeId: string) {
  return [...roomInfo.sockets]
    .map((s) => clients.get(s))
    .filter((c): c is ClientInfo => c !== undefined && c.id !== excludeId)
    .map(peerSummary);
}

// Peer list for a "room-state"/"admin room-state" reply. Without clustering
// this is exactly the old behavior (scan local sockets). Clustered, Redis is
// the source of truth for room membership — it already includes this
// instance's own peers (every join/sharing/mic/rename upserts there too),
// so a plain listPeers() covers peers on every instance at once. Falls back
// to the local view if Redis comes back empty (a hiccup, or this peer's own
// upsert hasn't landed yet) rather than showing an empty room.
async function getRoomPeers(room: string, excludeId: string, roomInfo: RoomInfo) {
  if (!CLUSTER_ENABLED) return localPeerSummaries(roomInfo, excludeId);
  const remote = await listPeers(room);
  if (remote.length === 0) return localPeerSummaries(roomInfo, excludeId);
  return remote
    .filter((p) => p.id !== excludeId)
    .map((p) => ({ id: p.id, name: p.name, sharing: p.sharing, mic: p.mic, ...(p.role ? { role: p.role } : {}) }));
}

function realPeopleCountFromPeers(peers: RemotePeer[]): number {
  return peers.filter((p) => !p.role).length;
}

function realSharingCountFromPeers(peers: RemotePeer[]): number {
  return peers.filter((p) => !p.role && p.sharing).length;
}

// Global room directory sourced from Redis — used by the public/admin HTTP
// listing routes so they answer the same regardless of which instance in
// the cluster serves the request. (Unlike registerStatsProvider's callback
// below, which deliberately stays local-only: that one feeds /metrics,
// where a per-replica Prometheus gauge is correct and a global figure
// repeated by every replica would double-count once summed across pods.)
async function getAggregateRooms(): Promise<Array<{ handle: string; createdAt: number; peers: RemotePeer[] }>> {
  const active = await listActiveRooms();
  return Promise.all(
    active.map(async ({ handle, createdAt }) => ({ handle, createdAt, peers: await listPeers(handle) }))
  );
}

// Relays a room event published by another instance to this instance's own
// local sockets in that room. Registered once per room via subscribeRoom,
// for as long as this instance has at least one local socket in it.
function makeClusterHandler(room: string) {
  return (event: ClusterEvent) => {
    if (event.instanceId === instanceId) return;
    switch (event.type) {
      case "peer-joined":
      case "peer-left":
      case "peer-sharing":
      case "peer-mic":
      case "peer-renamed":
        broadcastToRoom(room, { type: event.type, ...(event.payload as Record<string, unknown>) });
        break;
      case "chat-message": {
        // Mirror the message into this instance's own local RoomInfo cache
        // too, not just the live broadcast — otherwise a room whose local
        // RoomInfo predates the message (created before this instance ever
        // saw this particular chat event) keeps serving a stale
        // "room-state" history to anyone who (re)joins here afterward, even
        // though the message reached everyone live at the time.
        const roomInfo = rooms.get(room);
        if (roomInfo) {
          roomInfo.messages.push(event.payload as ChatMessage);
          if (roomInfo.messages.length > ROOM_CHAT_HISTORY_LIMIT) {
            roomInfo.messages.splice(0, roomInfo.messages.length - ROOM_CHAT_HISTORY_LIMIT);
          }
        }
        broadcastToRoom(room, { type: "chat-message", ...(event.payload as Record<string, unknown>) });
        break;
      }
      case "signal": {
        const { to, from, data } = event.payload as { to: string; from: string; data: unknown };
        const target = clientsById.get(to);
        if (target) send(target.socket, { type: "signal", from, data });
        break;
      }
    }
  };
}

// Gets (or lazily creates) the local RoomInfo for `room` without touching
// roomsCreatedTotal — used by admin-join, which may be the first thing to
// touch this room *on this instance* even though it's already active
// elsewhere in the cluster (see the "join" case for the metric-counting
// creation path used by real participants).
async function ensureLocalRoom(room: string): Promise<RoomInfo> {
  let roomInfo = rooms.get(room);
  if (roomInfo) return roomInfo;
  const messages = await loadPersistedChat(room);
  roomInfo = rooms.get(room);
  if (roomInfo) return roomInfo;
  roomInfo = { sockets: new Set(), createdAt: Date.now(), messages };
  rooms.set(room, roomInfo);
  if (CLUSTER_ENABLED) await subscribeRoom(room, makeClusterHandler(room));
  return roomInfo;
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
  const timer = setTimeout(async () => {
    roomDeletionTimers.delete(room);
    const roomInfo = rooms.get(room);
    if (!roomInfo || roomInfo.sockets.size !== 0) return;
    // The local cache/subscription only serves sockets on this instance —
    // once there are none, it's cheap to tear down and recreate on the
    // next local join, regardless of whether the room is still populated
    // on another instance.
    rooms.delete(room);
    if (CLUSTER_ENABLED) await unsubscribeRoom(room);
    // But the persisted chat is shared by the whole cluster — only wipe it
    // once the room is empty *everywhere*, not just on this instance.
    const globallyEmpty = CLUSTER_ENABLED ? await isRoomGloballyEmpty(room) : true;
    if (globallyEmpty) deletePersistedChat(room);
  }, ROOM_DELETION_GRACE_MS);
  roomDeletionTimers.set(room, timer);
}

async function leaveRoom(info: ClientInfo) {
  if (!info.room) return;
  const room = info.room;
  const roomInfo = rooms.get(room);
  if (roomInfo) {
    roomInfo.sockets.delete(info.socket);
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
  if (CLUSTER_ENABLED) {
    await Promise.all([removePeer(room, info.id), publishRoomEvent(room, instanceId, "peer-left", { id: info.id })]);
  }
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
      // Deliberately leaves the persisted chat file alone even if this was
      // the room's last socket: the new connection taking over this
      // identity is about to "join" the same room again, and will reload
      // this exact history from disk when it recreates the RoomInfo.
      if (roomInfo.sockets.size === 0) {
        rooms.delete(info.room);
        if (CLUSTER_ENABLED) unsubscribeRoom(info.room);
      }
    }
    if (CLUSTER_ENABLED) removePeer(info.room, info.id);
    info.room = null;
  }
  if (info.name && namesInUse.get(info.name.toLowerCase()) === info.socket) {
    namesInUse.delete(info.name.toLowerCase());
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

export function registerSignalingRoutes(app: FastifyInstance, genId: () => string, id: string) {
  instanceId = id;


  // Detects and reaps half-dead connections (network dropped without a clean
  // close, e.g. mobile network handoff, sleeping laptop, NAT/proxy silently
  // dropping an idle socket). Without this, a client can vanish for other
  // peers with no "peer-left" until the OS eventually notices the TCP
  // connection is gone, which can take minutes — the pings also generate
  // periodic traffic that keeps idle-timeout proxies from killing the
  // connection in the first place. Doubles, when clustered, as the
  // heartbeat that refreshes this instance's peers in Redis and sweeps out
  // any other instance's peers that went stale (see STALE_PEER_AFTER_MS).
  heartbeatTimer = setInterval(() => {
    const now = Date.now();
    for (const [targetId, queue] of pendingSignals) {
      const fresh = queue.filter((item) => now - item.queuedAt <= PENDING_SIGNAL_TTL_MS);
      if (fresh.length === 0) pendingSignals.delete(targetId);
      else if (fresh.length !== queue.length) pendingSignals.set(targetId, fresh);
    }
    const refreshEntries: Array<{ room: string; peer: Omit<RemotePeer, "lastSeen"> }> = [];
    for (const info of clients.values()) {
      if (!info.isAlive) {
        heartbeatReapedTotal.inc();
        info.socket.terminate();
        continue;
      }
      info.isAlive = false;
      info.socket.ping();
      if (CLUSTER_ENABLED && info.room) {
        refreshEntries.push({ room: info.room, peer: toRemotePeer(info) });
      }
    }
    if (CLUSTER_ENABLED) {
      refreshPeers(refreshEntries);
      sweepStalePeers(STALE_PEER_AFTER_MS);
    }
  }, HEARTBEAT_INTERVAL_MS);

  app.addHook("onClose", (_instance, done) => {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    done();
  });

  // Site-wide "people online" counter. Unlike /rooms this includes private
  // rooms — but only ever returns a single aggregate number, never handles
  // or peer detail, so it can't be used to discover a private room's
  // existence the way /admin/rooms can.
  app.get("/stats", async () => {
    if (CLUSTER_ENABLED) {
      const aggregate = await getAggregateRooms();
      let peopleOnline = 0;
      for (const { peers } of aggregate) peopleOnline += realPeopleCountFromPeers(peers);
      return { peopleOnline };
    }
    let peopleOnline = 0;
    for (const info of rooms.values()) peopleOnline += realPeopleCount(info);
    return { peopleOnline };
  });

  // Public room directory. Private rooms (handle starts with "priv-") are
  // filtered out here, server-side — the client never receives them, so
  // there's no separate access-control step to forget on the frontend.
  // Sourced from Redis when clustered so this answers the same regardless
  // of which instance the load balancer happens to route the request to.
  app.get("/rooms", async () => {
    if (CLUSTER_ENABLED) {
      const aggregate = await getAggregateRooms();
      const publicRooms = aggregate
        .filter(({ handle }) => !isPrivateRoom(handle))
        .map(({ handle, createdAt, peers }) => ({
          handle,
          peopleCount: realPeopleCountFromPeers(peers),
          createdAt,
        }))
        .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
      return { rooms: publicRooms };
    }
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
  app.post("/auth/register", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = typeof body.username === "string" ? body.username.trim() : "";
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

  app.post("/auth/login", async (request, reply) => {
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

  app.get("/auth/me", async (request, reply) => {
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
  app.get("/admin/rooms", async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (CLUSTER_ENABLED) {
      const aggregate = await getAggregateRooms();
      const allRooms = aggregate
        .map(({ handle, createdAt, peers }) => ({
          handle,
          isPrivate: isPrivateRoom(handle),
          createdAt,
          peopleCount: realPeopleCountFromPeers(peers),
          peers: peers
            .filter((p) => !p.role)
            .map((p) => ({ id: p.id, name: p.name, sharing: p.sharing, mic: p.mic })),
        }))
        .sort((a, b) => b.peopleCount - a.peopleCount || a.createdAt - b.createdAt);
      return { rooms: allRooms };
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
  // already active on load; POST replaces it (and re-broadcasts); DELETE
  // ends it for everyone currently connected.
  app.get("/admin/announcement", async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return { announcement: currentAnnouncement };
  });

  app.post("/admin/announcement", async (request, reply) => {
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

    currentAnnouncement = {
      id: genId(),
      text,
      buttonLabel,
      buttonAction: buttonAction as AnnouncementButtonAction,
      buttonUrl: needsUrl ? rawUrl : null,
      color: color as AnnouncementColor,
      dismissible,
    };
    broadcastToAll({ type: "announcement", announcement: currentAnnouncement });
    return { announcement: currentAnnouncement };
  });

  app.delete("/admin/announcement", async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    currentAnnouncement = null;
    broadcastToAll({ type: "announcement", announcement: null });
    return reply.code(204).send();
  });

  // Dashboard overview for the admin panel — aggregate numbers only (no
  // room/peer detail, see /admin/rooms for that), so it's cheap to poll.
  app.get("/admin/stats", async (request, reply) => {
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
  app.get("/admin/bans", async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return { bans: listBans() };
  });

  app.post("/admin/bans", async (request, reply) => {
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

  app.delete("/admin/bans/:ip", async (request, reply) => {
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
  app.get("/admin/banned-words", async (request, reply) => {
    if (!requireAdmin(request)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return { words: listBannedWords() };
  });

  app.put("/admin/banned-words", async (request, reply) => {
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

  app.get("/ws", { websocket: true }, (socket: WebSocket, request: FastifyRequest) => {
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

      switch (msg.type) {
        case "register": {
          const rawName = typeof msg.name === "string" ? msg.name.trim().slice(0, 24) : "";
          if (!isValidDisplayName(rawName)) {
            registerErrorsTotal.inc();
            send(socket, { type: "register-error", message: "Nome inválido." });
            return;
          }

          // A client-supplied id (persisted client-side across reloads and
          // reconnects) lets a returning client reclaim its previous
          // identity instead of showing up as a stranger to everyone else's
          // still-open peer connections. If a stale session under that id
          // is still around (server restart wiped nothing since it's a
          // fresh process, but a plain reconnect can race the heartbeat
          // reaper), take it over cleanly first.
          // A logged-in client passes its JWT here so the rest of this
          // session (the reserved-name check right below, admin checks,
          // etc) can trust info.accountId instead of re-verifying a token
          // on every message.
          const rawToken = typeof msg.token === "string" ? msg.token : "";
          const authPayload = rawToken ? verifyToken(rawToken) : null;

          const requestedClientId = typeof msg.clientId === "string" ? msg.clientId : "";
          const clientId = CLIENT_ID_RE.test(requestedClientId) ? requestedClientId : null;
          const existingById = clientId ? clientsById.get(clientId) : undefined;
          if (existingById && existingById.socket !== socket) {
            detachSession(existingById);
          }

          const key = rawName.toLowerCase();
          const existingByName = namesInUse.get(key);
          if (existingByName && existingByName !== socket) {
            registerErrorsTotal.inc();
            send(socket, { type: "register-error", message: "Esse nome já está em uso." });
            return;
          }
          // A name tied to a registered account (its username or display
          // name) is reserved for that account's owner — anyone else, guest
          // or a different account, trying to register under it gets
          // rejected the same as an already-in-use name above.
          const reservedOwnerId = isNameReserved(key);
          if (reservedOwnerId && reservedOwnerId !== authPayload?.sub) {
            registerErrorsTotal.inc();
            send(socket, {
              type: "register-error",
              message: "Esse nome pertence a uma conta registrada.",
            });
            return;
          }
          const previousName = info.name;
          if (info.name) namesInUse.delete(info.name.toLowerCase());
          info.name = rawName;
          namesInUse.set(key, socket);
          info.accountId = authPayload?.sub;
          info.flags = authPayload?.flags;

          if (clientId && clientId !== info.id) {
            if (clientsById.get(info.id) === info) clientsById.delete(info.id);
            info.id = clientId;
          }
          clientsById.set(info.id, info);

          send(socket, {
            type: "registered",
            id: info.id,
            name: rawName,
            account: authPayload
              ? { username: authPayload.username, flags: authPayload.flags }
              : null,
          });

          // Renaming while already in a room doesn't go through "join"
          // again, so nothing else would tell the other participants —
          // without this their peer list would keep showing the old name.
          if (info.room && previousName && previousName !== rawName) {
            broadcastToRoom(info.room, { type: "peer-renamed", id: info.id, name: rawName }, socket);
            if (CLUSTER_ENABLED) {
              upsertPeer(info.room, toRemotePeer(info));
              publishRoomEvent(info.room, instanceId, "peer-renamed", { id: info.id, name: rawName });
            }
          }
          break;
        }
        case "join": {
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
              roomInfo = { sockets: new Set(), createdAt: Date.now(), messages };
              rooms.set(room, roomInfo);
              roomsCreatedTotal.inc({ visibility: isPrivateRoom(room) ? "private" : "public" });
            }
          }
          // subscribeRoom is idempotent (no-ops if already subscribed), so
          // it's safe to call on every join regardless of whether this
          // particular call is the one that created the local RoomInfo.
          if (CLUSTER_ENABLED) await subscribeRoom(room, makeClusterHandler(room));
          // The await above gave this socket's own "leave"/another "join"
          // a chance to run first and move it elsewhere (or the socket
          // could've closed outright) — don't add it to a room it's no
          // longer trying to join.
          if (info.room !== room || !clients.has(socket)) return;
          roomInfo.sockets.add(socket);
          if (CLUSTER_ENABLED) await upsertPeer(room, toRemotePeer(info));
          const peers = await getRoomPeers(room, info.id, roomInfo);
          send(socket, { type: "room-state", room, selfId: info.id, peers, messages: roomInfo.messages });
          flushPendingSignals(info);
          broadcastToRoom(room, { type: "peer-joined", id: info.id, name: info.name }, socket);
          if (CLUSTER_ENABLED) {
            publishRoomEvent(room, instanceId, "peer-joined", { id: info.id, name: info.name });
          }
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
          // A room can be active on another instance without this one ever
          // having seen a local socket for it — check globally, not just
          // this instance's local cache, before declaring it gone.
          const existsLocally = rooms.has(room);
          const existsGlobally = CLUSTER_ENABLED ? !(await isRoomGloballyEmpty(room)) : existsLocally;
          if (!existsLocally && !existsGlobally) {
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
          const roomInfo = await ensureLocalRoom(room);
          // Mirrors "join": the await above could let this socket move
          // elsewhere or close outright — don't add it to a room it's no
          // longer trying to join.
          if (info.room !== room || !clients.has(socket)) return;
          roomInfo.sockets.add(socket);
          if (CLUSTER_ENABLED) await upsertPeer(room, toRemotePeer(info));
          const adminPeers = await getRoomPeers(room, info.id, roomInfo);
          send(socket, {
            type: "room-state",
            room,
            selfId: info.id,
            peers: adminPeers,
            messages: roomInfo.messages,
          });
          flushPendingSignals(info);
          broadcastToRoom(room, { type: "peer-joined", id: info.id, name: info.name, role: "moderator" }, socket);
          if (CLUSTER_ENABLED) {
            publishRoomEvent(room, instanceId, "peer-joined", { id: info.id, name: info.name, role: "moderator" });
          }
          break;
        }
        case "leave": {
          if (info.room) leaveRoom(info);
          break;
        }
        case "sharing": {
          if (!info.room) return;
          info.sharing = Boolean(msg.sharing);
          broadcastToRoom(info.room, { type: "peer-sharing", id: info.id, sharing: info.sharing });
          if (CLUSTER_ENABLED) {
            upsertPeer(info.room, toRemotePeer(info));
            publishRoomEvent(info.room, instanceId, "peer-sharing", { id: info.id, sharing: info.sharing });
          }
          break;
        }
        case "mic": {
          if (!info.room) return;
          info.mic = Boolean(msg.mic);
          broadcastToRoom(info.room, { type: "peer-mic", id: info.id, mic: info.mic });
          if (CLUSTER_ENABLED) {
            upsertPeer(info.room, toRemotePeer(info));
            publishRoomEvent(info.room, instanceId, "peer-mic", { id: info.id, mic: info.mic });
          }
          break;
        }
        case "chat": {
          if (!info.room) return;
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
          if (CLUSTER_ENABLED) {
            publishRoomEvent(info.room, instanceId, "chat-message", chatMessage);
          }
          break;
        }
        case "signal": {
          if (!info.room) return;
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
        default:
          break;
      }
    });

    socket.on("close", () => {
      wsDisconnectionsTotal.inc();
      if (info.room) leaveRoom(info);
      // Guard against a stale/superseded session's delayed close event
      // wiping out a newer reconnect that already took over this name/id.
      if (info.name && namesInUse.get(info.name.toLowerCase()) === socket) {
        namesInUse.delete(info.name.toLowerCase());
      }
      if (clientsById.get(info.id) === info) {
        clientsById.delete(info.id);
        pendingSignals.delete(info.id);
      }
      clients.delete(socket);
    });
  });
}

// Called from index.ts on SIGTERM/SIGINT. Tells every locally-connected
// client the process is about to go away (so the browser-side reconnect
// logic can act immediately instead of waiting to notice the socket died),
// then cleans up this instance's room presence and closes each socket with
// close code 1012 ("Service Restart") so it reads as an intentional,
// reconnect-worthy close rather than a network failure.
export async function shutdownSignaling(): Promise<void> {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
  const infos = [...clients.values()];
  for (const info of infos) {
    send(info.socket, { type: "server-shutdown" });
  }
  await Promise.all(
    infos.map(async (info) => {
      if (info.room) await leaveRoom(info);
      info.socket.close(1012, "server-shutting-down");
    })
  );
}
