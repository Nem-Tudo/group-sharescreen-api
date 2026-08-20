import { randomUUID } from "node:crypto";
import { createClient } from "redis";

// Unlike chatStore.ts's Redis usage (opt-in, falls back to disk), this
// module is the cross-instance coordination layer itself — rooms,
// presence, name reservations, clientId ownership/reclaim, the WebRTC
// signal relay, and the announcement banner all live here instead of only
// in this process's memory (see signaling.ts). Running more than one
// instance behind a load balancer is only safe once this is wired up, so
// REDIS_URL is a hard requirement (connectCluster throws without it) rather
// than an optional enhancement.
const REDIS_URL = process.env.REDIS_URL;

// Same rationale as chatStore.ts's RedisClient alias: @redis/client's
// generic RedisClientType doesn't structurally match itself across
// separate `ReturnType<typeof createClient>` computations, so a precise
// alias costs more than it's worth for the plain commands used below.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

// Stamps every pub/sub message this process publishes, so a subscription
// handler can recognize (and skip) its own echo — the local delivery path
// (broadcastToRoom et al. in signaling.ts) already handled it directly, no
// need to redeliver from the loop-back copy of our own publish.
export const instanceId = randomUUID();

let commandClient: RedisClient | null = null;
let subscriberClient: RedisClient | null = null;
let connecting: Promise<void> | null = null;

// Connects both the command client (regular reads/writes/publishes) and a
// duplicated subscriber client (node-redis requires a dedicated connection
// once it enters subscribe mode). Called once at startup from
// server/index.ts, before the server starts accepting connections — every
// function below assumes this has already resolved.
export async function connectCluster(): Promise<void> {
  if (connecting) return connecting;
  if (!REDIS_URL) {
    throw new Error(
      "REDIS_URL não configurada — obrigatória para coordenar múltiplas instâncias (ver server/cluster.ts)."
    );
  }
  connecting = (async () => {
    const cmd = createClient({ url: REDIS_URL });
    cmd.on("error", (err: Error) => {
      console.error("[cluster] Erro na conexão com o Redis:", err.message);
    });
    const sub = cmd.duplicate();
    sub.on("error", (err: Error) => {
      console.error("[cluster] Erro na conexão (subscriber) com o Redis:", err.message);
    });
    await Promise.all([cmd.connect(), sub.connect()]);
    commandClient = cmd;
    subscriberClient = sub;
  })();
  try {
    await connecting;
  } catch (err) {
    connecting = null;
    throw err;
  }
}

function cmd(): RedisClient {
  if (!commandClient) throw new Error("cluster: connectCluster() ainda não foi chamado.");
  return commandClient;
}

function sub(): RedisClient {
  if (!subscriberClient) throw new Error("cluster: connectCluster() ainda não foi chamado.");
  return subscriberClient;
}

function roomPeersKey(room: string): string {
  return `sharescreen:room:${room}:peers`;
}
function roomNamesKey(room: string): string {
  return `sharescreen:room:${room}:names`;
}
function roomCreatedAtKey(room: string): string {
  return `sharescreen:room:${room}:createdAt`;
}
function roomChannel(room: string): string {
  return `sharescreen:room:${room}:events`;
}
function clientChannel(clientId: string): string {
  return `sharescreen:client:${clientId}`;
}
function pendingKey(clientId: string): string {
  return `sharescreen:pending:${clientId}`;
}
function roomHeartbeatsKey(room: string): string {
  return `sharescreen:room:${room}:heartbeats`;
}
const CLIENTS_KEY = "sharescreen:clients";
const CLIENTS_HEARTBEATS_KEY = "sharescreen:clients:heartbeats";
const ANNOUNCEMENT_KEY = "sharescreen:announcement:current";
const ANNOUNCEMENT_CHANNEL = "sharescreen:announcement";

// How long a room-peer/clientId registry entry stays valid without a fresh
// heartbeat before it's treated as gone. Renewed every signaling.ts WS
// heartbeat tick (25s — see HEARTBEAT_INTERVAL_MS there) for every locally
// connected, registered/in-a-room client, so under normal operation this
// never comes close to expiring. It only matters when an instance stops
// renewing altogether — almost always because it died without running any
// cleanup code (crash, OOM-kill, SIGKILL) rather than a graceful shutdown,
// which already runs leaveRoom/detachSession synchronously. 90s is a
// several-missed-ticks margin (tolerates a GC pause or a brief Redis
// hiccup without falsely expiring someone still very much connected) while
// still clearing a genuinely dead instance's presence within about a
// minute and a half instead of leaving it a permanent "ghost" in every
// room/registry read.
const PRESENCE_TTL_MS = 90_000;

// Mirrors signaling.ts's peerSummary() plus `ip` (needed for /admin/rooms,
// which today reads it straight off the local ClientInfo) and `instanceId`
// (which instance currently hosts the live socket behind this peer).
export interface RoomPeerRecord {
  id: string;
  name: string | null;
  sharing: boolean;
  mic: boolean;
  isModerator?: boolean;
  ip: string;
  instanceId: string;
  // Stable per-account (accountId) or per-guest (guestId) identity — unlike
  // `id`, which is per-connection and changes on every reconnect, this stays
  // the same across reloads/reconnects for the same person, so clients can
  // key durable local preferences (e.g. per-peer volume) on it instead.
  userId?: string;
}

// The cross-instance equivalent of a clientsById entry. `epoch` is a fresh
// random value written on every claim (register's reclaim path, or a plain
// first-time registration) — see deleteClientRecordIfOwn for why.
export interface ClientRecord {
  instanceId: string;
  epoch: string;
  accountId?: string;
  guestId?: string;
  guestVerified?: boolean;
  room: string | null;
}

export interface PendingSignalEntry {
  from: string;
  data: unknown;
  queuedAt: number;
}

export interface RoomAggregate {
  handle: string;
  peopleCount: number;
  sharingCount: number;
  createdAt: number;
  peers: RoomPeerRecord[];
}

// --- Room roster ------------------------------------------------------

// Adds/updates one peer's entry in `room`'s roster and stamps its
// heartbeat as fresh right now (see PRESENCE_TTL_MS) — the periodic renewal
// from signaling.ts's WS heartbeat tick (touchRoomPeerHeartbeat) is what
// keeps it fresh after this. Also stamps the room's createdAt the first
// time it's ever touched (SET NX — later calls for the same room are
// no-ops), mirroring the local RoomInfo.createdAt that used to be set once
// when the room's first local socket joined.
export async function upsertRoomPeer(room: string, peer: RoomPeerRecord): Promise<void> {
  const multi = cmd().multi();
  multi.hSet(roomPeersKey(room), peer.id, JSON.stringify(peer));
  multi.zAdd(roomHeartbeatsKey(room), { value: peer.id, score: Date.now() });
  multi.set(roomCreatedAtKey(room), String(Date.now()), { NX: true });
  await multi.exec();
}

export async function removeRoomPeer(room: string, peerId: string): Promise<void> {
  const multi = cmd().multi();
  multi.hDel(roomPeersKey(room), peerId);
  multi.zRem(roomHeartbeatsKey(room), peerId);
  await multi.exec();
}

// Called once a room is confirmed truly empty (see signaling.ts's
// finalizeRoomDeletion) — the peers/names hashes and the heartbeats zset
// all auto-delete themselves once their last field/member is removed, but
// this plain string key doesn't, so it's the one piece of room state that
// needs an explicit delete to avoid leaking one small key per room handle
// ever used, forever.
export async function clearRoomCreatedAt(room: string): Promise<void> {
  await cmd().del(roomCreatedAtKey(room));
}

// Renews `peerId`'s presence in `room` without rewriting its roster entry —
// called every signaling.ts WS heartbeat tick (~25s) for every locally
// connected peer still in a room, purely to keep PRESENCE_TTL_MS from
// elapsing. Fire-and-forget from the caller's perspective (see
// signaling.ts) — a missed renewal just means slightly earlier expiry, not
// a correctness problem.
export async function touchRoomPeerHeartbeat(room: string, peerId: string): Promise<void> {
  await cmd().zAdd(roomHeartbeatsKey(room), { value: peerId, score: Date.now() });
}

async function aliveRoomPeerIds(room: string): Promise<Set<string>> {
  const ids = await cmd().zRangeByScore(roomHeartbeatsKey(room), Date.now() - PRESENCE_TTL_MS, "+inf");
  return new Set(ids as string[]);
}

async function isRoomPeerAlive(room: string, peerId: string): Promise<boolean> {
  const score = await cmd().zScore(roomHeartbeatsKey(room), peerId);
  return typeof score === "number" && score >= Date.now() - PRESENCE_TTL_MS;
}

// A peer whose heartbeat has expired (see PRESENCE_TTL_MS) is filtered out
// here and cleaned up as a side effect of having noticed it — lazy,
// on-read cleanup, the same pattern moderationStore.ts's isIpBanned
// already uses for an expired ban. This is what turns an instance dying
// without running any cleanup code into a peer that's merely absent from
// every room/registry read within ~90s, instead of a permanent "ghost"
// that lingers until someone manually clears it.
export async function getRoomPeers(room: string): Promise<RoomPeerRecord[]> {
  const client = cmd();
  const [raw, alive] = await Promise.all([client.hGetAll(roomPeersKey(room)), aliveRoomPeerIds(room)]);
  const live: RoomPeerRecord[] = [];
  const stale: RoomPeerRecord[] = [];
  for (const json of Object.values(raw as Record<string, string>)) {
    const peer = JSON.parse(json) as RoomPeerRecord;
    (alive.has(peer.id) ? live : stale).push(peer);
  }
  if (stale.length > 0) void reapStaleRoomPeers(room, stale);
  return live;
}

async function reapStaleRoomPeers(room: string, stalePeers: RoomPeerRecord[]): Promise<void> {
  const multi = cmd().multi();
  for (const peer of stalePeers) {
    multi.hDel(roomPeersKey(room), peer.id);
    multi.zRem(roomHeartbeatsKey(room), peer.id);
  }
  await multi.exec();
  // Guarded (releaseRoomName only deletes if this exact peerId still holds
  // the name) rather than batched into the multi above — a name this stale
  // peer once held could already have been legitimately reclaimed by
  // someone else between the heartbeat expiring and this cleanup running.
  await Promise.all(
    stalePeers.filter((p) => p.name).map((p) => releaseRoomName(room, p.name!.toLowerCase(), p.id))
  );
}

// Real (non-moderator) headcount/sharing-count for a room — the
// cross-instance equivalent of signaling.ts's realPeopleCount/
// realSharingCount, used wherever a number or list is shown to an
// ordinary user.
export async function roomCounts(room: string): Promise<{ people: number; sharing: number }> {
  const peers = await getRoomPeers(room);
  let people = 0;
  let sharing = 0;
  for (const peer of peers) {
    if (peer.isModerator) continue;
    people += 1;
    if (peer.sharing) sharing += 1;
  }
  return { people, sharing };
}

function extractRoomHandle(key: string): string | null {
  const match = /^sharescreen:room:(.+):peers$/.exec(key);
  return match ? match[1] : null;
}

// Every active room (at least one *live* peer, on any instance) with its
// aggregated counts and full peer list — backs /rooms, /stats,
// /admin/rooms and /admin/stats, all of which used to just iterate the
// local `rooms` Map. Uses SCAN (not KEYS) so this stays safe to call on
// every request even as the key space grows. Reuses getRoomPeers per room
// (rather than reading each room's hash directly) so a room that's really
// just heartbeat-expired ghosts is correctly reported — and cleaned up —
// the same as everywhere else that reads presence.
export async function listAllRooms(): Promise<RoomAggregate[]> {
  const client = cmd();
  const rooms: RoomAggregate[] = [];
  for await (const key of client.scanIterator({ MATCH: "sharescreen:room:*:peers", COUNT: 100 })) {
    const handle = extractRoomHandle(key as string);
    if (!handle) continue;
    const peers = await getRoomPeers(handle);
    // A hash Redis just reported via SCAN could've emptied out (auto-deleted
    // on its last field, or every remaining peer being a stale ghost just
    // reaped above) between the SCAN and this read — skip rather than
    // report a phantom empty room.
    if (peers.length === 0) continue;
    let peopleCount = 0;
    let sharingCount = 0;
    for (const peer of peers) {
      if (peer.isModerator) continue;
      peopleCount += 1;
      if (peer.sharing) sharingCount += 1;
    }
    const createdAtRaw = await client.get(roomCreatedAtKey(handle));
    rooms.push({
      handle,
      peopleCount,
      sharingCount,
      createdAt: createdAtRaw ? Number(createdAtRaw) : Date.now(),
      peers,
    });
  }
  return rooms;
}

// --- Room-scoped name reservations -------------------------------------

// Plain read-then-write, not Lua-guarded — same small accepted race window
// the original in-memory Map-based version already had (nothing else in
// this codebase locks/transactions this kind of check-then-act either; see
// the "join" handler's own comment about the loadPersistedChat race).
export async function reserveRoomName(room: string, nameKey: string, peerId: string): Promise<void> {
  await cmd().hSet(roomNamesKey(room), nameKey, peerId);
}

// Only releases the reservation if `peerId` is still the one holding it —
// guards against a stale/delayed release clobbering a newer holder's claim
// on the same name.
export async function releaseRoomName(room: string, nameKey: string, peerId: string): Promise<void> {
  const client = cmd();
  const current = await client.hGet(roomNamesKey(room), nameKey);
  if (current === peerId) await client.hDel(roomNamesKey(room), nameKey);
}

// A name held by a peer whose heartbeat has since expired (see
// PRESENCE_TTL_MS) is treated as free — self-heals the reservation the
// same way getRoomPeers self-heals the roster, so a ghost from a dead
// instance can't permanently squat a display name in the room.
export async function getRoomNameHolder(room: string, nameKey: string): Promise<string | null> {
  const holder = await cmd().hGet(roomNamesKey(room), nameKey);
  if (!holder) return null;
  if (await isRoomPeerAlive(room, holder)) return holder;
  void releaseRoomName(room, nameKey, holder);
  return null;
}

// --- Global clientId ownership registry ---------------------------------

async function getRawClientRecord(clientId: string): Promise<ClientRecord | null> {
  const raw = await cmd().hGet(CLIENTS_KEY, clientId);
  return raw ? (JSON.parse(raw) as ClientRecord) : null;
}

async function isClientAlive(clientId: string): Promise<boolean> {
  const score = await cmd().zScore(CLIENTS_HEARTBEATS_KEY, clientId);
  return typeof score === "number" && score >= Date.now() - PRESENCE_TTL_MS;
}

// A client whose heartbeat has expired (see PRESENCE_TTL_MS) is treated as
// not registered anywhere and cleaned up here — same lazy on-read pattern
// as getRoomPeers/getRoomNameHolder, so a dead instance's registrations
// don't permanently block (register would otherwise think the id is still
// "someone else's protected session") or falsely validate a reclaim once
// that instance is actually gone.
export async function getClientRecord(clientId: string): Promise<ClientRecord | null> {
  const record = await getRawClientRecord(clientId);
  if (!record) return null;
  if (await isClientAlive(clientId)) return record;
  void reapExpiredClient(clientId, record.epoch);
  return null;
}

// Writes a fresh epoch on every call — the returned value is what the
// caller should hold onto (ClientInfo.registryEpoch) and pass back into
// deleteClientRecordIfOwn later, so a delayed cleanup from a
// since-superseded connection can never delete a newer owner's entry. Also
// stamps the heartbeat fresh; signaling.ts's WS heartbeat tick
// (touchClientHeartbeat) is what keeps it fresh after this.
export async function setClientRecord(clientId: string, record: Omit<ClientRecord, "epoch">): Promise<string> {
  const epoch = randomUUID();
  const full: ClientRecord = { ...record, epoch };
  const multi = cmd().multi();
  multi.hSet(CLIENTS_KEY, clientId, JSON.stringify(full));
  multi.zAdd(CLIENTS_HEARTBEATS_KEY, { value: clientId, score: Date.now() });
  await multi.exec();
  return epoch;
}

// Renews `clientId`'s presence without rewriting its registry entry —
// called every signaling.ts WS heartbeat tick (~25s) for every locally
// connected, registered client, purely to keep PRESENCE_TTL_MS from
// elapsing.
export async function touchClientHeartbeat(clientId: string): Promise<void> {
  await cmd().zAdd(CLIENTS_HEARTBEATS_KEY, { value: clientId, score: Date.now() });
}

// The cross-process equivalent of signaling.ts's `clientsById.get(info.id)
// === info` identity check: only deletes if the registry still holds the
// exact epoch this connection last wrote. In the reclaim flow the new
// owner writes its own (different) epoch before the old connection's
// cleanup ever runs, so this naturally no-ops instead of deleting the new
// owner's fresh entry. Deliberately reads the raw (not liveness-filtered)
// record — this is an explicit "delete my own entry" call from the epoch's
// actual owner, not a passive staleness check, and going through
// getClientRecord here would recurse into reapExpiredClient below for no
// reason.
export async function deleteClientRecordIfOwn(clientId: string, epoch: string | undefined): Promise<void> {
  if (!epoch) return;
  const current = await getRawClientRecord(clientId);
  if (current && current.epoch === epoch) {
    const multi = cmd().multi();
    multi.hDel(CLIENTS_KEY, clientId);
    multi.zRem(CLIENTS_HEARTBEATS_KEY, clientId);
    await multi.exec();
  }
}

async function reapExpiredClient(clientId: string, epoch: string): Promise<void> {
  await deleteClientRecordIfOwn(clientId, epoch);
}

// --- Room broadcast relay ------------------------------------------------

type RoomEventHandler = (msg: unknown) => void;
const subscribedRooms = new Set<string>();

// Delivers `msg` to every socket this instance has locally in `room` that
// isn't the originator (the direct local broadcastToRoom call in
// signaling.ts already covers this instance's own sockets — the
// originInstanceId check below is what stops that from happening twice).
export async function subscribeRoomChannel(room: string, handler: RoomEventHandler): Promise<void> {
  if (subscribedRooms.has(room)) return;
  subscribedRooms.add(room);
  await sub().subscribe(roomChannel(room), (message: string) => {
    let payload: { originInstanceId: string; msg: unknown };
    try {
      payload = JSON.parse(message);
    } catch {
      return;
    }
    if (payload.originInstanceId === instanceId) return;
    handler(payload.msg);
  });
}

export async function unsubscribeRoomChannel(room: string): Promise<void> {
  if (!subscribedRooms.has(room)) return;
  subscribedRooms.delete(room);
  await sub().unsubscribe(roomChannel(room));
}

export async function publishRoomEvent(room: string, msg: unknown): Promise<void> {
  await cmd().publish(roomChannel(room), JSON.stringify({ originInstanceId: instanceId, msg }));
}

// --- Site-wide announcement banner ---------------------------------------

type AnnouncementHandler = (announcement: unknown) => void;

export async function subscribeAnnouncementChannel(handler: AnnouncementHandler): Promise<void> {
  await sub().subscribe(ANNOUNCEMENT_CHANNEL, (message: string) => {
    try {
      handler(JSON.parse(message));
    } catch {
      // Malformed payload — ignore rather than crash the subscription.
    }
  });
}

// Persists `announcement` (or clears it, when null) so a freshly-started
// instance can prime its local copy via getStoredAnnouncement, then
// notifies every instance (including this one, via the loop-back message)
// to update its own local copy and broadcast to its local sockets.
export async function publishAnnouncement(announcement: unknown): Promise<void> {
  const client = cmd();
  if (announcement) await client.set(ANNOUNCEMENT_KEY, JSON.stringify(announcement));
  else await client.del(ANNOUNCEMENT_KEY);
  await client.publish(ANNOUNCEMENT_CHANNEL, JSON.stringify(announcement));
}

export async function getStoredAnnouncement(): Promise<unknown | null> {
  const raw = await cmd().get(ANNOUNCEMENT_KEY);
  return raw ? JSON.parse(raw) : null;
}

// --- Per-client signal/reclaim channel ------------------------------------

export type ClientChannelMessage =
  | { type: "signal"; from: string; data: unknown }
  | { type: "reclaim" };
type ClientChannelHandler = (msg: ClientChannelMessage) => void;

// Subscribed only while `clientId` is actually live on this instance (see
// signaling.ts's "register" handler) — exactly one instance is ever
// subscribed to a given clientId's channel at a time, which is what lets
// publishToClient's subscriber-count return double as an "is this id live
// anywhere right now" check.
export async function subscribeClientChannel(clientId: string, handler: ClientChannelHandler): Promise<void> {
  await sub().subscribe(clientChannel(clientId), (message: string) => {
    try {
      handler(JSON.parse(message) as ClientChannelMessage);
    } catch {
      // Malformed payload — ignore rather than crash the subscription.
    }
  });
}

export async function unsubscribeClientChannel(clientId: string): Promise<void> {
  await sub().unsubscribe(clientChannel(clientId));
}

// Returns the number of subscribers that received the publish — 0 means
// nobody is currently subscribed for this clientId (i.e. it isn't
// connected on any instance right now), which the caller uses to decide
// whether to fall back to queuePendingSignal instead.
export async function publishToClient(clientId: string, msg: ClientChannelMessage): Promise<number> {
  return cmd().publish(clientChannel(clientId), JSON.stringify(msg));
}

// --- Durable pending-signal queue -----------------------------------------

// Replaces the old process-local pendingSignals Map entirely: a signal
// queued here survives the queuing instance restarting, and is reachable
// from flushPendingSignals regardless of which instance the target peer
// eventually reconnects to. MAX_PENDING_SIGNALS_PER_TARGET mirrors the
// original local queue's cap; the EXPIRE is just a backstop for a peer that
// never comes back — real staleness filtering by `queuedAt` still happens
// at flush time in signaling.ts, same as before.
const MAX_PENDING_SIGNALS_PER_TARGET = 32;
const PENDING_SIGNAL_BACKSTOP_TTL_SECONDS = 60;

export async function queuePendingSignal(clientId: string, entry: PendingSignalEntry): Promise<void> {
  const key = pendingKey(clientId);
  const multi = cmd().multi();
  multi.rPush(key, JSON.stringify(entry));
  multi.lTrim(key, -MAX_PENDING_SIGNALS_PER_TARGET, -1);
  multi.expire(key, PENDING_SIGNAL_BACKSTOP_TTL_SECONDS);
  await multi.exec();
}

// Atomically reads and clears the queue (multi() guarantees no other
// client's commands interleave between the lRange and the del), so a
// signal can never be delivered twice even if flushPendingSignals is
// somehow triggered concurrently.
export async function flushPendingSignals(clientId: string): Promise<PendingSignalEntry[]> {
  const key = pendingKey(clientId);
  const multi = cmd().multi();
  multi.lRange(key, 0, -1);
  multi.del(key);
  const [raw] = (await multi.exec()) as [string[], number];
  return raw.map((entry) => JSON.parse(entry) as PendingSignalEntry);
}
