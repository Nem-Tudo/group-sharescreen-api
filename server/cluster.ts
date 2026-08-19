import { createClient } from "redis";

// Cross-instance coordination for signaling.ts, opt-in via REDIS_URL — same
// pattern as chatStore.ts. With no Redis configured, every export here is a
// no-op / empty result, so a single-instance deployment behaves exactly as
// it did before this module existed.
const REDIS_URL = process.env.REDIS_URL;
export const CLUSTER_ENABLED = Boolean(REDIS_URL);

const ROOMS_ACTIVE_KEY = "sharescreen:rooms:active";

function roomPeersKey(room: string): string {
  return `sharescreen:room:${room}:peers`;
}

function roomChannel(room: string): string {
  return `sharescreen:room:${room}`;
}

function pendingKey(targetId: string): string {
  return `sharescreen:pending:${targetId}`;
}

// See chatStore.ts's identical RedisClient comment — @redis/client's
// generic type doesn't structurally match itself across separate
// ReturnType<typeof createClient> computations, so a precise alias costs
// more than it's worth for the handful of plain commands used here.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let commandReady: Promise<RedisClient> | null = null;

// Plain command connection (GET/SET/HSET/PUBLISH/...). Kept separate from
// the subscriber connection below because Redis puts a connection that has
// ever issued SUBSCRIBE into a restricted pub/sub-only mode.
async function getCommandClient(): Promise<RedisClient> {
  if (commandReady) return commandReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[cluster] Erro na conexão com o Redis:", err.message);
  });
  const connecting = client.connect().then(() => client);
  commandReady = connecting;
  try {
    return await connecting;
  } catch (err) {
    commandReady = null;
    throw err;
  }
}

let subReady: Promise<RedisClient> | null = null;

async function getSubClient(): Promise<RedisClient> {
  if (subReady) return subReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[cluster] Erro na conexão de assinatura com o Redis:", err.message);
  });
  const connecting = client.connect().then(() => client);
  subReady = connecting;
  try {
    return await connecting;
  } catch (err) {
    subReady = null;
    throw err;
  }
}

export type ClusterEventType =
  | "peer-joined"
  | "peer-left"
  | "peer-sharing"
  | "peer-mic"
  | "peer-renamed"
  | "chat-message"
  | "signal";

export interface ClusterEvent {
  instanceId: string;
  type: ClusterEventType;
  payload: unknown;
}

// One listener per room this instance currently has local sockets in —
// registered against the shared subscriber connection's per-channel
// dispatch, so a single Redis connection serves every locally-open room.
const roomHandlers = new Map<string, (event: ClusterEvent) => void>();

export async function subscribeRoom(room: string, onEvent: (event: ClusterEvent) => void): Promise<void> {
  if (!CLUSTER_ENABLED || roomHandlers.has(room)) return;
  roomHandlers.set(room, onEvent);
  try {
    const client = await getSubClient();
    await client.subscribe(roomChannel(room), (message: string) => {
      let event: ClusterEvent;
      try {
        event = JSON.parse(message);
      } catch {
        return;
      }
      roomHandlers.get(room)?.(event);
    });
  } catch (err) {
    roomHandlers.delete(room);
    console.error("[cluster] Erro ao assinar sala:", (err as Error).message);
  }
}

export async function unsubscribeRoom(room: string): Promise<void> {
  if (!CLUSTER_ENABLED || !roomHandlers.has(room)) return;
  roomHandlers.delete(room);
  try {
    const client = await getSubClient();
    await client.unsubscribe(roomChannel(room));
  } catch (err) {
    console.error("[cluster] Erro ao cancelar assinatura da sala:", (err as Error).message);
  }
}

// `instanceId` rides inside the envelope (not just implicit) so a receiving
// instance can tell its own publishes apart from a peer's — it already
// handled its own event locally at publish time via the normal in-process
// broadcast path, so it must ignore its own echo here to avoid double
// delivery to its local sockets.
export async function publishRoomEvent(
  room: string,
  instanceId: string,
  type: ClusterEventType,
  payload: unknown
): Promise<void> {
  if (!CLUSTER_ENABLED) return;
  try {
    const client = await getCommandClient();
    await client.publish(roomChannel(room), JSON.stringify({ instanceId, type, payload } satisfies ClusterEvent));
  } catch (err) {
    console.error("[cluster] Erro ao publicar evento:", (err as Error).message);
  }
}

export interface RemotePeer {
  id: string;
  name: string | null;
  sharing: boolean;
  mic: boolean;
  role?: "moderator";
  instanceId: string;
  lastSeen: number;
}

export async function upsertPeer(room: string, peer: Omit<RemotePeer, "lastSeen">): Promise<void> {
  if (!CLUSTER_ENABLED) return;
  try {
    const client = await getCommandClient();
    const entry: RemotePeer = { ...peer, lastSeen: Date.now() };
    // hSetNX so an already-active room keeps its original createdAt instead
    // of it being bumped forward every time a peer (re)joins.
    await client
      .multi()
      .hSet(roomPeersKey(room), peer.id, JSON.stringify(entry))
      .hSetNX(ROOMS_ACTIVE_KEY, room, String(Date.now()))
      .exec();
  } catch (err) {
    console.error("[cluster] Erro ao gravar presença:", (err as Error).message);
  }
}

export async function removePeer(room: string, peerId: string): Promise<void> {
  if (!CLUSTER_ENABLED) return;
  try {
    const client = await getCommandClient();
    await client.hDel(roomPeersKey(room), peerId);
    // Drop the room from the active-rooms index as soon as it empties out,
    // rather than waiting up to STALE_PEER_AFTER_MS for the sweep to notice
    // — keeps /rooms, /admin/rooms and /stats accurate promptly.
    const remaining = await client.hLen(roomPeersKey(room));
    if (remaining === 0) await client.hDel(ROOMS_ACTIVE_KEY, room);
  } catch (err) {
    console.error("[cluster] Erro ao remover presença:", (err as Error).message);
  }
}

export async function listPeers(room: string): Promise<RemotePeer[]> {
  if (!CLUSTER_ENABLED) return [];
  try {
    const client = await getCommandClient();
    const raw = (await client.hGetAll(roomPeersKey(room))) as Record<string, string>;
    return Object.values(raw).map((entry) => JSON.parse(entry) as RemotePeer);
  } catch (err) {
    console.error("[cluster] Erro ao listar presença:", (err as Error).message);
    return [];
  }
}

export interface ActiveRoom {
  handle: string;
  createdAt: number;
}

export async function listActiveRooms(): Promise<ActiveRoom[]> {
  if (!CLUSTER_ENABLED) return [];
  try {
    const client = await getCommandClient();
    const raw = (await client.hGetAll(ROOMS_ACTIVE_KEY)) as Record<string, string>;
    return Object.entries(raw).map(([handle, createdAt]) => ({ handle, createdAt: Number(createdAt) }));
  } catch (err) {
    console.error("[cluster] Erro ao listar salas ativas:", (err as Error).message);
    return [];
  }
}

// Called once per heartbeat tick with the peers this instance currently
// owns locally: refreshes their lastSeen so sweepStalePeers below never
// reaps a peer that's still actually connected, somewhere.
export async function refreshPeers(entries: Array<{ room: string; peer: Omit<RemotePeer, "lastSeen"> }>): Promise<void> {
  if (!CLUSTER_ENABLED || entries.length === 0) return;
  try {
    const client = await getCommandClient();
    const multi = client.multi();
    for (const { room, peer } of entries) {
      const entry: RemotePeer = { ...peer, lastSeen: Date.now() };
      multi.hSet(roomPeersKey(room), peer.id, JSON.stringify(entry));
    }
    await multi.exec();
  } catch (err) {
    console.error("[cluster] Erro ao renovar presença:", (err as Error).message);
  }
}

// Safety net for an instance that vanished without a clean shutdown (OOM
// kill, crash) — the graceful-shutdown path already removes its own peers
// immediately on SIGTERM, so in the common rollout case this never finds
// anything to reap. Returns the rooms that ended up empty, so the caller
// can decide whether to also drop their persisted chat.
export async function sweepStalePeers(staleAfterMs: number): Promise<string[]> {
  if (!CLUSTER_ENABLED) return [];
  const emptiedRooms: string[] = [];
  try {
    const client = await getCommandClient();
    const activeRooms = (await client.hGetAll(ROOMS_ACTIVE_KEY)) as Record<string, string>;
    const now = Date.now();
    for (const room of Object.keys(activeRooms)) {
      const raw = (await client.hGetAll(roomPeersKey(room))) as Record<string, string>;
      const entries = Object.entries(raw);
      let remaining = entries.length;
      for (const [peerId, json] of entries) {
        let stale = true;
        try {
          const entry = JSON.parse(json) as RemotePeer;
          stale = now - entry.lastSeen > staleAfterMs;
        } catch {
          stale = true;
        }
        if (stale) {
          await client.hDel(roomPeersKey(room), peerId);
          remaining -= 1;
        }
      }
      if (remaining <= 0) {
        await client.hDel(ROOMS_ACTIVE_KEY, room);
        emptiedRooms.push(room);
      }
    }
  } catch (err) {
    console.error("[cluster] Erro na varredura de presença:", (err as Error).message);
  }
  return emptiedRooms;
}

export async function isRoomGloballyEmpty(room: string): Promise<boolean> {
  if (!CLUSTER_ENABLED) return true;
  try {
    const client = await getCommandClient();
    return (await client.hLen(roomPeersKey(room))) === 0;
  } catch (err) {
    console.error("[cluster] Erro ao checar sala vazia:", (err as Error).message);
    // Fails safe toward "don't delete" — losing chat history is worse than
    // an occasional orphaned file/Redis key left behind.
    return false;
  }
}

export interface PendingSignalEntry {
  from: string;
  data: unknown;
  queuedAt: number;
}

export async function pushPendingSignal(targetId: string, entry: PendingSignalEntry, ttlSeconds: number): Promise<void> {
  if (!CLUSTER_ENABLED) return;
  try {
    const client = await getCommandClient();
    const key = pendingKey(targetId);
    await client.multi().rPush(key, JSON.stringify(entry)).expire(key, ttlSeconds).exec();
  } catch (err) {
    console.error("[cluster] Erro ao enfileirar sinal pendente:", (err as Error).message);
  }
}

export async function popPendingSignals(targetId: string): Promise<PendingSignalEntry[]> {
  if (!CLUSTER_ENABLED) return [];
  try {
    const client = await getCommandClient();
    const key = pendingKey(targetId);
    const raw: string[] = await client.lRange(key, 0, -1);
    await client.del(key);
    return raw.map((entry) => JSON.parse(entry) as PendingSignalEntry);
  } catch (err) {
    console.error("[cluster] Erro ao ler sinais pendentes:", (err as Error).message);
    return [];
  }
}
