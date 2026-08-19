import fs from "node:fs";
import path from "node:path";
import { createClient } from "redis";

export interface ChatMessage {
  id: string;
  from: string;
  name: string;
  kind?: "text" | "gif";
  text: string;
  url?: string;
  ts: number;
}

// Redis is opt-in: only used when REDIS_URL is set. With no Redis around,
// this falls back to exactly the original behavior — one JSON file per room
// under server/data/rooms, scoped to this single process. That file-based
// fallback is what makes Redis worth adding in the first place: it can't be
// shared across multiple signaling instances, while Redis can.
const REDIS_URL = process.env.REDIS_URL;

const CHAT_DATA_DIR = path.join(process.cwd(), "server", "data", "rooms");
try {
  fs.mkdirSync(CHAT_DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

// `room` is always pre-validated against HANDLE_RE (alphanumeric/-/_ only)
// by every caller before it reaches these, so it's safe to use directly as
// a filename with no path-traversal risk.
function chatFilePath(room: string): string {
  return path.join(CHAT_DATA_DIR, `${room}.json`);
}

function loadFromDisk(room: string): ChatMessage[] {
  try {
    const raw = fs.readFileSync(chatFilePath(room), "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ChatMessage[]) : [];
  } catch {
    return [];
  }
}

function saveToDisk(room: string, messages: ChatMessage[]) {
  try {
    fs.writeFileSync(chatFilePath(room), JSON.stringify(messages));
  } catch {
    // Best-effort — chat still works in-memory for the life of the room
    // even if the disk write fails.
  }
}

function deleteFromDisk(room: string) {
  try {
    fs.unlinkSync(chatFilePath(room));
  } catch {
    // Already gone (or nothing we can do about it) — fine either way.
  }
}

// `any` here isn't a shortcut — @redis/client's generic RedisClientType
// fails to structurally match itself across separate `ReturnType<typeof
// createClient>` computations (a known typings quirk around scanIterator's
// `this` parameter), so a precise alias is more trouble than it's worth for
// the handful of plain commands (lRange/multi/del/rPush/exec) used below.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let redisReady: Promise<RedisClient> | null = null;

// Lazily connects on first use and memoizes the in-flight/connected client.
// A failed connect resets the memo so the next call retries instead of
// replaying the same rejection forever.
async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[chatStore] Erro na conexão com o Redis:", err.message);
  });
  const connecting = client.connect().then(() => client);
  redisReady = connecting;
  try {
    return await connecting;
  } catch (err) {
    redisReady = null;
    throw err;
  }
}

function redisKey(room: string): string {
  return `sharescreen:chat:${room}`;
}

export async function loadPersistedChat(room: string): Promise<ChatMessage[]> {
  if (!REDIS_URL) return loadFromDisk(room);
  try {
    const client = await getRedis();
    const raw: string[] = await client.lRange(redisKey(room), 0, -1);
    return raw.map((entry: string) => JSON.parse(entry) as ChatMessage);
  } catch (err) {
    console.error("[chatStore] Erro ao carregar histórico do Redis:", (err as Error).message);
    return [];
  }
}

// Overwrites the room's whole stored history with `messages` every call —
// same semantics as the disk backend (which always rewrites the full file).
// Simple and safe to reason about; history is capped at
// ROOM_CHAT_HISTORY_LIMIT (server/signaling.ts) so this stays cheap even at
// the cap.
export async function savePersistedChat(room: string, messages: ChatMessage[]): Promise<void> {
  if (!REDIS_URL) return saveToDisk(room, messages);
  try {
    const client = await getRedis();
    const key = redisKey(room);
    const multi = client.multi().del(key);
    if (messages.length > 0) {
      multi.rPush(
        key,
        messages.map((m) => JSON.stringify(m))
      );
    }
    await multi.exec();
  } catch (err) {
    console.error("[chatStore] Erro ao salvar histórico no Redis:", (err as Error).message);
  }
}

export async function deletePersistedChat(room: string): Promise<void> {
  if (!REDIS_URL) return deleteFromDisk(room);
  try {
    const client = await getRedis();
    await client.del(redisKey(room));
  } catch (err) {
    console.error("[chatStore] Erro ao apagar histórico do Redis:", (err as Error).message);
  }
}
