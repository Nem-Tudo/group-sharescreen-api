import fs from "node:fs";
import path from "node:path";
import { createClient } from "redis";

export type AnnouncementButtonAction = "open-new-tab" | "open-same-tab" | "reload";
export type AnnouncementColor = "green" | "red" | "blue";
// "online-only" is only ever pushed live to whoever's connected right when
// it's sent/edited; "all" also reaches every connection opened later, for as
// long as it stays active (see signaling.ts's "/ws" handler).
export type AnnouncementVisibility = "online-only" | "all";
// Client-side sound policy — see components/AnnouncementBanner.tsx.
export type AnnouncementSound = "always" | "live-only" | "off";

export interface Announcement {
  id: string;
  // Bumped on every edit (see signaling.ts's PUT /admin/announcement) —
  // never on a fresh POST, which always starts a new id at version 1.
  version: number;
  text: string;
  hasButton: boolean;
  buttonLabel: string;
  buttonAction: AnnouncementButtonAction;
  buttonUrl: string | null;
  color: AnnouncementColor;
  dismissible: boolean;
  visibility: AnnouncementVisibility;
  sound: AnnouncementSound;
  // When true, the client only ever hides this on an explicit "x" click or
  // when the admin removes it — see components/AnnouncementBanner.tsx (and
  // its localStorage fallback) for what this actually changes client-side.
  // The server itself treats it as an opaque passthrough field.
  persistent: boolean;
}

// Redis is opt-in: only used when REDIS_URL is set. With no Redis around,
// this falls back to a single JSON file under server/data, scoped to this
// one process — same fallback shape as chatStore.ts, and for the same
// reason: it's what makes Redis worth adding in the first place (surviving
// a redeploy/restart without losing the active topwarn, and — unlike the
// file — shared across multiple signaling instances).
const REDIS_URL = process.env.REDIS_URL;

const ANNOUNCEMENT_DATA_DIR = path.join(process.cwd(), "server", "data");
const ANNOUNCEMENT_FILE_PATH = path.join(ANNOUNCEMENT_DATA_DIR, "announcement.json");
try {
  fs.mkdirSync(ANNOUNCEMENT_DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

function loadFromDisk(): Announcement | null {
  try {
    const raw = fs.readFileSync(ANNOUNCEMENT_FILE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Announcement) : null;
  } catch {
    return null;
  }
}

function saveToDisk(announcement: Announcement) {
  try {
    fs.writeFileSync(ANNOUNCEMENT_FILE_PATH, JSON.stringify(announcement));
  } catch {
    // Best-effort — the announcement still works in-memory for the life of
    // the process even if the disk write fails.
  }
}

function deleteFromDisk() {
  try {
    fs.unlinkSync(ANNOUNCEMENT_FILE_PATH);
  } catch {
    // Already gone (or nothing we can do about it) — fine either way.
  }
}

// See chatStore.ts's identical `RedisClient` alias for why this is `any`
// rather than a precise type.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let redisReady: Promise<RedisClient> | null = null;

// Lazily connects on first use and memoizes the in-flight/connected client.
// A failed connect resets the memo so the next call retries instead of
// replaying the same rejection forever.
async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[announcementStore] Erro na conexão com o Redis:", err.message);
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

const REDIS_KEY = "sharescreen:announcement";

export async function loadPersistedAnnouncement(): Promise<Announcement | null> {
  if (!REDIS_URL) return loadFromDisk();
  try {
    const client = await getRedis();
    const raw: string | null = await client.get(REDIS_KEY);
    return raw ? (JSON.parse(raw) as Announcement) : null;
  } catch (err) {
    console.error("[announcementStore] Erro ao carregar aviso do Redis:", (err as Error).message);
    return null;
  }
}

export async function savePersistedAnnouncement(announcement: Announcement): Promise<void> {
  if (!REDIS_URL) return saveToDisk(announcement);
  try {
    const client = await getRedis();
    await client.set(REDIS_KEY, JSON.stringify(announcement));
  } catch (err) {
    console.error("[announcementStore] Erro ao salvar aviso no Redis:", (err as Error).message);
  }
}

export async function deletePersistedAnnouncement(): Promise<void> {
  if (!REDIS_URL) return deleteFromDisk();
  try {
    const client = await getRedis();
    await client.del(REDIS_KEY);
  } catch (err) {
    console.error("[announcementStore] Erro ao apagar aviso do Redis:", (err as Error).message);
  }
}
