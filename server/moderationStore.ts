import fs from "node:fs";
import path from "node:path";
import { MONGO_ENABLED, connectMongo } from "./mongo.js";
import { IpBanModel, ModerationConfigModel, type IpBan } from "./moderationModels.js";

export type { IpBan };

const MAX_REASON_LEN = 200;
const MAX_BANNED_WORDS = 500;
const MAX_WORD_LEN = 100;

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
// Loose on purpose: IPv6 has enough valid shapes (::1, ::ffff:1.2.3.4,
// compressed forms) that fully validating it here isn't worth it — this
// only needs to reject obviously-wrong input from the admin ban form, since
// a real connection's IP always comes from request.ip and is trusted as-is.
const IPV6_RE = /^[0-9a-fA-F:]+$/;

export function isValidIp(ip: string): boolean {
  if (ip.length === 0 || ip.length > 45) return false;
  if (IPV4_RE.test(ip)) return ip.split(".").every((part) => Number(part) <= 255);
  return ip.includes(":") && IPV6_RE.test(ip);
}

// Same opt-in shape as chatStore.ts: JSON file on disk when MONGO_URL isn't
// set, so moderation config still persists across restarts without
// requiring Mongo for a small/single-instance deployment.
const DATA_DIR = path.join(process.cwd(), "server", "data");
const DATA_FILE = path.join(DATA_DIR, "moderation.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

interface ModerationDoc {
  bannedWords: string[];
  bans: IpBan[];
}

// Both bans and banned words are read on every single WebSocket connection
// and every chat message respectively, so they're kept fully in memory and
// mirrored to Mongo/disk on mutation — the hot path never awaits storage.
let bansCache = new Map<string, IpBan>();
let bannedWordsCache: string[] = [];
let compiledWordFilter: RegExp | null = null;

function loadFromDisk(): ModerationDoc {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      bannedWords: Array.isArray(parsed.bannedWords) ? parsed.bannedWords : [],
      bans: Array.isArray(parsed.bans) ? parsed.bans : [],
    };
  } catch {
    return { bannedWords: [], bans: [] };
  }
}

function saveToDisk() {
  try {
    const doc: ModerationDoc = { bannedWords: bannedWordsCache, bans: [...bansCache.values()] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(doc));
  } catch {
    // Best-effort — moderation config still works in-memory for the life of
    // the process even if the disk write fails.
  }
}

async function loadFromMongo(): Promise<ModerationDoc> {
  await connectMongo();
  // _id excluded: Mongo always adds its own to every document, which isn't
  // part of the IpBan shape the rest of this module (and the admin API
  // response) expects.
  const [config, bans] = await Promise.all([
    ModerationConfigModel.findById("config").lean(),
    IpBanModel.find().select("-_id").lean(),
  ]);
  return { bannedWords: config?.bannedWords ?? [], bans: bans as IpBan[] };
}

async function saveBannedWordsToMongo(words: string[]) {
  await connectMongo();
  await ModerationConfigModel.findByIdAndUpdate(
    "config",
    { bannedWords: words },
    { upsert: true }
  );
}

async function saveBanToMongo(ban: IpBan) {
  await connectMongo();
  await IpBanModel.findOneAndUpdate({ ip: ban.ip }, ban, { upsert: true });
}

async function deleteBanFromMongo(ip: string) {
  await connectMongo();
  await IpBanModel.deleteOne({ ip });
}

// Strips accents/diacritics and lowercases, so "não" and "nao" (or "É" and
// "e") match the same filter entry regardless of how either was typed.
function foldText(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compileWordFilter() {
  if (bannedWordsCache.length === 0) {
    compiledWordFilter = null;
    return;
  }
  const alternation = bannedWordsCache.map(escapeRegExp).join("|");
  compiledWordFilter = new RegExp(`\\b(?:${alternation})\\b`, "i");
}

// Loads bans and banned words into the in-memory cache. Called once at
// startup (see server/index.ts) before the server starts accepting
// connections, so the very first WS connection is already checked against
// whatever was persisted from a previous run.
export async function initModerationStore(): Promise<void> {
  const doc = MONGO_ENABLED ? await loadFromMongo().catch(() => loadFromDisk()) : loadFromDisk();
  bansCache = new Map(doc.bans.map((b) => [b.ip, b]));
  bannedWordsCache = doc.bannedWords;
  compileWordFilter();
}

// Sync, cache-only lookup — this runs on every WebSocket connection, so it
// can't afford to await storage. Lazily prunes an expired ban on read
// instead of running a separate sweep timer.
export function isIpBanned(ip: string): IpBan | null {
  const ban = bansCache.get(ip);
  if (!ban) return null;
  if (ban.expiresAt !== null && ban.expiresAt <= Date.now()) {
    bansCache.delete(ip);
    void (MONGO_ENABLED ? deleteBanFromMongo(ip) : Promise.resolve()).catch(() => {});
    if (!MONGO_ENABLED) saveToDisk();
    return null;
  }
  return ban;
}

export function listBans(): IpBan[] {
  return [...bansCache.values()].sort((a, b) => b.createdAt - a.createdAt);
}

export async function banIp(ip: string, reason: string, durationMinutes: number | null): Promise<IpBan> {
  const ban: IpBan = {
    ip,
    reason: reason.slice(0, MAX_REASON_LEN),
    createdAt: Date.now(),
    expiresAt: durationMinutes && durationMinutes > 0 ? Date.now() + durationMinutes * 60_000 : null,
  };
  bansCache.set(ip, ban);
  if (MONGO_ENABLED) await saveBanToMongo(ban);
  else saveToDisk();
  return ban;
}

export async function unbanIp(ip: string): Promise<boolean> {
  const existed = bansCache.delete(ip);
  if (!existed) return false;
  if (MONGO_ENABLED) await deleteBanFromMongo(ip);
  else saveToDisk();
  return true;
}

export function listBannedWords(): string[] {
  return [...bannedWordsCache];
}

// Replaces the whole list at once — simplest shape for an admin textarea of
// one word/phrase per line, and avoids the list drifting out of sync with
// what's shown in the UI the way incremental add/remove endpoints could.
export async function setBannedWords(words: string[]): Promise<string[]> {
  const normalized = [
    ...new Set(
      words
        .map((w) => foldText(w.trim()).slice(0, MAX_WORD_LEN))
        .filter((w) => w.length > 0)
    ),
  ].slice(0, MAX_BANNED_WORDS);
  bannedWordsCache = normalized;
  compileWordFilter();
  if (MONGO_ENABLED) await saveBannedWordsToMongo(normalized);
  else saveToDisk();
  return normalized;
}

// Returns the matched (folded) word for logging/feedback purposes, or null
// if the text is clean.
export function findBannedWord(text: string): string | null {
  if (!compiledWordFilter) return null;
  const match = compiledWordFilter.exec(foldText(text));
  return match ? match[0] : null;
}
