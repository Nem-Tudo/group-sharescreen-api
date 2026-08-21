import fs from "node:fs";
import path from "node:path";
import { createClient } from "redis";

export interface Partner {
  id: string;
  title: string;
  description: string;
  imageUrl: string | null;
  buttonLabel: string;
  buttonUrl: string;
  // null means "use the client's own default" for each — see
  // components/PartnerCard.tsx's `?? "#..."` fallbacks.
  backgroundColor: string | null;
  textColor: string | null;
  buttonBackgroundColor: string | null;
  buttonTextColor: string | null;
  // Relative share of impressions among currently *active* partners — see
  // signaling.ts's assignPartnersToConnections/pickWeightedPartner. 1 = an
  // equal share with every other partner, 2 = double, etc.
  weight: number;
  // epoch ms; null = never expires. A partner past this is excluded from
  // selection (see signaling.ts's activePartners) but stays in this list —
  // deliberately not auto-deleted, so the admin panel can still show/extend/
  // remove it after the fact instead of it just silently vanishing.
  expiresAt: number | null;
  createdAt: number;
}

export interface PartnerConfig {
  partners: Partner[];
  // 0-100: percentage of HTTP GET /partner requests that get an empty
  // response even while partners are active, so a visitor who'd otherwise
  // never see a paid slot still sees the "anuncie aqui" pitch sometimes —
  // see signaling.ts's GET /partner. Doesn't apply to the live socket push
  // (see broadcastPartnerUpdate), only to that per-request HTTP roll.
  emptyPercent: number;
}

const DEFAULT_CONFIG: PartnerConfig = { partners: [], emptyPercent: 0 };

// Redis is opt-in: only used when REDIS_URL is set. With no Redis around,
// this falls back to a single JSON file under server/data, scoped to this
// one process — same fallback shape as announcementStore.ts/chatStore.ts.
const REDIS_URL = process.env.REDIS_URL;

const PARTNER_DATA_DIR = path.join(process.cwd(), "server", "data");
const PARTNER_FILE_PATH = path.join(PARTNER_DATA_DIR, "partners.json");
try {
  fs.mkdirSync(PARTNER_DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

function normalizeConfig(parsed: unknown): PartnerConfig {
  if (!parsed || typeof parsed !== "object") return { ...DEFAULT_CONFIG, partners: [] };
  const obj = parsed as Record<string, unknown>;
  return {
    partners: Array.isArray(obj.partners) ? (obj.partners as Partner[]) : [],
    emptyPercent: typeof obj.emptyPercent === "number" ? obj.emptyPercent : 0,
  };
}

function loadFromDisk(): PartnerConfig {
  try {
    const raw = fs.readFileSync(PARTNER_FILE_PATH, "utf8");
    return normalizeConfig(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_CONFIG, partners: [] };
  }
}

function saveToDisk(config: PartnerConfig) {
  try {
    fs.writeFileSync(PARTNER_FILE_PATH, JSON.stringify(config));
  } catch {
    // Best-effort — partners still work in-memory for the life of the
    // process even if the disk write fails.
  }
}

// See chatStore.ts's identical `RedisClient` alias for why this is `any`
// rather than a precise type.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let redisReady: Promise<RedisClient> | null = null;

async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[partnerStore] Erro na conexão com o Redis:", err.message);
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

const REDIS_KEY = "sharescreen:partners";

export async function loadPersistedPartnerConfig(): Promise<PartnerConfig> {
  if (!REDIS_URL) return loadFromDisk();
  try {
    const client = await getRedis();
    const raw: string | null = await client.get(REDIS_KEY);
    return raw ? normalizeConfig(JSON.parse(raw)) : { ...DEFAULT_CONFIG, partners: [] };
  } catch (err) {
    console.error("[partnerStore] Erro ao carregar anúncios do Redis:", (err as Error).message);
    return { ...DEFAULT_CONFIG, partners: [] };
  }
}

export async function savePersistedPartnerConfig(config: PartnerConfig): Promise<void> {
  if (!REDIS_URL) return saveToDisk(config);
  try {
    const client = await getRedis();
    await client.set(REDIS_KEY, JSON.stringify(config));
  } catch (err) {
    console.error("[partnerStore] Erro ao salvar anúncios no Redis:", (err as Error).message);
  }
}

// Accumulated engagement counters for one partner ad. Deliberately plain
// totals rather than the id-set signaling.ts dedupes sessions with in memory:
// that set is keyed by *connection* id, and connections never outlive a
// restart, so there'd be nothing for a persisted set to dedupe against —
// only the running process can dedupe its own connections, and what has to
// survive the restart is the number it already arrived at.
//
// Three numbers rather than one because the slot rotates now (see
// PartnerCard's five-minute refill), and rotation makes "a view" ambiguous.
// None of the three can be derived from the others:
//   - views: every serve. The same person, in the same tab, counts again
//     each time the slot refills onto this ad.
//   - sessionViews: one per (connection x ad). This is what "views" alone
//     used to mean, back when a slot was filled once per page load.
//   - unique viewers: distinct people, which is a *cardinality*, not a
//     counter — see recordPersistedPartnerViewer below, which keeps the set
//     rather than a running total precisely because a total cannot be
//     deduplicated after the fact.
export interface PartnerStats {
  views: number;
  sessionViews: number;
  clicks: number;
}

const PARTNER_STATS_FILE_PATH = path.join(PARTNER_DATA_DIR, "partner-stats.json");

// Mirror of the stats file, so the no-Redis fallback can apply an increment
// without re-reading the file every time. Null until the first load.
let diskStats: Record<string, PartnerStats> | null = null;

function normalizeStats(parsed: unknown): Record<string, PartnerStats> {
  const out: Record<string, PartnerStats> = {};
  if (!parsed || typeof parsed !== "object") return out;
  for (const [id, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!value || typeof value !== "object") continue;
    const entry = value as Record<string, unknown>;
    out[id] = {
      views: typeof entry.views === "number" ? entry.views : 0,
      // Absent in anything written before sessions were split out of views.
      // Zero is the honest answer there: the old file genuinely holds no
      // separate session count, and back-filling it from "views" would be
      // inventing history — those two numbers only ever coincided for an ad
      // that never rotated.
      sessionViews: typeof entry.sessionViews === "number" ? entry.sessionViews : 0,
      clicks: typeof entry.clicks === "number" ? entry.clicks : 0,
    };
  }
  return out;
}

function loadStatsFromDisk(): Record<string, PartnerStats> {
  if (diskStats) return diskStats;
  try {
    diskStats = normalizeStats(JSON.parse(fs.readFileSync(PARTNER_STATS_FILE_PATH, "utf8")));
  } catch {
    diskStats = {};
  }
  return diskStats;
}

function saveStatsToDisk() {
  try {
    fs.writeFileSync(PARTNER_STATS_FILE_PATH, JSON.stringify(diskStats ?? {}));
  } catch {
    // Best-effort, same as saveToDisk above — the counters still work
    // in-memory for the life of the process.
  }
}

// Separate key from REDIS_KEY (the ad config) on purpose: these change on
// every single view/click, and a hash lets each one be a HINCRBY on one
// field instead of rewriting the whole config blob. HINCRBY is also atomic,
// so several signaling instances sharing this Redis accumulate into the
// same totals instead of clobbering each other's snapshot.
const REDIS_STATS_KEY = "sharescreen:partner-stats";

function statsField(id: string, metric: keyof PartnerStats): string {
  return `${id}:${metric}`;
}

export async function loadPersistedPartnerStats(): Promise<Record<string, PartnerStats>> {
  if (!REDIS_URL) return { ...loadStatsFromDisk() };
  try {
    const client = await getRedis();
    const raw: Record<string, string> = (await client.hGetAll(REDIS_STATS_KEY)) ?? {};
    const out: Record<string, PartnerStats> = {};
    for (const [field, value] of Object.entries(raw)) {
      // Field names are `<partnerId>:views` / `<partnerId>:clicks`, and ids
      // (genId — a UUID) never contain ":", so the last one splits them.
      const sep = field.lastIndexOf(":");
      if (sep < 0) continue;
      const id = field.slice(0, sep);
      const metric = field.slice(sep + 1);
      if (metric !== "views" && metric !== "sessionViews" && metric !== "clicks") continue;
      const entry = out[id] ?? (out[id] = { views: 0, sessionViews: 0, clicks: 0 });
      entry[metric] = Number(value) || 0;
    }
    return out;
  } catch (err) {
    console.error("[partnerStore] Erro ao carregar estatísticas do Redis:", (err as Error).message);
    return {};
  }
}

// Adds to whatever's already stored, rather than writing an absolute value:
// the caller's in-memory number only covers this process's lifetime, so
// setting it would wipe out everything counted before the last restart (and
// anything another instance counted in the meantime).
export async function incrementPersistedPartnerStats(
  id: string,
  delta: Partial<PartnerStats>
): Promise<void> {
  const views = delta.views ?? 0;
  const sessionViews = delta.sessionViews ?? 0;
  const clicks = delta.clicks ?? 0;
  if (views === 0 && sessionViews === 0 && clicks === 0) return;
  if (!REDIS_URL) {
    const stats = loadStatsFromDisk();
    const entry = stats[id] ?? (stats[id] = { views: 0, sessionViews: 0, clicks: 0 });
    entry.views += views;
    entry.sessionViews += sessionViews;
    entry.clicks += clicks;
    saveStatsToDisk();
    return;
  }
  try {
    const client = await getRedis();
    const multi = client.multi();
    if (views !== 0) multi.hIncrBy(REDIS_STATS_KEY, statsField(id, "views"), views);
    if (sessionViews !== 0) {
      multi.hIncrBy(REDIS_STATS_KEY, statsField(id, "sessionViews"), sessionViews);
    }
    if (clicks !== 0) multi.hIncrBy(REDIS_STATS_KEY, statsField(id, "clicks"), clicks);
    await multi.exec();
  } catch (err) {
    console.error("[partnerStore] Erro ao salvar estatísticas no Redis:", (err as Error).message);
  }
}

// ---------------------------------------------------------------------------
// Unique viewers
// ---------------------------------------------------------------------------

// Counting distinct people is not a counter, it is a set, and the difference
// is not academic: an increment cannot be un-double-counted afterwards, so
// there is no way to build this number except by remembering who has already
// been seen. That memory has to live in the persisted store rather than in
// the process — a per-process set would restart empty and count every
// returning visitor again on every deploy, which is exactly the failure the
// word "unique" promises not to have.
//
// Redis does the deduplication itself (SADD is a no-op for a member already
// in the set), so nothing is loaded into this process: the sets stay in
// Redis, one per ad, and only their cardinality is ever read back.
const REDIS_UNIQUES_KEY_PREFIX = "sharescreen:partner-uniques:";

function uniquesKey(id: string): string {
  return REDIS_UNIQUES_KEY_PREFIX + id;
}

const PARTNER_UNIQUES_FILE_PATH = path.join(PARTNER_DATA_DIR, "partner-uniques.json");

// Mirror of the uniques file for the no-Redis fallback, same shape and same
// reasoning as diskStats above. Null until the first load.
let diskUniques: Record<string, Set<string>> | null = null;

function loadUniquesFromDisk(): Record<string, Set<string>> {
  if (diskUniques) return diskUniques;
  const out: Record<string, Set<string>> = {};
  try {
    const parsed = JSON.parse(fs.readFileSync(PARTNER_UNIQUES_FILE_PATH, "utf8")) as unknown;
    if (parsed && typeof parsed === "object") {
      for (const [id, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (Array.isArray(value)) out[id] = new Set(value.filter((v) => typeof v === "string"));
      }
    }
  } catch {
    // No file yet, or unreadable — start empty, same as the stats fallback.
  }
  diskUniques = out;
  return diskUniques;
}

function saveUniquesToDisk() {
  try {
    const plain: Record<string, string[]> = {};
    for (const [id, set] of Object.entries(diskUniques ?? {})) plain[id] = [...set];
    fs.writeFileSync(PARTNER_UNIQUES_FILE_PATH, JSON.stringify(plain));
  } catch {
    // Best-effort, same as the other writers here.
  }
}

/**
 * Remembers that this viewer has seen this ad. Idempotent by construction.
 *
 * The viewer key is whatever the caller considers one person — see
 * signaling.ts's partnerViewerKey, which uses the account id when there is
 * one and the IP otherwise, and documents what that does and does not
 * capture.
 *
 * Note that the no-Redis fallback keeps every key on disk and in memory, so
 * it grows with the audience. That is acceptable for the single-process,
 * no-Redis setup it exists for (development, a small self-host); a
 * deployment large enough for it to matter is a deployment with Redis, where
 * the set never enters this process at all.
 */
export async function recordPersistedPartnerViewer(id: string, viewerKey: string): Promise<void> {
  if (!id || !viewerKey) return;
  if (!REDIS_URL) {
    const uniques = loadUniquesFromDisk();
    const set = uniques[id] ?? (uniques[id] = new Set());
    if (set.has(viewerKey)) return;
    set.add(viewerKey);
    saveUniquesToDisk();
    return;
  }
  try {
    const client = await getRedis();
    await client.sAdd(uniquesKey(id), viewerKey);
  } catch (err) {
    console.error(
      "[partnerStore] Erro ao registrar espectador único no Redis:",
      (err as Error).message
    );
  }
}

/** How many distinct viewers each of these ads has had. Unknown ids read 0. */
export async function loadPersistedPartnerUniqueCounts(
  ids: string[]
): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const id of ids) out[id] = 0;
  if (ids.length === 0) return out;
  if (!REDIS_URL) {
    const uniques = loadUniquesFromDisk();
    for (const id of ids) out[id] = uniques[id]?.size ?? 0;
    return out;
  }
  try {
    const client = await getRedis();
    // One pipeline rather than a round trip per ad: the admin panel asks for
    // every ad at once, and it is the only caller.
    const multi = client.multi();
    for (const id of ids) multi.sCard(uniquesKey(id));
    const results: unknown[] = (await multi.exec()) ?? [];
    ids.forEach((id, i) => {
      out[id] = Number(results[i]) || 0;
    });
    return out;
  } catch (err) {
    console.error(
      "[partnerStore] Erro ao contar espectadores únicos no Redis:",
      (err as Error).message
    );
    return out;
  }
}

// Only called when the ad itself is deleted (see signaling.ts's DELETE
// /admin/partners/:id) — an expired ad keeps its numbers, same as it keeps
// its config entry (see Partner.expiresAt).
export async function deletePersistedPartnerStats(id: string): Promise<void> {
  if (!REDIS_URL) {
    const stats = loadStatsFromDisk();
    delete stats[id];
    saveStatsToDisk();
    const uniques = loadUniquesFromDisk();
    if (uniques[id]) {
      delete uniques[id];
      saveUniquesToDisk();
    }
    return;
  }
  try {
    const client = await getRedis();
    await client.hDel(REDIS_STATS_KEY, [
      statsField(id, "views"),
      statsField(id, "sessionViews"),
      statsField(id, "clicks"),
    ]);
    // The viewer set goes with the ad. Left behind it would be the largest
    // thing this store keeps, held for an id nothing can ever display again.
    await client.del(uniquesKey(id));
  } catch (err) {
    console.error("[partnerStore] Erro ao apagar estatísticas do Redis:", (err as Error).message);
  }
}
