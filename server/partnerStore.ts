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
