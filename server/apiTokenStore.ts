import fs from "node:fs";
import path from "node:path";
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { MONGO_ENABLED, connectMongo } from "./mongo.js";
import { ApiTokenModel, type ApiTokenDoc } from "./apiTokenModels.js";
import { getBearerToken } from "./auth.js";

export interface ApiToken {
  id: string;
  label: string;
  createdAt: number;
  createdBy: string;
  revokedAt: number | null;
  lastUsedAt: number | null;
}

export interface ApiTokenAuth {
  id: string;
  label: string;
}

// Same opt-in shape as every other store here: JSON file on disk when
// MONGO_URL isn't set.
const DATA_DIR = path.join(process.cwd(), "server", "data");
const DATA_FILE = path.join(DATA_DIR, "apiTokens.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

// Unlike moderationStore.ts/accountStore.ts, this deliberately keeps no
// in-memory cache: /createroom traffic is low-QPS (rate-limited per token,
// see rateLimiter.ts's createRoomLimiter), so every lookup can afford to hit
// storage directly. That also sidesteps a stale-cache-after-revocation bug a
// boot-time-loaded cache would otherwise need its own invalidation path for.
function loadFromDisk(): ApiTokenDoc[] {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ApiTokenDoc[]) : [];
  } catch {
    return [];
  }
}

function saveToDisk(tokens: ApiTokenDoc[]) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(tokens));
  } catch {
    // Best-effort, matches every other store here.
  }
}

function toPublic(doc: ApiTokenDoc): ApiToken {
  const { tokenHash: _tokenHash, ...rest } = doc;
  return rest;
}

function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

// A 32-byte random secret already carries 256 bits of entropy — there's no
// offline-guessing risk here the way there is for a human-chosen password,
// so a fast SHA-256 lookup is the right hash, not bcrypt: bcrypt's per-hash
// salt makes an indexed lookup by hash impossible without iterating every
// stored token, which doesn't scale past a handful of integrations.
function generateRawToken(): string {
  return `sst_${randomBytes(32).toString("base64url")}`;
}

export async function createApiToken(
  label: string,
  createdBy: string
): Promise<{ token: ApiToken; raw: string }> {
  const raw = generateRawToken();
  const doc: ApiTokenDoc = {
    id: randomUUID(),
    label,
    tokenHash: hashToken(raw),
    createdAt: Date.now(),
    createdBy,
    revokedAt: null,
    lastUsedAt: null,
  };
  if (MONGO_ENABLED) {
    await connectMongo();
    await ApiTokenModel.create(doc);
  } else {
    const tokens = loadFromDisk();
    tokens.push(doc);
    saveToDisk(tokens);
  }
  return { token: toPublic(doc), raw };
}

export async function listApiTokens(): Promise<ApiToken[]> {
  let docs: ApiTokenDoc[];
  if (MONGO_ENABLED) {
    await connectMongo();
    docs = (await ApiTokenModel.find().select("-_id").lean()) as ApiTokenDoc[];
  } else {
    docs = loadFromDisk();
  }
  return docs.map(toPublic).sort((a, b) => b.createdAt - a.createdAt);
}

export async function revokeApiToken(id: string): Promise<boolean> {
  const revokedAt = Date.now();
  if (MONGO_ENABLED) {
    await connectMongo();
    const res = await ApiTokenModel.updateOne({ id, revokedAt: null }, { revokedAt });
    return res.modifiedCount > 0;
  }
  const tokens = loadFromDisk();
  const doc = tokens.find((t) => t.id === id && t.revokedAt === null);
  if (!doc) return false;
  doc.revokedAt = revokedAt;
  saveToDisk(tokens);
  return true;
}

async function findActiveTokenByHash(raw: string): Promise<ApiToken | null> {
  const tokenHash = hashToken(raw);
  if (MONGO_ENABLED) {
    await connectMongo();
    const doc = await ApiTokenModel.findOne({ tokenHash }).select("-_id").lean();
    if (!doc || doc.revokedAt !== null) return null;
    return toPublic(doc as ApiTokenDoc);
  }
  const tokens = loadFromDisk();
  const doc = tokens.find((t) => t.tokenHash === tokenHash);
  if (!doc || doc.revokedAt !== null) return null;
  return toPublic(doc);
}

async function touchApiTokenUsage(id: string): Promise<void> {
  try {
    const lastUsedAt = Date.now();
    if (MONGO_ENABLED) {
      await connectMongo();
      await ApiTokenModel.updateOne({ id }, { lastUsedAt });
    } else {
      const tokens = loadFromDisk();
      const doc = tokens.find((t) => t.id === id);
      if (doc) {
        doc.lastUsedAt = lastUsedAt;
        saveToDisk(tokens);
      }
    }
  } catch {
    // Best-effort — a failed "last used" bump shouldn't fail the request.
  }
}

// Auth for POST/DELETE /createroom — a distinct, narrower credential from
// the admin JWT (see auth.ts's requireAdmin): a valid token can only touch
// /createroom, nothing else, and carries no flags.
export async function requireApiToken(request: {
  headers: { authorization?: string };
}): Promise<ApiTokenAuth | null> {
  const raw = getBearerToken(request.headers.authorization);
  if (!raw) return null;
  const token = await findActiveTokenByHash(raw);
  if (!token) return null;
  void touchApiTokenUsage(token.id);
  return { id: token.id, label: token.label };
}
