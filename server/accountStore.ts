import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import bcrypt from "bcryptjs";
import { MONGO_ENABLED, connectMongo } from "./mongo.js";
import { AccountModel, type AccountDoc } from "./accountModels.js";

export interface PublicAccount {
  id: string;
  username: string;
  displayName: string;
  flags: string[];
  createdAt: number;
  updatedAt: number;
}

// Full record, password hash and IP history included — never crosses into
// an HTTP response as-is; toPublicAccount() below is the only thing that's
// ever sent to a client.
interface FullAccount extends PublicAccount {
  passwordHash: string;
  ips: string[];
}

export const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const MAX_IPS_TRACKED = 20;
const BCRYPT_ROUNDS = 10;

// Same control-character guard as signaling.ts's isValidDisplayName (kept
// as its own copy here rather than imported, since signaling.ts is the one
// that imports this module — importing back would be circular).
export function isValidAccountDisplayName(name: string): boolean {
  if (name.length < 1 || name.length > 24) return false;
  for (let i = 0; i < name.length; i += 1) {
    const code = name.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

// Bootstraps the very first admin account from the same env vars the old
// Basic-Auth admin login used (see the former adminAuth.ts), so a
// deployment that already had ADMIN_USER/ADMIN_PASSWORD configured doesn't
// lose admin access just because this replaced that system.
const ADMIN_USER = process.env.ADMIN_USER || null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;

// Same opt-in shape as moderationStore.ts: JSON file on disk when
// MONGO_URL isn't set.
const DATA_DIR = path.join(process.cwd(), "server", "data");
const DATA_FILE = path.join(DATA_DIR, "accounts.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

let accountsById = new Map<string, FullAccount>();
let accountsByUsername = new Map<string, string>(); // folded username -> id
// A registered account's "nick" (see the register handler in signaling.ts)
// is whichever of username/displayName someone types — both need to
// resolve to the same owner, so this reservation map is keyed by either,
// distinct from accountsByUsername above (which is strictly for login).
let reservedNames = new Map<string, string>(); // folded name -> id

function fold(name: string): string {
  return name.toLowerCase();
}

function loadFromDisk(): FullAccount[] {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as FullAccount[]) : [];
  } catch {
    return [];
  }
}

function saveToDisk() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify([...accountsById.values()]));
  } catch {
    // Best-effort — accounts still work in-memory for the life of the
    // process even if the disk write fails.
  }
}

function docToFullAccount(doc: AccountDoc): FullAccount {
  return {
    id: doc.id,
    username: doc.username,
    displayName: doc.displayName,
    flags: doc.flags,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
    passwordHash: doc.account.passwordHash,
    ips: doc.account.ips,
  };
}

async function loadFromMongo(): Promise<FullAccount[]> {
  await connectMongo();
  const docs = await AccountModel.find().select("+account").lean();
  return docs.map((doc) => docToFullAccount(doc as unknown as AccountDoc));
}

async function persistNewAccount(account: FullAccount): Promise<void> {
  if (MONGO_ENABLED) {
    await connectMongo();
    await AccountModel.create({
      id: account.id,
      username: account.username,
      displayName: account.displayName,
      flags: account.flags,
      account: { passwordHash: account.passwordHash, ips: account.ips },
      createdAt: account.createdAt,
      updatedAt: account.updatedAt,
    });
  } else {
    saveToDisk();
  }
}

async function persistAccountUpdate(account: FullAccount): Promise<void> {
  if (MONGO_ENABLED) {
    await connectMongo();
    await AccountModel.findOneAndUpdate(
      { id: account.id },
      { flags: account.flags, "account.ips": account.ips, updatedAt: account.updatedAt }
    );
  } else {
    saveToDisk();
  }
}

function indexAccount(account: FullAccount) {
  accountsById.set(account.id, account);
  accountsByUsername.set(fold(account.username), account.id);
  reservedNames.set(fold(account.username), account.id);
  reservedNames.set(fold(account.displayName), account.id);
}

export function toPublicAccount(account: FullAccount): PublicAccount {
  return {
    id: account.id,
    username: account.username,
    displayName: account.displayName,
    flags: account.flags,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

// Loads every account into the in-memory cache. Called once at startup
// (see server/index.ts), same as initModerationStore — the register/login
// hot paths below can't afford to await storage on every call.
export async function initAccountStore(): Promise<void> {
  const accounts = MONGO_ENABLED ? await loadFromMongo().catch(() => loadFromDisk()) : loadFromDisk();
  accountsById = new Map();
  accountsByUsername = new Map();
  reservedNames = new Map();
  for (const account of accounts) indexAccount(account);

  // Only ever creates the account if that username isn't already taken —
  // never retroactively grants the ADMIN flag to one someone else claimed
  // first, so a name matching this env var can't become an admin account
  // just by someone signing up before it's configured.
  if (ADMIN_USER && ADMIN_PASSWORD && !reservedNames.has(fold(ADMIN_USER))) {
    try {
      await createAccount(ADMIN_USER, ADMIN_USER, ADMIN_PASSWORD, "127.0.0.1", ["ADMIN"]);
    } catch (err) {
      console.error(
        "[accountStore] Falha ao criar conta admin inicial:",
        err instanceof Error ? err.message : err
      );
    }
  }
}

// Returns the id of the account that owns `foldedName` (as a username or a
// display name), or undefined if it isn't reserved by anyone.
export function isNameReserved(foldedName: string): string | undefined {
  return reservedNames.get(foldedName);
}

export function getPublicAccountById(id: string): PublicAccount | null {
  const account = accountsById.get(id);
  return account ? toPublicAccount(account) : null;
}

export async function createAccount(
  username: string,
  displayName: string,
  password: string,
  ip: string,
  flags: string[] = []
): Promise<PublicAccount> {
  if (!USERNAME_RE.test(username)) {
    throw new Error("Usuário inválido — use 3 a 20 letras, números ou _.");
  }
  if (!isValidAccountDisplayName(displayName)) {
    throw new Error("Nome de exibição inválido.");
  }
  const usernameKey = fold(username);
  const displayNameKey = fold(displayName);
  if (reservedNames.has(usernameKey) || reservedNames.has(displayNameKey)) {
    throw new Error("Usuário ou nome de exibição já em uso.");
  }
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const now = Date.now();
  const account: FullAccount = {
    id: randomUUID(),
    username,
    displayName,
    flags,
    createdAt: now,
    updatedAt: now,
    passwordHash,
    ips: [ip],
  };
  indexAccount(account);
  await persistNewAccount(account);
  return toPublicAccount(account);
}

export async function verifyAccountLogin(
  username: string,
  password: string,
  ip: string
): Promise<PublicAccount | null> {
  const id = accountsByUsername.get(fold(username));
  const account = id ? accountsById.get(id) : undefined;
  if (!account) return null;
  const valid = await bcrypt.compare(password, account.passwordHash);
  if (!valid) return null;
  if (!account.ips.includes(ip)) {
    account.ips = [...account.ips, ip].slice(-MAX_IPS_TRACKED);
    account.updatedAt = Date.now();
    await persistAccountUpdate(account).catch(() => {
      // Best-effort — login already succeeded; losing this IP-history
      // write shouldn't fail the login itself.
    });
  }
  return toPublicAccount(account);
}
