import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import bcrypt from "bcryptjs";
import { createClient } from "redis";
import { MONGO_ENABLED, connectMongo } from "./mongo.js";
import { AccountModel, type AccountDoc, type OAuthIdentityDoc } from "./accountModels.js";

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
  // Null for an account that only ever logged in through Discord/Google —
  // see createOAuthAccount and the guard in verifyAccountLogin.
  passwordHash: string | null;
  ips: string[];
  email: string | null;
  emailVerified: boolean;
  oauth: OAuthIdentityDoc[];
}

// One linked social identity, as the callers outside this module build it
// (linkedAt is stamped here, not by them).
export interface OAuthIdentityInput {
  provider: string;
  providerUserId: string;
  email: string | null;
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
// "<provider>:<providerUserId>" -> id. The provider's id is what a social
// login is resolved by (never the email, which the user can change on their
// side without it meaning anything here).
let accountsByOAuth = new Map<string, string>();
// folded email -> id, but only ever populated from an email a provider
// asserted *verified* — an unverified one must not be enough to find, and
// then claim, someone else's account (see findAccountByVerifiedEmail).
let accountsByVerifiedEmail = new Map<string, string>();
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
    passwordHash: doc.account.passwordHash ?? null,
    ips: doc.account.ips,
    email: doc.account.email ?? null,
    emailVerified: doc.account.emailVerified ?? false,
    // Accounts written before social login existed have no `oauth` field at
    // all — treated as "no identities linked", not as a broken document.
    oauth: doc.account.oauth ?? [],
  };
}

export function oauthIndexKey(provider: string, providerUserId: string): string {
  return `${provider}:${providerUserId}`;
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
      account: {
        passwordHash: account.passwordHash,
        ips: account.ips,
        email: account.email,
        emailVerified: account.emailVerified,
        oauth: account.oauth,
      },
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
  // Written here as much as by "flags" (currently the only field this
  // function ever changes besides ips) — anything this process itself
  // writes should never be masked by its own Redis cache for up to a
  // minute. invalidateCachedAccount is defined further down, after the
  // redis helpers, but hoisting makes this reference valid at call time.
  void invalidateCachedAccount(account.id);
}

// Sibling of persistAccountUpdate for the fields *it* deliberately doesn't
// touch: the linked identities and the email that came with them. Kept
// separate rather than widening that one, so the frequently-called
// flags/ips write can't accidentally clobber an identity list it wasn't
// given a current copy of.
async function persistAccountIdentity(account: FullAccount): Promise<void> {
  if (MONGO_ENABLED) {
    await connectMongo();
    await AccountModel.findOneAndUpdate(
      { id: account.id },
      {
        "account.oauth": account.oauth,
        "account.email": account.email,
        "account.emailVerified": account.emailVerified,
        updatedAt: account.updatedAt,
      }
    );
  } else {
    saveToDisk();
  }
  void invalidateCachedAccount(account.id);
}

function indexAccount(account: FullAccount) {
  accountsById.set(account.id, account);
  accountsByUsername.set(fold(account.username), account.id);
  reservedNames.set(fold(account.username), account.id);
  reservedNames.set(fold(account.displayName), account.id);
  for (const identity of account.oauth) {
    accountsByOAuth.set(oauthIndexKey(identity.provider, identity.providerUserId), account.id);
  }
  if (account.email && account.emailVerified) {
    accountsByVerifiedEmail.set(fold(account.email), account.id);
  }
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
  accountsByOAuth = new Map();
  accountsByVerifiedEmail = new Map();
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

// Redis is opt-in: only used when REDIS_URL is set (same shape as
// chatStore.ts/announcementStore.ts/partnerStore.ts). Sits in front of the
// MongoDB read below — a 60s TTL cache, not a source of truth, so any
// failure here just falls through to Mongo instead of blocking anything.
const REDIS_URL = process.env.REDIS_URL;
// `any` for the same reason as chatStore.ts's RedisClient alias — see its
// doc comment.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any
let redisReady: Promise<RedisClient> | null = null;

async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[accountStore] Erro na conexão com o Redis:", err.message);
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

function redisAccountKey(id: string): string {
  return `sharescreen:account:${id}`;
}

// 60s: refreshAccountFromMongo exists specifically so a flag change made
// directly in the database (no admin-panel write path for it yet) shows up
// without a server restart — this is the cap on how long that can now take
// to actually reach a client, in exchange for not hitting Mongo on every
// single WS "register" and /auth/me poll.
const ACCOUNT_CACHE_TTL_SECONDS = 60;

async function getCachedAccount(id: string): Promise<PublicAccount | null> {
  if (!REDIS_URL) return null;
  try {
    const client = await getRedis();
    const raw: string | null = await client.get(redisAccountKey(id));
    return raw ? (JSON.parse(raw) as PublicAccount) : null;
  } catch (err) {
    console.error("[accountStore] Erro ao ler cache de conta no Redis:", (err as Error).message);
    return null;
  }
}

async function setCachedAccount(account: PublicAccount): Promise<void> {
  if (!REDIS_URL) return;
  try {
    const client = await getRedis();
    await client.set(redisAccountKey(account.id), JSON.stringify(account), {
      EX: ACCOUNT_CACHE_TTL_SECONDS,
    });
  } catch (err) {
    console.error("[accountStore] Erro ao salvar cache de conta no Redis:", (err as Error).message);
  }
}

async function invalidateCachedAccount(id: string): Promise<void> {
  if (!REDIS_URL) return;
  try {
    const client = await getRedis();
    await client.del(redisAccountKey(id));
  } catch (err) {
    console.error("[accountStore] Erro ao invalidar cache de conta no Redis:", (err as Error).message);
  }
}

// Same as getPublicAccountById, but re-reads the account first instead of
// trusting whatever initAccountStore() cached at boot — accountsById is a
// startup snapshot, only ever updated afterward by this process's own
// writes (createAccount/persistAccountUpdate), so a flag (e.g. "VERIFIED")
// added directly in Mongo — by hand, or by a future admin tool — would
// otherwise stay invisible until the next restart. Used wherever flags
// genuinely need to be current: the WS "register" handler (what every
// peer's badge is decided from) and GET /auth/me (what the owning client
// itself sees).
//
// A Redis cache (see above, ACCOUNT_CACHE_TTL_SECONDS) sits in front of the
// actual MongoDB read, so a change still shows up within a bounded time
// (60s) without hitting Mongo on every connect/rename/poll. On a cache miss
// this also re-indexes accountsById with what it finds, so the two stay in
// sync instead of drifting further apart. Falls back to the plain cached
// lookup when Mongo isn't configured, *or* when the read itself fails — the
// caller (WS "register", on every connect/rename) has no try/catch of its
// own, so a transient Mongo hiccup must degrade to the cached value here
// rather than reject and take the whole handler down.
export async function refreshAccountFromMongo(id: string): Promise<PublicAccount | null> {
  const cached = await getCachedAccount(id);
  if (cached) return cached;
  if (!MONGO_ENABLED) return getPublicAccountById(id);
  let doc: (AccountDoc & { _id: unknown }) | null;
  try {
    await connectMongo();
    doc = (await AccountModel.findOne({ id }).select("+account").lean()) as
      | (AccountDoc & { _id: unknown })
      | null;
  } catch {
    return getPublicAccountById(id);
  }
  if (!doc) {
    // Deleted out from under the cache — drop it so nothing else here
    // still treats the id/name as claimed.
    const existing = accountsById.get(id);
    if (existing) {
      accountsById.delete(id);
      accountsByUsername.delete(fold(existing.username));
      reservedNames.delete(fold(existing.username));
      reservedNames.delete(fold(existing.displayName));
      for (const identity of existing.oauth) {
        accountsByOAuth.delete(oauthIndexKey(identity.provider, identity.providerUserId));
      }
      if (existing.email) accountsByVerifiedEmail.delete(fold(existing.email));
    }
    void invalidateCachedAccount(id);
    return null;
  }
  const account = docToFullAccount(doc as unknown as AccountDoc);
  indexAccount(account);
  const publicAccount = toPublicAccount(account);
  void setCachedAccount(publicAccount);
  return publicAccount;
}

// The name checks both creation paths (password and social) have to pass —
// pulled out so a social signup can never end up with a username a password
// signup would have rejected, or claim a name someone else already holds.
function assertNamesAvailable(username: string, displayName: string) {
  if (!USERNAME_RE.test(username)) {
    throw new Error("Usuário inválido — use 3 a 20 letras, números ou _.");
  }
  if (!isValidAccountDisplayName(displayName)) {
    throw new Error("Nome de exibição inválido.");
  }
  if (reservedNames.has(fold(username)) || reservedNames.has(fold(displayName))) {
    throw new Error("Usuário ou nome de exibição já em uso.");
  }
}

export async function createAccount(
  username: string,
  displayName: string,
  password: string,
  ip: string,
  flags: string[] = []
): Promise<PublicAccount> {
  assertNamesAvailable(username, displayName);
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
    // A password signup never asks for an email, so there's nothing to
    // record here — an account only gets one by linking a provider.
    email: null,
    emailVerified: false,
    oauth: [],
  };
  indexAccount(account);
  await persistNewAccount(account);
  return toPublicAccount(account);
}

// The social-login counterpart of createAccount: same name rules, no
// password at all (see FullAccount.passwordHash), and the provider identity
// stored with the account from the start, so there's never a moment where
// one exists without the other.
export async function createOAuthAccount(options: {
  username: string;
  displayName: string;
  ip: string;
  identity: OAuthIdentityInput;
  emailVerified: boolean;
}): Promise<PublicAccount> {
  const { username, displayName, ip, identity, emailVerified } = options;
  // Racing signups for the same provider account (double-clicked button,
  // two tabs, a retried request) must not produce two accounts — the second
  // one finds the first here and logs into it instead. Checked before the
  // name validation so the loser of the race doesn't fail on its own
  // now-taken username.
  const existingId = findAccountIdByOAuth(identity.provider, identity.providerUserId);
  const existing = existingId ? accountsById.get(existingId) : undefined;
  if (existing) return toPublicAccount(existing);
  assertNamesAvailable(username, displayName);
  const now = Date.now();
  const account: FullAccount = {
    id: randomUUID(),
    username,
    displayName,
    flags: [],
    createdAt: now,
    updatedAt: now,
    passwordHash: null,
    ips: [ip],
    email: identity.email,
    emailVerified,
    oauth: [{ ...identity, linkedAt: now }],
  };
  indexAccount(account);
  await persistNewAccount(account);
  return toPublicAccount(account);
}

// Attaches a provider identity to an account that already exists — either
// because a verified email matched it (see oauthRoutes.ts) or because its
// owner asked to connect it while logged in. Idempotent: linking the same
// identity twice is a no-op rather than a duplicate entry.
export type LinkOAuthResult =
  | { ok: true; account: PublicAccount }
  // The account the link was for no longer exists (deleted mid-flow).
  | { ok: false; reason: "account-gone" }
  // That provider account is already someone else's way into the site.
  | { ok: false; reason: "identity-taken" };

export async function linkOAuthIdentity(
  accountId: string,
  identity: OAuthIdentityInput,
  emailVerified: boolean
): Promise<LinkOAuthResult> {
  const account = accountsById.get(accountId);
  if (!account) return { ok: false, reason: "account-gone" };
  // A provider identity resolves to exactly one account here (see
  // accountsByOAuth), so linking one that already belongs to somebody else
  // can't mean "move it" — it would silently take over their login while
  // leaving a dead entry behind on their account. Refuse instead, and let
  // the caller say so.
  const owner = findAccountIdByOAuth(identity.provider, identity.providerUserId);
  if (owner && owner !== accountId) return { ok: false, reason: "identity-taken" };
  const alreadyLinked = account.oauth.some(
    (entry) =>
      entry.provider === identity.provider && entry.providerUserId === identity.providerUserId
  );
  if (!alreadyLinked) {
    // One entry per provider: connecting a *different* Discord account
    // replaces the previous one rather than leaving two entries on the same
    // account, which is what switching Discord accounts actually means. The
    // one being replaced stops resolving here, so drop its index entry too.
    for (const entry of account.oauth) {
      if (entry.provider === identity.provider) {
        accountsByOAuth.delete(oauthIndexKey(entry.provider, entry.providerUserId));
      }
    }
    account.oauth = [
      ...account.oauth.filter((entry) => entry.provider !== identity.provider),
      { ...identity, linkedAt: Date.now() },
    ];
    // Only ever *fills in* a missing email — never overwrites one already on
    // file, so linking a provider can't quietly move an account's identity
    // to a different address.
    if (identity.email && emailVerified && !account.email) {
      account.email = identity.email;
      account.emailVerified = true;
    }
    account.updatedAt = Date.now();
    indexAccount(account);
    await persistAccountIdentity(account);
  }
  return { ok: true, account: toPublicAccount(account) };
}

function findAccountIdByOAuth(provider: string, providerUserId: string): string | undefined {
  return accountsByOAuth.get(oauthIndexKey(provider, providerUserId));
}

// The primary social-login lookup: an identity this deployment has seen
// before resolves straight to its account, no email involved.
export function findAccountByOAuthIdentity(
  provider: string,
  providerUserId: string
): PublicAccount | null {
  const id = findAccountIdByOAuth(provider, providerUserId);
  const account = id ? accountsById.get(id) : undefined;
  return account ? toPublicAccount(account) : null;
}

// The secondary lookup, used only on a *first* login with a given provider:
// an account whose email some provider already asserted verified.
// Deliberately not a plain email match — see accountsByVerifiedEmail.
export function findAccountByVerifiedEmail(email: string): PublicAccount | null {
  const id = accountsByVerifiedEmail.get(fold(email));
  const account = id ? accountsById.get(id) : undefined;
  return account ? toPublicAccount(account) : null;
}

// Detaches a provider from an account, refusing when it's the only way its
// owner can still get in — there's no email recovery here, so an account
// with neither a password nor a linked identity is simply lost. The caller
// turns "last-credential" into a 409 (see oauthRoutes.ts).
export async function unlinkOAuthProvider(
  accountId: string,
  provider: string
): Promise<"ok" | "not-linked" | "last-credential"> {
  const account = accountsById.get(accountId);
  if (!account) return "not-linked";
  const remaining = account.oauth.filter((entry) => entry.provider !== provider);
  if (remaining.length === account.oauth.length) return "not-linked";
  if (!account.passwordHash && remaining.length === 0) return "last-credential";
  for (const entry of account.oauth) {
    if (entry.provider === provider) {
      accountsByOAuth.delete(oauthIndexKey(entry.provider, entry.providerUserId));
    }
  }
  account.oauth = remaining;
  account.updatedAt = Date.now();
  await persistAccountIdentity(account);
  return "ok";
}

// Which providers are linked, for the account's own view of itself (see GET
// /auth/me). Provider ids only — the provider-side email isn't that
// endpoint's business — plus whether a password exists, which is what tells
// a client that unlinking everything would lock the owner out.
export function getAccountConnections(id: string): { providers: string[]; hasPassword: boolean } {
  const account = accountsById.get(id);
  if (!account) return { providers: [], hasPassword: false };
  return {
    providers: account.oauth.map((entry) => entry.provider),
    hasPassword: Boolean(account.passwordHash),
  };
}

export async function verifyAccountLogin(
  username: string,
  password: string,
  ip: string
): Promise<PublicAccount | null> {
  const id = accountsByUsername.get(fold(username));
  const account = id ? accountsById.get(id) : undefined;
  if (!account) return null;
  // An account created through Discord/Google has no password to compare
  // against — bailing here (instead of letting bcrypt.compare decide) keeps
  // that from ever becoming a login path.
  if (!account.passwordHash) return null;
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
