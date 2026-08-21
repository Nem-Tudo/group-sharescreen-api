// Provider-agnostic half of the social login. Everything specific to
// Discord/Google lives in the PROVIDERS table below and nowhere else — the
// routes in oauthRoutes.ts only ever deal with the normalized OAuthProfile
// this module hands back, so adding a third provider is a table entry plus
// two env vars, not a new code path.
//
// No PKCE: both providers here are *confidential* clients (the token
// exchange is server-to-server and signed with a client secret the browser
// never sees), which is exactly the case PKCE isn't needed for. The
// authorization code is bound to this server by that secret, and the CSRF
// binding comes from the signed state + nonce cookie in oauthRoutes.ts.
import { signPurposeToken, verifyPurposeToken } from "./auth.js";

export type OAuthProviderId = "discord" | "google";

// What every provider gets boiled down to before the account layer sees it.
// `emailVerified` decides whether an existing account with the same email
// may be auto-linked (see oauthRoutes.ts) — never trusted from a provider
// that doesn't actually assert it.
export interface OAuthProfile {
  provider: OAuthProviderId;
  providerUserId: string;
  email: string | null;
  emailVerified: boolean;
  // Starting points for the "choose your username" step, not decisions —
  // both are validated (and can be freely overridden) before an account is
  // created. See suggestUsername.
  suggestedUsername: string;
  suggestedDisplayName: string;
}

interface ProviderDef {
  id: OAuthProviderId;
  label: string;
  clientId: string | null;
  clientSecret: string | null;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scope: string;
  // Provider-specific authorize params — e.g. Google needs prompt/access_type
  // to behave sanely for someone signed into more than one account.
  extraAuthorizeParams: Record<string, string>;
  parseProfile(raw: Record<string, unknown>): OAuthProfile;
}

const PROVIDERS: Record<OAuthProviderId, ProviderDef> = {
  discord: {
    id: "discord",
    label: "Discord",
    clientId: process.env.DISCORD_CLIENT_ID || null,
    clientSecret: process.env.DISCORD_CLIENT_SECRET || null,
    authorizeUrl: "https://discord.com/oauth2/authorize",
    tokenUrl: "https://discord.com/api/oauth2/token",
    userInfoUrl: "https://discord.com/api/users/@me",
    // "identify" alone would be enough to log someone in, but without
    // "email" there's nothing to match an existing account against (see the
    // linking rule in oauthRoutes.ts), so every social login would strand
    // the user on the signup step even when they already have an account.
    scope: "identify email",
    extraAuthorizeParams: {},
    parseProfile(raw) {
      // `global_name` is Discord's current display name; `username` is the
      // unique handle that replaced the old name#1234 pair. Accounts that
      // never migrated have only `username`.
      const globalName = typeof raw.global_name === "string" ? raw.global_name : "";
      const username = typeof raw.username === "string" ? raw.username : "";
      return {
        provider: "discord",
        providerUserId: String(raw.id ?? ""),
        email: typeof raw.email === "string" ? raw.email : null,
        // Discord's `verified` is specifically about the email address,
        // which is what this flag means here too.
        emailVerified: raw.verified === true,
        suggestedUsername: suggestUsername(username || globalName),
        suggestedDisplayName: (globalName || username).slice(0, 24),
      };
    },
  },
  google: {
    id: "google",
    label: "Google",
    clientId: process.env.GOOGLE_CLIENT_ID || null,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || null,
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    // The OIDC userinfo endpoint, read with the access token we just got
    // over TLS straight from Google — same claims as the id_token, without
    // this server having to fetch JWKS and verify a signature to trust them.
    userInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
    scope: "openid email profile",
    extraAuthorizeParams: {
      // Nothing here needs offline access: Google is called exactly once,
      // inside the callback, and never again on the user's behalf.
      access_type: "online",
      // Without this, someone signed into several Google accounts gets
      // silently logged in as whichever one Google feels like picking.
      prompt: "select_account",
    },
    parseProfile(raw) {
      const name = typeof raw.name === "string" ? raw.name : "";
      const email = typeof raw.email === "string" ? raw.email : null;
      const fallbackName = name || (email ? email.split("@")[0] : "");
      return {
        provider: "google",
        providerUserId: String(raw.sub ?? ""),
        email,
        // A real boolean on this endpoint, but Google has historically sent
        // the string "true" on other surfaces — accept both, nothing else.
        emailVerified: raw.email_verified === true || raw.email_verified === "true",
        suggestedUsername: suggestUsername(fallbackName),
        suggestedDisplayName: fallbackName.slice(0, 24),
      };
    },
  },
};

export function isOAuthProviderId(value: string): value is OAuthProviderId {
  return value === "discord" || value === "google";
}

// A provider with no credentials configured is treated as if it didn't
// exist (404 from /start, hidden from the button list) rather than failing
// halfway through the redirect dance. Every external dependency in this
// project is opt-in via env (see MONGO_URL/REDIS_URL) and social login is
// no different — a deployment that sets neither pair keeps working exactly
// as it did before.
export function isProviderConfigured(id: OAuthProviderId): boolean {
  const provider = PROVIDERS[id];
  return Boolean(provider.clientId && provider.clientSecret);
}

// Drives which buttons the frontend renders — it has no other way to know
// which providers this deployment actually holds secrets for.
export function listConfiguredProviders(): { id: OAuthProviderId; label: string }[] {
  return (Object.keys(PROVIDERS) as OAuthProviderId[])
    .filter(isProviderConfigured)
    .map((id) => ({ id, label: PROVIDERS[id].label }));
}

// Turns a provider's free-form name into something USERNAME_RE accepts
// (3-20 of [a-zA-Z0-9_]): strips accents rather than dropping the letters
// under them ("João" -> "joao", not "jo"), folds everything else to "_",
// and collapses the runs that creates. Only ever a *suggestion* — the user
// sees it in an editable field, and uniqueness is settled server-side when
// the account is actually created.
export function suggestUsername(raw: string): string {
  // NFD splits an accented letter into its base letter plus a combining
  // mark, and every one of those marks lives in U+0300-U+036F — dropping
  // that range is what leaves "joao" behind instead of "jo". Filtered by
  // codepoint rather than by a regex range so the source file stays plain
  // ASCII (the literal marks are invisible in an editor).
  const ascii = [...raw.normalize("NFD")]
    .filter((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      return code < 0x300 || code > 0x36f;
    })
    .join("")
    .toLowerCase();
  const folded = ascii
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  const sliced = folded.slice(0, 20);
  // Has to still be offerable when the name was e.g. entirely emoji or two
  // characters long: the field is editable, but it shouldn't start out
  // failing its own validation.
  return sliced.length >= 3 ? sliced : `${sliced}_user`.slice(0, 20);
}

export function buildAuthorizeUrl(id: OAuthProviderId, state: string, redirectUri: string): string {
  const provider = PROVIDERS[id];
  const url = new URL(provider.authorizeUrl);
  url.searchParams.set("client_id", provider.clientId ?? "");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", provider.scope);
  url.searchParams.set("state", state);
  for (const [key, value] of Object.entries(provider.extraAuthorizeParams)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

// Anything upstream refusing us (bad code, revoked client, provider
// outage) surfaces as this one error type, so the callback route can turn
// every failure into the same generic redirect instead of leaking provider
// internals into a URL the user sees.
export class OAuthError extends Error {}

const UPSTREAM_TIMEOUT_MS = 10_000;

async function postForm(url: string, body: Record<string, string>): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(body).toString(),
    // A provider hanging must not hang a request of ours along with it —
    // the user is sitting on a blank redirect page while this runs.
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new OAuthError(`Token endpoint respondeu ${res.status}`);
  }
  return (await res.json()) as Record<string, unknown>;
}

// The whole server-to-server half of the dance: code -> access token ->
// profile. One call because neither step is ever useful on its own, and the
// access token deliberately doesn't escape it — OAuth is used here purely
// to authenticate a person, never to hold an API credential for them
// afterwards, so there's nothing worth storing once the profile is read.
export async function exchangeCodeForProfile(
  id: OAuthProviderId,
  code: string,
  redirectUri: string
): Promise<OAuthProfile> {
  const provider = PROVIDERS[id];
  if (!provider.clientId || !provider.clientSecret) {
    throw new OAuthError(`Provedor ${id} não configurado.`);
  }
  const tokenResponse = await postForm(provider.tokenUrl, {
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    grant_type: "authorization_code",
    code,
    // Must match the /start redirect_uri byte for byte or both providers
    // reject the exchange — that's why it's threaded through from the
    // caller instead of being rebuilt here.
    redirect_uri: redirectUri,
  });
  const accessToken = tokenResponse.access_token;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new OAuthError("Resposta do provedor não trouxe access_token.");
  }
  const userRes = await fetch(provider.userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!userRes.ok) {
    throw new OAuthError(`Endpoint de perfil respondeu ${userRes.status}`);
  }
  const profile = provider.parseProfile((await userRes.json()) as Record<string, unknown>);
  if (!profile.providerUserId) {
    throw new OAuthError("Perfil do provedor veio sem id.");
  }
  return profile;
}

// --- Short-lived tokens carried through the redirect chain ---------------
//
// Both are signed with the same JWT_SECRET as a session token but under a
// distinct `purpose` (see auth.ts), so neither can ever be replayed as one.
// That separation is what makes it safe to hand them to the browser.

// Round-trips through the provider as the `state` param. Its `nonce` is
// matched against a cookie set on the same browser at /start, which is what
// stops an attacker from feeding a victim a callback URL for the attacker's
// own authorization (login CSRF).
export interface OAuthState {
  provider: OAuthProviderId;
  nonce: string;
  // Origin to hand the result back to, already checked against the
  // allowlist at /start so the callback can trust it as-is.
  origin: string;
  // Path within that origin the user started from, so a login begun inside
  // a room returns there instead of dumping them on the home page.
  next: string;
  // Set when the flow was started by someone already logged in, to link a
  // provider to their existing account instead of logging in as someone new.
  linkAccountId?: string;
}

const STATE_TTL = "10m";

export function signOAuthState(state: OAuthState): string {
  return signPurposeToken("oauth-state", state, STATE_TTL);
}

export function verifyOAuthState(token: string): OAuthState | null {
  const payload = verifyPurposeToken("oauth-state", token);
  if (!payload) return null;
  const { provider, nonce, origin, next, linkAccountId } = payload;
  if (typeof provider !== "string" || !isOAuthProviderId(provider)) return null;
  if (typeof nonce !== "string" || typeof origin !== "string" || typeof next !== "string") return null;
  return {
    provider,
    nonce,
    origin,
    next,
    linkAccountId: typeof linkAccountId === "string" ? linkAccountId : undefined,
  };
}

// Handed to the frontend when a social login turns out to be a *signup*: it
// carries the already-verified provider identity across the "choose your
// username" step, so that step needs no half-created account sitting in the
// database — an abandoned signup leaves nothing behind to clean up.
export interface OAuthSignupTicket {
  provider: OAuthProviderId;
  providerUserId: string;
  email: string | null;
  emailVerified: boolean;
  suggestedUsername: string;
  suggestedDisplayName: string;
}

// Long enough to actually pick a name (and fix a collision or two), short
// enough that a ticket left behind in a tab's URL stops working quickly.
const SIGNUP_TICKET_TTL = "30m";

export function signSignupTicket(ticket: OAuthSignupTicket): string {
  return signPurposeToken("oauth-signup", ticket, SIGNUP_TICKET_TTL);
}

export function verifySignupTicket(token: string): OAuthSignupTicket | null {
  const payload = verifyPurposeToken("oauth-signup", token);
  if (!payload) return null;
  const { provider, providerUserId, email, emailVerified, suggestedUsername, suggestedDisplayName } =
    payload;
  if (typeof provider !== "string" || !isOAuthProviderId(provider)) return null;
  if (typeof providerUserId !== "string" || !providerUserId) return null;
  return {
    provider,
    providerUserId,
    email: typeof email === "string" ? email : null,
    emailVerified: emailVerified === true,
    suggestedUsername: typeof suggestedUsername === "string" ? suggestedUsername : "",
    suggestedDisplayName: typeof suggestedDisplayName === "string" ? suggestedDisplayName : "",
  };
}
