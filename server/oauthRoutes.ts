import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { signToken, verifyToken, getBearerToken } from "./auth.js";
import {
  buildAuthorizeUrl,
  exchangeCodeForProfile,
  isOAuthProviderId,
  isProviderConfigured,
  listConfiguredProviders,
  signOAuthState,
  signSignupTicket,
  verifyOAuthState,
  verifySignupTicket,
  type OAuthProfile,
  type OAuthProviderId,
} from "./oauth.js";
import {
  createOAuthAccount,
  findAccountByOAuthIdentity,
  findAccountByVerifiedEmail,
  getPublicAccountById,
  linkOAuthIdentity,
  isValidAccountDisplayName,
  unlinkOAuthProvider,
  USERNAME_RE,
  type PublicAccount,
} from "./accountStore.js";

// Social login, start to finish. Split out of signaling.ts (where the
// password routes live) because it's a self-contained flow with its own
// vocabulary — redirects, provider state, tickets — and none of it touches
// rooms or sockets. What it produces is deliberately identical to what
// /auth/login produces: the same JWT, for the same accounts, so everything
// downstream (the WS "register" handler, requireAdmin, /auth/me) needs to
// know nothing about how someone signed in.
//
// The shape of the flow:
//
//   GET  /auth/oauth/providers          which buttons to render
//   GET  /auth/oauth/:provider/start    -> 302 to the provider
//   GET  /auth/oauth/:provider/callback <- provider comes back with a code
//        |- identity already known      -> 302 to the app with a token
//        |- verified email matches      -> links, 302 with a token
//        `- otherwise                   -> 302 with a *signup ticket*
//   POST /auth/oauth/complete           ticket + chosen username -> token
//
// Everything the browser carries between those steps is a signed,
// short-lived token (see auth.ts's signPurposeToken), so no server-side
// session store is involved and a restart mid-login doesn't break it.

// Where the app lives. Every redirect this module emits has to land on one
// of these origins — an unchecked `returnTo` would turn the callback into
// an open redirect that hands out session tokens, which is about the worst
// possible thing to have on an auth endpoint.
const WEB_ORIGINS = (process.env.WEB_ORIGINS || "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

// Public base URL of *this* API, used to build the redirect_uri the
// providers must have registered. Derived from the incoming request when
// unset (trustProxy is on, so those headers are the real public ones),
// which keeps local dev config-free — but pin it in production, where a
// spoofed Host header would otherwise change where the code is sent.
const OAUTH_CALLBACK_BASE = process.env.OAUTH_CALLBACK_BASE || null;

// Fixed page on the frontend that every callback lands on; it reads the
// fragment and either finishes the login or shows the username step.
const CALLBACK_PATH = "/oauth/callback";

const NONCE_COOKIE = "golive_oauth_nonce";
const NONCE_TTL_SECONDS = 600;

function callbackBase(request: FastifyRequest): string {
  if (OAUTH_CALLBACK_BASE) return OAUTH_CALLBACK_BASE.replace(/\/+$/, "");
  // `host`, not `hostname` — the latter drops the port, which produces a
  // redirect_uri of http://localhost/... in dev and gets rejected by both
  // providers for not matching the registered one.
  return `${request.protocol}://${request.host}`;
}

function redirectUriFor(request: FastifyRequest, provider: OAuthProviderId): string {
  return `${callbackBase(request)}/auth/oauth/${provider}/callback`;
}

// Only the *origin* of a caller-supplied URL is honoured, and only if it's
// on the allowlist; the path is kept separately (see `next` below) and
// re-attached to a known-good origin, so nothing the caller sends can point
// the redirect somewhere else.
function resolveOrigin(rawReturnTo: string | undefined): { origin: string; next: string } {
  const fallback = { origin: WEB_ORIGINS[0] ?? "", next: "/" };
  if (!rawReturnTo) return fallback;
  let parsed: URL;
  try {
    parsed = new URL(rawReturnTo);
  } catch {
    return fallback;
  }
  if (!WEB_ORIGINS.includes(parsed.origin)) return fallback;
  // Query and hash are dropped on purpose: the fragment is where the result
  // gets written, and nothing in the original query is worth carrying back.
  return { origin: parsed.origin, next: parsed.pathname || "/" };
}

// The result is handed over in the URL *fragment*, not the query string:
// fragments aren't sent to the server, don't land in access logs, and
// aren't forwarded in a Referer header — which matters a lot when the value
// is a session token.
function redirectToApp(reply: FastifyReply, state: { origin: string; next: string }, params: Record<string, string>) {
  const fragment = new URLSearchParams({ ...params, next: state.next }).toString();
  return reply.redirect(`${state.origin}${CALLBACK_PATH}#${fragment}`, 302);
}

function setNonceCookie(reply: FastifyReply, nonce: string, secure: boolean) {
  // Written by hand rather than via @fastify/cookie: it's one cookie, on
  // two routes, and this avoids a dependency (and a plugin registration)
  // for a dozen characters of header.
  //
  // SameSite=Lax is the point of the whole thing — it's still sent on the
  // top-level GET navigation the provider bounces back to, but not on
  // cross-site subresource requests. Path-scoped so it exists only for the
  // routes that read it.
  const parts = [
    `${NONCE_COOKIE}=${nonce}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/auth/oauth",
    `Max-Age=${NONCE_TTL_SECONDS}`,
  ];
  if (secure) parts.push("Secure");
  reply.header("Set-Cookie", parts.join("; "));
}

function clearNonceCookie(reply: FastifyReply, secure: boolean) {
  const parts = [`${NONCE_COOKIE}=`, "HttpOnly", "SameSite=Lax", "Path=/auth/oauth", "Max-Age=0"];
  if (secure) parts.push("Secure");
  reply.header("Set-Cookie", parts.join("; "));
}

function readNonceCookie(request: FastifyRequest): string | null {
  const header = request.headers.cookie;
  if (!header) return null;
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === NONCE_COOKIE) return rest.join("=");
  }
  return null;
}

function sessionTokenFor(account: PublicAccount): string {
  return signToken({ sub: account.id, username: account.username, flags: account.flags });
}

export async function registerOAuthRoutes(app: FastifyInstance) {
  // Lets the frontend render only the buttons this deployment can actually
  // serve — a provider with no client id/secret configured is invisible
  // rather than a button that 404s.
  app.get(
    "/auth/oauth/providers",
    { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
    async () => ({ providers: listConfiguredProviders() })
  );

  // Step 1. Mints the state + nonce pair and bounces the browser to the
  // provider. A GET (not a POST) because it's reached by a plain link or
  // window.open from the client, and nothing here mutates anything.
  app.get(
    "/auth/oauth/:provider/start",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const { provider } = request.params as { provider: string };
      if (!isOAuthProviderId(provider) || !isProviderConfigured(provider)) {
        return reply.code(404).send({ error: "Provedor não disponível." });
      }
      const query = request.query as { returnTo?: string; token?: string };
      const { origin, next } = resolveOrigin(query.returnTo);
      if (!origin) {
        return reply.code(500).send({ error: "WEB_ORIGINS não configurado." });
      }

      // An already-logged-in caller can pass their session token to attach a
      // provider to *that* account instead of logging in as someone else.
      // It rides in the query because this is a top-level navigation, which
      // can't carry an Authorization header — it's the caller's own token,
      // over TLS, and it's verified here rather than trusted.
      const session = query.token ? verifyToken(query.token) : null;
      const linkAccountId = session && !session.guest ? session.sub : undefined;

      const nonce = randomBytes(16).toString("hex");
      const state = signOAuthState({ provider, nonce, origin, next, linkAccountId });
      setNonceCookie(reply, nonce, request.protocol === "https");
      return reply.redirect(
        buildAuthorizeUrl(provider, state, redirectUriFor(request, provider)),
        302
      );
    }
  );

  // Step 2. Where the provider sends the browser back. Everything that can
  // go wrong here ends as a redirect carrying `error=...`, never as a raw
  // error page: the user is mid-login on a blank tab, and the frontend
  // callback page is the only thing that can show them something useful.
  app.get(
    "/auth/oauth/:provider/callback",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const { provider } = request.params as { provider: string };
      const query = request.query as { code?: string; state?: string; error?: string };
      const secure = request.protocol === "https";

      const state = query.state ? verifyOAuthState(query.state) : null;
      // With no valid state there's no verified origin to redirect to, so
      // this is the one failure that has to be answered inline.
      if (!state || !isOAuthProviderId(provider) || state.provider !== provider) {
        clearNonceCookie(reply, secure);
        return reply.code(400).send({ error: "Estado de login inválido ou expirado." });
      }

      // The CSRF check: the state came back intact, but only the browser
      // that *started* this flow has the matching nonce cookie. Without it,
      // an attacker could hand someone a callback URL for the attacker's own
      // authorization and silently log them into the attacker's account.
      const cookieNonce = readNonceCookie(request);
      clearNonceCookie(reply, secure);
      if (!cookieNonce || cookieNonce !== state.nonce) {
        return redirectToApp(reply, state, { error: "state_mismatch" });
      }

      // The user pressed "cancel" on the provider's consent screen.
      if (query.error || !query.code) {
        return redirectToApp(reply, state, { error: "cancelled" });
      }

      let profile: OAuthProfile;
      try {
        profile = await exchangeCodeForProfile(provider, query.code, redirectUriFor(request, provider));
      } catch (err) {
        console.error("[oauth] Falha ao trocar code por perfil:", (err as Error).message);
        return redirectToApp(reply, state, { error: "provider_failed" });
      }

      // Case A — an explicit link request from someone already logged in.
      if (state.linkAccountId) {
        const linked = await linkOAuthIdentity(
          state.linkAccountId,
          { provider, providerUserId: profile.providerUserId, email: profile.email },
          profile.emailVerified
        );
        if (!linked) return redirectToApp(reply, state, { error: "account_gone" });
        return redirectToApp(reply, state, { token: sessionTokenFor(linked), linked: provider });
      }

      // Case B — an identity we've seen before: a plain login.
      const existing = findAccountByOAuthIdentity(provider, profile.providerUserId);
      if (existing) {
        return redirectToApp(reply, state, { token: sessionTokenFor(existing) });
      }

      // Case C — first time with this provider, but the provider vouches for
      // an email that already belongs to an account here. Linking the two is
      // what keeps someone from ending up with a duplicate account just
      // because they clicked a different button than last time.
      //
      // Gated on emailVerified precisely because the provider's word is the
      // only evidence involved: without it, anyone could set an unverified
      // email on a throwaway provider account and walk into the matching
      // account here.
      if (profile.email && profile.emailVerified) {
        const byEmail = findAccountByVerifiedEmail(profile.email);
        if (byEmail) {
          const linked = await linkOAuthIdentity(
            byEmail.id,
            { provider, providerUserId: profile.providerUserId, email: profile.email },
            true
          );
          if (linked) {
            return redirectToApp(reply, state, { token: sessionTokenFor(linked), linked: provider });
          }
        }
      }

      // Case D — a genuine signup. No account is created yet: the ticket
      // carries the verified identity to the username step, so abandoning
      // it leaves nothing behind.
      const ticket = signSignupTicket({
        provider,
        providerUserId: profile.providerUserId,
        email: profile.email,
        emailVerified: profile.emailVerified,
        suggestedUsername: profile.suggestedUsername,
        suggestedDisplayName: profile.suggestedDisplayName,
      });
      return redirectToApp(reply, state, {
        ticket,
        provider,
        suggestedUsername: profile.suggestedUsername,
        suggestedDisplayName: profile.suggestedDisplayName,
      });
    }
  );

  // Step 3, only for a signup: turns a ticket plus the name the user picked
  // into a real account. A POST from the frontend (not a redirect), so it
  // answers with JSON in the same { token, account } shape as /auth/login —
  // the client stores it exactly the same way.
  app.post(
    "/auth/oauth/complete",
    { config: { rateLimit: { max: 10, timeWindow: "15 minutes" } } },
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const ticket = typeof body.ticket === "string" ? verifySignupTicket(body.ticket) : null;
      if (!ticket) {
        return reply.code(400).send({ error: "Sessão de cadastro expirada — entre novamente." });
      }
      const username = (typeof body.username === "string" ? body.username.trim() : "").toLowerCase();
      const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
      if (!USERNAME_RE.test(username)) {
        return reply.code(400).send({ error: "Usuário inválido — use 3 a 20 letras, números ou _." });
      }
      if (!isValidAccountDisplayName(displayName)) {
        return reply.code(400).send({ error: "Nome de exibição inválido." });
      }
      try {
        const account = await createOAuthAccount({
          username,
          displayName,
          ip: request.ip,
          identity: {
            provider: ticket.provider,
            providerUserId: ticket.providerUserId,
            email: ticket.email,
          },
          emailVerified: ticket.emailVerified,
        });
        return { token: sessionTokenFor(account), account };
      } catch (err) {
        // The realistic failure is a name taken between the suggestion and
        // the submit — 409 so the client can re-prompt on the same ticket
        // rather than restart the whole provider dance.
        const message = err instanceof Error ? err.message : "Falha ao criar conta.";
        return reply.code(409).send({ error: message });
      }
    }
  );

  // Unlinks a provider from the caller's own account. Refuses to remove the
  // last way in: an account with no password and no other identity would
  // become unreachable, and there's no email recovery here to fall back on.
  app.delete(
    "/auth/oauth/:provider/link",
    { config: { rateLimit: { max: 10, timeWindow: "5 minutes" } } },
    async (request, reply) => {
      const { provider } = request.params as { provider: string };
      if (!isOAuthProviderId(provider)) {
        return reply.code(404).send({ error: "Provedor não disponível." });
      }
      const session = verifyToken(getBearerToken(request.headers.authorization));
      if (!session || session.guest) return reply.code(401).send({ error: "unauthorized" });
      const account = getPublicAccountById(session.sub);
      if (!account) return reply.code(401).send({ error: "unauthorized" });
      const result = await unlinkOAuthProvider(session.sub, provider);
      if (result === "last-credential") {
        return reply
          .code(409)
          .send({ error: "Defina uma senha antes de desconectar seu único método de login." });
      }
      return { ok: true };
    }
  );
}

