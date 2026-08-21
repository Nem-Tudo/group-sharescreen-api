import { randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";

// Falls back to a per-process random secret when unset, matching this
// project's no-config-needed-for-dev pattern (see server/index.ts) — but
// every restart then invalidates every existing token (everyone gets
// logged out), so set JWT_SECRET in production.
const JWT_SECRET = process.env.JWT_SECRET || randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) {
  console.warn(
    "[auth] JWT_SECRET não configurado — usando um segredo temporário (tokens não sobrevivem a um restart do servidor)."
  );
}

const JWT_TTL = "30d";

export interface JwtPayload {
  sub: string;
  username: string;
  flags: string[];
  // True for a guest identity token (see signaling.ts's "register" handler)
  // rather than a registered account — same signing/verification path as an
  // account token, this flag is what lets a caller tell the two apart. A
  // guest's `sub` is a randomly generated id (never a real account id), and
  // its `flags` is always empty.
  guest?: boolean;
}

export function signToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL });
}

export function verifyToken(token: string | null | undefined): JwtPayload | null {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (typeof decoded !== "object" || decoded === null) return null;
    const { sub, username, flags, guest, purpose } = decoded as Record<string, unknown>;
    // A session token never carries `purpose` — anything that does is one of
    // the short-lived OAuth tokens below and must not authenticate anyone,
    // even though it's signed with this same secret. The field checks below
    // would already reject it for lacking sub/username/flags; this is the
    // explicit half of that, so it stays true if this payload ever grows.
    if (purpose !== undefined) return null;
    if (typeof sub !== "string" || typeof username !== "string" || !Array.isArray(flags)) {
      return null;
    }
    return {
      sub,
      username,
      flags: flags.filter((f): f is string => typeof f === "string"),
      guest: guest === true,
    };
  } catch {
    return null;
  }
}

// Short-lived tokens for things that are *not* a session: the OAuth `state`
// that round-trips through Discord/Google, and the signup ticket that
// carries a verified provider identity across the "choose your username"
// step (see oauth.ts). Same secret as a session token, but stamped with a
// `purpose` that verifyToken above never accepts and that these two check
// explicitly — so one of these can't be replayed as a login, and a stolen
// session token can't be replayed as either of them. Signing them instead
// of keeping server-side state is what lets the flow work across a restart
// or a second instance without a shared session store.
type TokenPurpose = "oauth-state" | "oauth-signup";

export function signPurposeToken(
  purpose: TokenPurpose,
  payload: object,
  ttl: string
): string {
  return jwt.sign({ ...payload, purpose }, JWT_SECRET, { expiresIn: ttl as jwt.SignOptions["expiresIn"] });
}

export function verifyPurposeToken(
  purpose: TokenPurpose,
  token: string | null | undefined
): Record<string, unknown> | null {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (typeof decoded !== "object" || decoded === null) return null;
    const claims = decoded as Record<string, unknown>;
    // The check that makes the separation real — a token signed for another
    // purpose (or a plain session token, which carries no purpose at all)
    // verifies cryptographically but is rejected right here.
    if (claims.purpose !== purpose) return null;
    return claims;
  } catch {
    return null;
  }
}

export function getBearerToken(header: string | undefined): string | null {
  return header?.startsWith("Bearer ") ? header.slice(7) : null;
}

// Shared by every /admin/* route (replacing the old checkBasicAuth /
// verifyAdminToken pair) — admin is now just an account whose flags
// include "ADMIN", authenticated the exact same way as any other request.
export function requireAdmin(request: { headers: { authorization?: string } }): JwtPayload | null {
  const payload = verifyToken(getBearerToken(request.headers.authorization));
  return payload && payload.flags.includes("ADMIN") ? payload : null;
}
