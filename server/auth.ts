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
}

export function signToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL });
}

export function verifyToken(token: string | null | undefined): JwtPayload | null {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (typeof decoded !== "object" || decoded === null) return null;
    const { sub, username, flags } = decoded as Record<string, unknown>;
    if (typeof sub !== "string" || typeof username !== "string" || !Array.isArray(flags)) {
      return null;
    }
    return { sub, username, flags: flags.filter((f): f is string => typeof f === "string") };
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
