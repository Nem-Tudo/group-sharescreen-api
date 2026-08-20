// Cloudflare Turnstile server-side verification — gates the WS "join"
// message (see signaling.ts), since that's also how a room gets *created*
// in this codebase (the first join creates it — there's no separate
// "create room" action). Two separate opt-ins, deliberately not one:
//   - TURNSTILE_SECRET_KEY: needed at all to call Cloudflare's siteverify.
//     Unset (local dev, or before the front-end widget exists) and
//     verifyTurnstileToken below just passes everyone through, same
//     pattern as MONGO_ENABLED/METRICS_TOKEN elsewhere in this server.
//   - TURNSTILE_ENABLED=true: actually *enforces* it (see TURNSTILE_ENABLED
//     below and its use in signaling.ts's "join" handler) — kept separate
//     from the secret key so the key + front-end widget can be deployed and
//     exercised first without immediately rejecting anyone. Older,
//     not-yet-updated clients never send a token at all, so flipping
//     enforcement on the moment the key is configured would lock all of
//     them out; this way it only turns on once someone deliberately does so.
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || null;
export const TURNSTILE_ENABLED = process.env.TURNSTILE_ENABLED === "true" && TURNSTILE_SECRET_KEY !== null;

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
// Cloudflare's own guidance: treat a slow/unreachable siteverify call as a
// failure rather than hanging the client's join indefinitely.
const VERIFY_TIMEOUT_MS = 5_000;

interface SiteverifyResponse {
  success: boolean;
  "error-codes"?: string[];
}

// Each token is valid for exactly one verification (Cloudflare invalidates
// it the moment this call succeeds), lives for ~5 minutes, and is bound to
// the site key that issued it — the front-end must fetch a fresh token
// before every join, not reuse one across multiple rooms.
export async function verifyTurnstileToken(token: string, remoteIp: string): Promise<boolean> {
  if (!TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
  try {
    const body = new URLSearchParams({
      secret: TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: remoteIp,
    });
    const res = await fetch(SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: controller.signal,
    });
    const data = (await res.json()) as SiteverifyResponse;
    return data.success === true;
  } catch (err) {
    console.error("[turnstile] Falha ao verificar token:", (err as Error).message);
    // Fail closed — if Cloudflare's own verification endpoint is
    // unreachable, that's treated the same as a failed challenge rather
    // than letting an unverifiable join through. This is a bot gate; an
    // unverifiable request is exactly the case it exists to catch.
    return false;
  } finally {
    clearTimeout(timeout);
  }
}
