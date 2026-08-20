// Per-connection rate limiting for WebSocket *messages* — a different
// concern from @fastify/rate-limit (server/index.ts, server/signaling.ts's
// HTTP routes), which only ever sees the single "/ws" upgrade request and
// has no idea what happens over the socket afterwards. Everything below is
// consumed with the sending connection's own `rateLimitKey` (see
// ClientInfo.rateLimitKey in signaling.ts) so one abusive tab can never burn
// through another connection's — or another *person's* — budget.
//
// Split into one bucket per message category, deliberately sized very
// differently, because a single flat "N messages/sec" limit would either be
// so high it's useless against real spam, or so low it'd choke WebRTC
// signaling — which legitimately bursts dozens of offer/answer/ICE messages
// in the couple of seconds after joining a busy room. rate-limiter-flexible
// is used (rather than hand-rolling yet another token-bucket Map, as this
// file's neighbors already do for other things) specifically because its
// per-key TTL cleanup is automatic, so a churn of short-lived connections
// can't slowly leak memory the way a hand-rolled Map would without its own
// sweep timer.
import { RateLimiterMemory } from "rate-limiter-flexible";
import { wsRateLimitedTotal } from "./metrics.js";

// Safety net across *all* message types combined, per connection — catches
// anything the per-type limiters below don't (e.g. a flood of an unknown
// `type`, which never reaches any of them), without constraining normal
// mixed traffic. Must stay comfortably above wsSignalLimiter's own ceiling
// (1500/5s, i.e. up to 3000 across this limiter's own 10s window) or it —
// not the signal-specific limiter — would end up being the thing that
// throttles a big room's join burst, which defeats the point of sizing
// that one generously.
export const wsGlobalLimiter = new RateLimiterMemory({ points: 3500, duration: 10 });

// "register" covers both the initial name registration and every rename
// after (renaming doesn't go through "join" again — see signaling.ts). A
// real user does this at most a handful of times per session.
export const wsRegisterLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

// "join" (switch room) and "admin-join" (moderator watch) share this same
// budget — both are something a real connection does rarely, never in a
// tight loop.
export const wsJoinLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

// Chat is the one category real users drive directly and repeatedly by
// hand — generous enough for an enthusiastic back-and-forth (bursts of a
// message every second or so) while still cutting off a paste-spam loop.
export const wsChatLimiter = new RateLimiterMemory({ points: 8, duration: 5 });

// WebRTC signaling (offer/answer/ICE candidates) is by far the highest
// legitimate-traffic category: this app opens one send/recv RTCPeerConnection
// *per peer* rather than a single bidirectional one (see useRoomMedia.ts),
// so starting a share fans out an offer plus several trickled ICE candidates
// to every other participant — and that fan-out multiplies again if TURN
// relay candidates are in play (see iceConfig.ts) or someone shares both
// mic and screen at once. The client now spaces those opens out over time
// instead of firing them all in the same instant (see useRoomMedia.ts's
// openSendPCsStaggered/STAGGER_MS — a 50-person room's burst spreads across
// several seconds now, not one), which is what actually keeps a big room
// under this; the points value below is just extra headroom on top of
// that, sized generously because a dropped offer/answer here isn't retried
// anywhere near as reliably as other traffic (an offline-peer signal at
// least gets queued by deliverOrQueueSignal — this doesn't) — it just
// silently fails to connect that one peer, so the cost of this being too
// tight is much worse than the cost of it being generous. Still a real
// backstop against a runaway/malicious client, just not a normal-usage
// limiter.
export const wsSignalLimiter = new RateLimiterMemory({ points: 1500, duration: 5 });

// "sharing" / "mic" toggles — occasional user-driven UI actions, but cheap
// enough to allow a bit of rapid double-toggling without dropping it.
export const wsToggleLimiter = new RateLimiterMemory({ points: 20, duration: 10 });

// Consumes one point from `limiter` for `key`; returns false (and bumps the
// `sharescreen_ws_rate_limited_total{kind}` counter) instead of throwing
// when the budget is exhausted, so call sites can use it as a plain
// `if (!(await consumeRateLimit(...))) return;` guard.
export async function consumeRateLimit(
  limiter: RateLimiterMemory,
  key: string,
  kind: string
): Promise<boolean> {
  try {
    await limiter.consume(key);
    return true;
  } catch {
    wsRateLimitedTotal.inc({ kind });
    return false;
  }
}
