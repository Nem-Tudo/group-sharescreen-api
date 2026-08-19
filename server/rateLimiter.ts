// Sliding-window-ish rate limiting for WebSocket message actions
// (chat, join, register) — @fastify/rate-limit in index.ts only covers HTTP
// requests, so anything that happens *after* the "/ws" upgrade (i.e. every
// signaling message) needs its own counter. Deliberately fixed-window rather
// than a true sliding window or token bucket: it's cheap (one Map entry per
// key, no per-hit array/timer bookkeeping) and "resets a little early at the
// window boundary" is an acceptable trade for a spam guard, not a billing
// system.
interface Bucket {
  count: number;
  windowStart: number;
}

const buckets = new Map<string, Bucket>();

// Evicts buckets that have been idle long enough that they can't possibly
// still be rate-limiting anything — without this, every distinct key ever
// seen (one per connected client id, per action) stays in memory forever.
// Piggybacks off the same interval as the reap sweep below rather than a
// separate timer per bucket.
const BUCKET_IDLE_MS = 5 * 60_000;
const SWEEP_INTERVAL_MS = 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now - bucket.windowStart > BUCKET_IDLE_MS) buckets.delete(key);
  }
}, SWEEP_INTERVAL_MS).unref();

// Returns true if this hit is allowed under `limit` per `windowMs` for
// `key`, and records it either way (a rejected hit still counts — otherwise
// a client spamming faster than the window could keep resetting its own
// budget by re-triggering right as a new window opens).
export function hitRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.windowStart >= windowMs) {
    buckets.set(key, { count: 1, windowStart: now });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= limit;
}

// Tracks rate-limit *violations* (not hits) per IP so repeat offenders — the
// actual bot-spam pattern this exists for, as opposed to one over-eager
// human — can be escalated to an IP ban automatically. Reuses the same
// bucket map/keyspace with a distinct prefix; see moderationStore.ts for
// where the resulting ban actually lands.
const VIOLATION_KEY_PREFIX = "violation:";

export function recordViolation(ip: string, limit: number, windowMs: number): boolean {
  return !hitRateLimit(`${VIOLATION_KEY_PREFIX}${ip}`, limit, windowMs);
}
