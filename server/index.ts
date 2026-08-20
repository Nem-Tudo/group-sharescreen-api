// Side-effect import (not `import dotenv from "dotenv"; dotenv.config();`)
// on purpose: ES module evaluation runs every statically imported module
// (signaling.js, accountStore.js, mongo.ts, auth.ts, and everything they in
// turn import) to completion *before* any of this file's own top-level
// statements run — regardless of where those statements sit relative to
// the import declarations in the source. A plain `dotenv.config()` call
// here would therefore only populate process.env after ADMIN_USER,
// MONGO_URL, JWT_SECRET etc. had already been read (as undefined) by those
// modules' own top-level code. Being the first *import* instead makes it
// the first module actually evaluated, ahead of everything else this file
// imports.
import "dotenv/config";

import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import websocketPlugin from "@fastify/websocket";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { registerSignalingRoutes, initClusterAnnouncementSync } from "./signaling.js";
import { register as metricsRegister, httpRateLimitedTotal } from "./metrics.js";
import { initModerationStore } from "./moderationStore.js";
import { initAccountStore } from "./accountStore.js";
import { connectCluster } from "./cluster.js";

const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || "0.0.0.0";
// Optional: if set, /metrics requires `Authorization: Bearer <token>`.
// Prometheus scrape configs support this natively (`bearer_token: ...`).
// Left unset by default to match this project's no-config-needed-for-dev
// pattern, but set it in production — metrics expose room activity and
// shouldn't be world-readable on an unauthenticated endpoint.
const METRICS_TOKEN = process.env.METRICS_TOKEN || null;

const CURRENT_ID = randomUUID()

async function main() {
  // Every piece of realtime signaling state (rooms, presence, name
  // reservations, clientId ownership/reclaim, the WebRTC signal relay, the
  // announcement banner — see cluster.ts) is coordinated through Redis, so
  // it stays consistent across however many instances of this process run
  // behind a load balancer. That coordination is what makes running more
  // than one instance safe at all, so REDIS_URL is required, not optional —
  // fail fast here rather than let a Redis-less second instance silently
  // desync from the first one.
  if (!process.env.REDIS_URL) {
    console.error("[server] REDIS_URL não configurada — obrigatória (ver server/cluster.ts).");
    process.exit(1);
  }

  // trustProxy: this always runs behind a reverse proxy in production (see
  // README — apigolive.nemtudo.me), so request.ip needs to read the real
  // client address from X-Forwarded-For instead of the proxy's own address.
  // Without it every connection would appear to come from the same IP,
  // making IP bans useless.
  const app = Fastify({ logger: true, trustProxy: true });

  // Connects the Redis command/subscriber clients used for cross-instance
  // coordination (cluster.ts) before anything else touches them, and primes
  // this instance's local announcement banner from whatever's currently
  // persisted (see initClusterAnnouncementSync in signaling.ts).
  await connectCluster();
  await initClusterAnnouncementSync();

  // Loads persisted IP bans and banned words (Mongo if MONGO_URL is set,
  // otherwise a local JSON file — see moderationStore.ts) before the server
  // starts accepting connections, so the very first WebSocket upgrade is
  // already checked against whatever was configured in a previous run.
  await initModerationStore();
  // Loads registered accounts (and bootstraps the initial ADMIN one from
  // ADMIN_USER/ADMIN_PASSWORD if configured) before the server starts
  // accepting connections — see accountStore.ts.
  await initAccountStore();

  // @fastify/cors defaults to methods: "GET,HEAD,POST" — without listing
  // DELETE and PUT explicitly here, the browser's preflight for
  // DELETE /admin/announcement (clearing an announcement) or
  // PUT /admin/banned-words (saving the chat filter) gets back an
  // Access-Control-Allow-Methods that doesn't include them, so it blocks
  // the real request client-side with a CORS error before it ever reaches
  // this server.
  await app.register(cors, {
    origin: true,
    methods: ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: "*",
    exposedHeaders: "*",
  });
  await app.register(websocketPlugin, {
    options: { maxPayload: 64 * 1024 },
  });

  // Global default: applies to every route below unless overridden via that
  // route's own `config.rateLimit` (see signaling.ts, and the /health and
  // /metrics overrides right here) — most routes never touch this default
  // at all, it's just the floor for anything nobody's specifically tuned.
  // `global: true` (the plugin default) is what makes it apply automatically
  // to routes registered later, including the ones inside the nested
  // `registerSignalingRoutes` context below — a root-level onRequest hook
  // reaches every child context in Fastify's encapsulation model.
  await app.register(rateLimit, {
    max: 100,
    timeWindow: "1 minute",
    onExceeded: (request) => {
      httpRateLimitedTotal.inc({ route: request.routeOptions?.url ?? request.url });
    },
  });

  // Health checks (uptime monitors, container orchestrator probes, load
  // balancers) can legitimately poll every few seconds from a fixed set of
  // IPs — rate limiting this would risk the check itself flapping the
  // service as unhealthy, which is worse than any abuse this endpoint could
  // realistically absorb (it does nothing but echo a constant).
  app.get("/health", { config: { rateLimit: false } }, async () => ({ ok: true, CURRENT_ID }));

  app.get(
    "/metrics",
    {
      // Scraped automatically (Prometheus et al.) on a fixed interval from a
      // small, known set of scrapers — generous enough to tolerate several
      // scrape configs hitting it in parallel, but still capped in case this
      // ever ends up reachable without METRICS_TOKEN set.
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (METRICS_TOKEN) {
        const header = request.headers.authorization || "";
        const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
        if (provided !== METRICS_TOKEN) {
          return reply.code(401).send("Unauthorized");
        }
      }
      reply.header("Content-Type", metricsRegister.contentType);
      return metricsRegister.metrics();
    }
  );

  await app.register(async (instance) => {
    registerSignalingRoutes(instance, randomUUID);
  });

  try {
    await app.listen({ port: PORT, host: HOST });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
