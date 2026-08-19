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
import { registerSignalingRoutes } from "./signaling.js";
import { register as metricsRegister } from "./metrics.js";
import { initModerationStore } from "./moderationStore.js";
import { initAccountStore } from "./accountStore.js";

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
  // trustProxy: this always runs behind a reverse proxy in production (see
  // README — apigolive.nemtudo.me), so request.ip needs to read the real
  // client address from X-Forwarded-For instead of the proxy's own address.
  // Without it every connection would appear to come from the same IP,
  // making IP bans useless.
  const app = Fastify({ logger: true, trustProxy: true });

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

  app.get("/health", async () => ({ ok: true, CURRENT_ID }));

  app.get("/metrics", async (request, reply) => {
    if (METRICS_TOKEN) {
      const header = request.headers.authorization || "";
      const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
      if (provided !== METRICS_TOKEN) {
        return reply.code(401).send("Unauthorized");
      }
    }
    reply.header("Content-Type", metricsRegister.contentType);
    return metricsRegister.metrics();
  });

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
