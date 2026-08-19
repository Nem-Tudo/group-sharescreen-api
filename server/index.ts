import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import websocketPlugin from "@fastify/websocket";
import cors from "@fastify/cors";
import { registerSignalingRoutes } from "./signaling.js";
import { register as metricsRegister } from "./metrics.js";

const PORT = Number(process.env.SIGNALING_PORT || 4000);
const HOST = process.env.SIGNALING_HOST || "0.0.0.0";
// Optional: if set, /metrics requires `Authorization: Bearer <token>`.
// Prometheus scrape configs support this natively (`bearer_token: ...`).
// Left unset by default to match this project's no-config-needed-for-dev
// pattern, but set it in production — metrics expose room activity and
// shouldn't be world-readable on an unauthenticated endpoint.
const METRICS_TOKEN = process.env.METRICS_TOKEN || null;

async function main() {
  const app = Fastify({ logger: true });

  // @fastify/cors defaults to methods: "GET,HEAD,POST" — without listing
  // DELETE explicitly here, the browser's preflight for
  // DELETE /admin/announcement (clearing an announcement) gets back an
  // Access-Control-Allow-Methods that doesn't include DELETE, so it blocks
  // the real request client-side with a CORS error before it ever reaches
  // this server.
  await app.register(cors, { origin: true, methods: ["GET", "HEAD", "POST", "DELETE"] });
  await app.register(websocketPlugin, {
    options: { maxPayload: 64 * 1024 },
  });

  app.get("/health", async () => ({ ok: true }));

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
