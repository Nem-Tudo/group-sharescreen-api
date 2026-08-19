import mongoose from "mongoose";

// Optional, mirroring REDIS_URL's opt-in shape in chatStore.ts: only used
// when MONGO_URL is set. Every store built on top of this (moderationStore.ts)
// falls back to a JSON file on disk when it isn't configured, so a
// deployment that never sets it keeps working exactly as before.
const MONGO_URL = process.env.MONGO_URL;
const MONGO_DB_NAME = process.env.MONGO_DB_NAME || "sharescreen";

export const MONGO_ENABLED = Boolean(MONGO_URL);

mongoose.connection.on("error", (err: Error) => {
  console.error("[mongo] Erro na conexão com o MongoDB:", err.message);
});

// readyState 1 = connected. Checked directly on mongoose's single shared
// connection rather than tracked separately, so it can't drift out of sync
// with reality (e.g. a connection dropping after a successful connect).
export function isMongoConnected(): boolean {
  return mongoose.connection.readyState === 1;
}

let connectPromise: Promise<void> | null = null;

// Lazily connects on first use and memoizes the in-flight/connected
// promise. A failed connect resets the memo so the next call retries
// instead of replaying the same rejection forever.
export async function connectMongo(): Promise<void> {
  if (!MONGO_URL) throw new Error("MONGO_URL não configurada.");
  if (connectPromise) return connectPromise;
  connectPromise = mongoose
    .connect(MONGO_URL, { dbName: MONGO_DB_NAME })
    .then(() => undefined)
    .catch((err) => {
      connectPromise = null;
      throw err;
    });
  return connectPromise;
}
