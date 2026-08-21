import fs from "node:fs";
import path from "node:path";
import { MONGO_ENABLED, connectMongo } from "./mongo.js";
import { ApiRoomModel, type ApiRoomDoc } from "./apiTokenModels.js";

export interface ApiRoomReservation {
  handle: string;
  tokenId: string;
  createdAt: number;
}

// Same opt-in shape as apiTokenStore.ts, and deliberately no in-memory cache
// for the same reason — read/written only by POST/DELETE /createroom in
// signaling.ts, which is rate-limited and low-QPS.
const DATA_DIR = path.join(process.cwd(), "server", "data");
const DATA_FILE = path.join(DATA_DIR, "apiRooms.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

function loadFromDisk(): ApiRoomDoc[] {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ApiRoomDoc[]) : [];
  } catch {
    return [];
  }
}

function saveToDisk(rooms: ApiRoomDoc[]) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(rooms));
  } catch {
    // Best-effort, matches every other store here.
  }
}

export async function getRoomReservation(handle: string): Promise<ApiRoomReservation | null> {
  if (MONGO_ENABLED) {
    await connectMongo();
    const doc = await ApiRoomModel.findOne({ handle }).select("-_id").lean();
    return (doc as ApiRoomReservation | null) ?? null;
  }
  const rooms = loadFromDisk();
  return rooms.find((r) => r.handle === handle) ?? null;
}

export async function createRoomReservation(handle: string, tokenId: string): Promise<ApiRoomReservation> {
  const reservation: ApiRoomReservation = { handle, tokenId, createdAt: Date.now() };
  if (MONGO_ENABLED) {
    await connectMongo();
    await ApiRoomModel.create(reservation);
  } else {
    const rooms = loadFromDisk();
    rooms.push(reservation);
    saveToDisk(rooms);
  }
  return reservation;
}

export async function deleteRoomReservation(handle: string): Promise<void> {
  if (MONGO_ENABLED) {
    await connectMongo();
    await ApiRoomModel.deleteOne({ handle });
  } else {
    saveToDisk(loadFromDisk().filter((r) => r.handle !== handle));
  }
}
