import { Schema, model } from "mongoose";

export interface ApiTokenDoc {
  id: string;
  label: string;
  // sha256 of the raw secret — see apiTokenStore.ts for why sha256 rather
  // than bcrypt is the right hash here.
  tokenHash: string;
  createdAt: number;
  // Admin account id (JwtPayload.sub) that created this token.
  createdBy: string;
  revokedAt: number | null;
  lastUsedAt: number | null;
}

const apiTokenSchema = new Schema<ApiTokenDoc>(
  {
    id: { type: String, required: true, unique: true },
    label: { type: String, required: true },
    tokenHash: { type: String, required: true, unique: true },
    createdAt: { type: Number, required: true },
    createdBy: { type: String, required: true },
    revokedAt: { type: Number, default: null },
    lastUsedAt: { type: Number, default: null },
  },
  { versionKey: false }
);

export const ApiTokenModel = model<ApiTokenDoc>("ApiToken", apiTokenSchema, "api_tokens");

// A room handle reserved via POST /createroom — see apiRoomStore.ts. Purely
// a namespace-claim + ownership record for DELETE /createroom; the room
// itself only becomes a live RoomInfo (see signaling.ts) on first real
// WebSocket join, same as an organically-created room.
export interface ApiRoomDoc {
  handle: string;
  tokenId: string;
  createdAt: number;
}

const apiRoomSchema = new Schema<ApiRoomDoc>(
  {
    handle: { type: String, required: true, unique: true },
    tokenId: { type: String, required: true },
    createdAt: { type: Number, required: true },
  },
  { versionKey: false }
);

export const ApiRoomModel = model<ApiRoomDoc>("ApiRoom", apiRoomSchema, "api_rooms");
