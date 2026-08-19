import { Schema, model } from "mongoose";

export interface IpBan {
  ip: string;
  reason: string;
  createdAt: number;
  // null means permanent — never auto-expires.
  expiresAt: number | null;
}

const ipBanSchema = new Schema<IpBan>(
  {
    ip: { type: String, required: true, unique: true },
    reason: { type: String, required: true, default: "" },
    createdAt: { type: Number, required: true },
    expiresAt: { type: Number, default: null },
  },
  // No timestamps/versionKey — createdAt is our own app-level field (used
  // for sorting/display), not Mongoose's, and there's nothing here that
  // needs optimistic-concurrency version tracking.
  { versionKey: false }
);

export const IpBanModel = model<IpBan>("IpBan", ipBanSchema, "ip_bans");

// A single document (fixed _id) holding the whole banned-words list, mirroring
// setBannedWords' "replace the whole list at once" shape in moderationStore.ts.
interface ModerationConfigDoc {
  _id: string;
  bannedWords: string[];
}

const moderationConfigSchema = new Schema<ModerationConfigDoc>(
  {
    _id: { type: String },
    bannedWords: { type: [String], default: [] },
  },
  { versionKey: false }
);

export const ModerationConfigModel = model<ModerationConfigDoc>(
  "ModerationConfig",
  moderationConfigSchema,
  "moderation_config"
);
