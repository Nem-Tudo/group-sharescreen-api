import { Schema, model } from "mongoose";

export interface AccountDoc {
  id: string;
  username: string;
  displayName: string;
  flags: string[];
  // Sensitive/internal — excluded from queries by default (see `select:
  // false` below), same intent as the whole-list `select("-_id")` pattern
  // in moderationStore.ts: never accidentally leak this into an API
  // response just because a query forgot to project it out.
  account: {
    passwordHash: string;
    ips: string[];
  };
  createdAt: number;
  updatedAt: number;
}

const accountSchema = new Schema<AccountDoc>(
  {
    id: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    displayName: { type: String, required: true },
    flags: { type: [String], default: [] },
    account: {
      type: new Schema(
        {
          passwordHash: { type: String, required: true },
          ips: { type: [String], default: [] },
        },
        { _id: false }
      ),
      required: true,
      select: false,
    },
    createdAt: { type: Number, required: true },
    updatedAt: { type: Number, required: true },
  },
  // No timestamps/versionKey — createdAt/updatedAt are our own app-level
  // fields (used for display), not Mongoose's.
  { versionKey: false }
);

export const AccountModel = model<AccountDoc>("Account", accountSchema, "accounts");
