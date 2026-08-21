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
    // Null for an account created through Discord/Google that never set a
    // password — such an account simply can't log in through /auth/login
    // (see accountStore.ts's verifyAccountLogin), it isn't a passwordless
    // account in the "anyone can walk in" sense.
    passwordHash: string | null;
    ips: string[];
    // Email as reported by the OAuth provider, plus whether that provider
    // asserted it verified. Only a *verified* one is ever matched against
    // an existing account (see oauthRoutes.ts's linking rule), which is why
    // the flag is stored next to it rather than inferred later.
    email: string | null;
    emailVerified: boolean;
    // Every social identity that resolves to this account. An array (not a
    // pair of fields) so one account can hold Discord *and* Google, and so
    // a third provider needs no schema change.
    oauth: OAuthIdentityDoc[];
  };
  createdAt: number;
  updatedAt: number;
}

export interface OAuthIdentityDoc {
  provider: string;
  // The provider's own immutable id for the user — matched on, never the
  // email, so someone changing their Discord email still lands on the same
  // account here.
  providerUserId: string;
  email: string | null;
  linkedAt: number;
}

const oauthIdentitySchema = new Schema<OAuthIdentityDoc>(
  {
    provider: { type: String, required: true },
    providerUserId: { type: String, required: true },
    email: { type: String, default: null },
    linkedAt: { type: Number, required: true },
  },
  { _id: false }
);

const accountSchema = new Schema<AccountDoc>(
  {
    id: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    displayName: { type: String, required: true },
    flags: { type: [String], default: [] },
    account: {
      type: new Schema(
        {
          // Not `required` any more (see AccountDoc): an account created
          // through a social login has no password until it sets one.
          passwordHash: { type: String, default: null },
          ips: { type: [String], default: [] },
          email: { type: String, default: null },
          emailVerified: { type: Boolean, default: false },
          oauth: { type: [oauthIdentitySchema], default: [] },
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

// The lookups a social login does on every callback. accountStore.ts serves
// them from its in-memory index in practice (same as it does for usernames),
// so these exist for the direct-query path — a second instance, or anything
// reading the collection by hand — rather than for the hot path.
accountSchema.index({ "account.oauth.provider": 1, "account.oauth.providerUserId": 1 });
accountSchema.index({ "account.email": 1 });

export const AccountModel = model<AccountDoc>("Account", accountSchema, "accounts");
