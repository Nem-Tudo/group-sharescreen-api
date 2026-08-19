import { Registry, collectDefaultMetrics, Gauge, Counter } from "prom-client";

export const register = new Registry();

// CPU, memory (RSS/heap), event loop lag, GC, open file descriptors, etc. —
// everything Node/prom-client can tell us about this process for free.
collectDefaultMetrics({ register });

export type RoomStats = {
  handle: string;
  peopleCount: number;
  sharingCount: number;
  isPrivate: boolean;
};

export type SignalingStats = {
  connectedSockets: number;
  registeredPeers: number;
  rooms: RoomStats[];
};

const emptyStats: SignalingStats = { connectedSockets: 0, registeredPeers: 0, rooms: [] };

// signaling.ts owns the actual connection/room state; it hands us a getter
// once at startup instead of this module importing signaling.ts directly,
// so the metrics module never needs to know about ClientInfo/RoomInfo
// internals and there's no import cycle between the two files.
let statsProvider: (() => SignalingStats) | null = null;

export function registerStatsProvider(provider: () => SignalingStats) {
  statsProvider = provider;
}

function getStats(): SignalingStats {
  return statsProvider ? statsProvider() : emptyStats;
}

const TOP_PRIVATE_ROOMS = 5;

new Gauge({
  name: "sharescreen_connected_sockets",
  help: "WebSocket connections currently open on the signaling server",
  registers: [register],
  collect() {
    this.set(getStats().connectedSockets);
  },
});

new Gauge({
  name: "sharescreen_registered_peers",
  help: "Connected sockets that have completed name registration",
  registers: [register],
  collect() {
    this.set(getStats().registeredPeers);
  },
});

new Gauge({
  name: "sharescreen_rooms",
  help: "Active rooms (at least one person connected), by visibility",
  labelNames: ["visibility"],
  registers: [register],
  collect() {
    const { rooms } = getStats();
    this.set({ visibility: "public" }, rooms.filter((r) => !r.isPrivate).length);
    this.set({ visibility: "private" }, rooms.filter((r) => r.isPrivate).length);
  },
});

new Gauge({
  name: "sharescreen_room_people",
  help: "People connected per public room. Private rooms are intentionally never labeled by handle here — /metrics has no access control by default, and doing so would leak private room identities to anyone who finds this endpoint, defeating the point of them being private. See sharescreen_private_room_top_people for an anonymized view.",
  labelNames: ["room"],
  registers: [register],
  collect() {
    // A labeled Gauge remembers every label combination it has ever seen
    // and keeps reporting the last value forever, even after that room is
    // long gone — reset() first so a room that emptied out actually drops
    // out of the exposed metrics instead of showing phantom people.
    this.reset();
    for (const r of getStats().rooms) {
      if (!r.isPrivate) this.set({ room: r.handle }, r.peopleCount);
    }
  },
});

new Gauge({
  name: "sharescreen_room_sharing_screen",
  help: "People actively broadcasting their screen/camera, per public room. Private rooms excluded for the same reason as sharescreen_room_people — see sharescreen_sharing_screen_total for the aggregate across all rooms.",
  labelNames: ["room"],
  registers: [register],
  collect() {
    this.reset();
    for (const r of getStats().rooms) {
      if (!r.isPrivate) this.set({ room: r.handle }, r.sharingCount);
    }
  },
});

new Gauge({
  name: "sharescreen_sharing_screen_total",
  help: "People actively broadcasting their screen/camera right now, across all rooms (public and private combined)",
  registers: [register],
  collect() {
    const total = getStats().rooms.reduce((sum, r) => sum + r.sharingCount, 0);
    this.set(total);
  },
});

new Gauge({
  name: "sharescreen_private_rooms_people_total",
  help: "Total people currently in any private room combined",
  registers: [register],
  collect() {
    const total = getStats()
      .rooms.filter((r) => r.isPrivate)
      .reduce((sum, r) => sum + r.peopleCount, 0);
    this.set(total);
  },
});

new Gauge({
  name: "sharescreen_private_room_top_people",
  help: `Sizes of the ${TOP_PRIVATE_ROOMS} largest private rooms, ranked but not identified — gives capacity/activity visibility without exposing which private room it is`,
  labelNames: ["rank"],
  registers: [register],
  collect() {
    // Same reasoning as sharescreen_room_people: without this, a rank that
    // no longer has a private room behind it (fewer private rooms now than
    // before) would keep reporting its last stale size forever.
    this.reset();
    const sizes = getStats()
      .rooms.filter((r) => r.isPrivate)
      .map((r) => r.peopleCount)
      .sort((a, b) => b - a)
      .slice(0, TOP_PRIVATE_ROOMS);
    for (let i = 0; i < sizes.length; i += 1) {
      this.set({ rank: String(i + 1) }, sizes[i]);
    }
  },
});

export const wsConnectionsTotal = new Counter({
  name: "sharescreen_ws_connections_total",
  help: "WebSocket connections accepted since process start",
  registers: [register],
});

export const wsDisconnectionsTotal = new Counter({
  name: "sharescreen_ws_disconnections_total",
  help: "WebSocket connections closed since process start",
  registers: [register],
});

export const heartbeatReapedTotal = new Counter({
  name: "sharescreen_heartbeat_reaped_total",
  help: "Connections forcibly terminated for failing to respond to a heartbeat ping (network dropped without a clean close)",
  registers: [register],
});

export const registerErrorsTotal = new Counter({
  name: "sharescreen_register_errors_total",
  help: "Name registration attempts rejected (invalid name or already in use)",
  registers: [register],
});

export const roomsCreatedTotal = new Counter({
  name: "sharescreen_rooms_created_total",
  help: "Rooms created (first person to join) since process start",
  registers: [register],
  labelNames: ["visibility"],
});

export const signalsRelayedTotal = new Counter({
  name: "sharescreen_signals_relayed_total",
  help: "WebRTC signaling messages (offer/answer/ice/stop) relayed between peers",
  labelNames: ["kind"],
  registers: [register],
});

export const bannedIpConnectionsRejectedTotal = new Counter({
  name: "sharescreen_banned_ip_connections_rejected_total",
  help: "WebSocket connection attempts rejected because the source IP is banned",
  registers: [register],
});

export const chatMessagesBlockedTotal = new Counter({
  name: "sharescreen_chat_messages_blocked_total",
  help: "Chat messages blocked by the banned-words filter",
  registers: [register],
});
