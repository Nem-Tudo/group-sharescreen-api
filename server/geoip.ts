import geoip from "geoip-lite";

// Rounded to 1 decimal place (~11km at the equator) — coarse enough that
// this never pinpoints an individual visitor's exact address, fine enough
// to still spread across a map instead of clustering into a single dot per
// country. This also bounds how many distinct label combinations
// connectionsByLocationGauge (see metrics.ts) can ever accumulate — however
// many grid cells actually get visited, not one per connection ever made.
const COORD_PRECISION = 1;

export interface ConnectionLocation {
  // ISO 3166-1 alpha-2 (e.g. "BR") — geoip-lite's own format.
  country: string;
  lat: string;
  lon: string;
}

// Returns null for an IP GeoIP can't place — a private/local address (dev,
// or behind a proxy that isn't forwarding the real client IP), an
// unroutable range, or just missing from the bundled offline database.
// Callers skip tracking those rather than plotting a pile of connections at
// 0,0. Synchronous and entirely offline (no external API call, no rate
// limit, no per-lookup network round trip) — geoip-lite loads its bundled
// MaxMind-derived database into memory once at import time.
export function lookupConnectionLocation(ip: string): ConnectionLocation | null {
  const result = geoip.lookup(ip);
  if (!result || !result.country || !result.ll) return null;
  const [lat, lon] = result.ll;
  return {
    country: result.country,
    lat: lat.toFixed(COORD_PRECISION),
    lon: lon.toFixed(COORD_PRECISION),
  };
}
