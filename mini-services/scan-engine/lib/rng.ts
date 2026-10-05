// ─── Deterministic RNG utilities ─────────────────────────────────────────────
//
// DETERMINISM SLO: byte-identical probe sequence for identical
// (target, seed, agent version).
//
// The master PRNG of every scan is a mulberry32 stream seeded with
// cyrb53(`${scanId}:${seed}`). ALL randomness in a scan — state durations,
// request counts, finding generation, correlation decisions — derives from
// that single master seed.
//
// Because agents inside one DAG stage execute in parallel on independent
// timers (whose interleaving is inherently non-deterministic), each agent
// receives its OWN child stream: at plan time, in fixed catalog order, one
// master-rng draw per planned agent seeds that agent's mulberry32 stream.
// Scan-level decisions (e.g. the verify-pass duration) are drawn from the
// master stream at fixed sequential points. This keeps every per-agent probe
// sequence byte-identical regardless of timer interleaving.

/** cyrb53 — 53-bit string hash (https://stackoverflow.com/a/52171480). */
export function cyrb53(str: string, seed = 0): number {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/** mulberry32 — small, fast, well-distributed seeded PRNG. */
export function mulberry32(a: number): () => number {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Inclusive integer in [min, max] drawn from a rng stream. */
export function randInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

/** Real in [min, max) drawn from a rng stream. */
export function randRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min);
}
