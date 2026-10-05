import { createHash } from "node:crypto";

/** Genesis prev-hash for the first entry of every per-scan evidence chain. */
export const ZERO_HASH = "0".repeat(64);

/**
 * WORM ledger link formula (must stay identical between seed, API routes
 * and the scan-engine ingest path):
 *
 *   hash = sha256(`${prevHash}:${sequence}:${content}`)   (hex)
 */
export function chainHash(prevHash: string, sequence: number, content: string): string {
  return createHash("sha256").update(`${prevHash}:${sequence}:${content}`).digest("hex");
}

/** Random 8-char hex string (used for scan seeds). */
export function randomSeed(): string {
  return createHash("sha256")
    .update(`${Date.now()}:${Math.random()}`)
    .digest("hex")
    .slice(0, 8);
}
