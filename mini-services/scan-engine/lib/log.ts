/** Timestamped console logging — one line per event, easy to tail. */
export function log(msg: string): void {
  console.log(`[${new Date().toISOString()}] [scan-engine] ${msg}`);
}

export function logError(msg: string, err?: unknown): void {
  const detail = err instanceof Error ? `: ${err.message}` : err ? `: ${String(err)}` : "";
  console.error(`[${new Date().toISOString()}] [scan-engine] ERROR ${msg}${detail}`);
}
