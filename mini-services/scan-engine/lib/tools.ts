// ─── External tool registry + safe process runner ───────────────────────────
//
// The real engine prefers industry tools (nmap, httpx, nuclei, …) and falls
// back to built-in TS probes when a binary is absent (graceful degradation —
// a missing tool reports "unavailable", it never fabricates a result).
//
// Safety: processes are spawned with an argv array (never a shell string), a
// hard timeout, and a captured-output cap. No user input is ever interpolated
// into a shell.

import { spawn } from "node:child_process";
import { access, constants } from "node:fs/promises";
import path from "node:path";

export type ToolName = "nmap" | "httpx" | "nuclei" | "subfinder" | "masscan" | "katana";

export const KNOWN_TOOLS: ToolName[] = ["nmap", "httpx", "nuclei", "subfinder", "masscan", "katana"];

const CACHE = new Map<string, string | null>();

/** Cross-platform PATH lookup (honours PATHEXT on Windows). */
export async function which(bin: string): Promise<string | null> {
  if (CACHE.has(bin)) return CACHE.get(bin)!;
  const pathVar = process.env.PATH ?? process.env.Path ?? "";
  const dirs = pathVar.split(path.delimiter).filter(Boolean);
  const exts =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";").map((e) => e.toLowerCase())
      : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      const full = path.join(dir, bin + ext);
      try {
        await access(full, constants.X_OK);
        CACHE.set(bin, full);
        return full;
      } catch {
        /* try next */
      }
    }
  }
  CACHE.set(bin, null);
  return null;
}

export interface ToolStatus {
  name: ToolName;
  available: boolean;
  path: string | null;
}

export async function detectTools(): Promise<Record<ToolName, ToolStatus>> {
  const out = {} as Record<ToolName, ToolStatus>;
  await Promise.all(
    KNOWN_TOOLS.map(async (name) => {
      const p = await which(name);
      out[name] = { name, available: p !== null, path: p };
    })
  );
  return out;
}

export interface RunResult {
  ok: boolean;
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnError?: string;
}

const MAX_OUTPUT = 4 * 1024 * 1024; // 4MB cap per stream

/** Spawn a binary with an argv array, a timeout, and captured output. */
export function run(
  bin: string,
  args: string[],
  opts: { timeoutMs?: number } = {}
): Promise<RunResult> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let child;
    try {
      child = spawn(bin, args, { windowsHide: true });
    } catch (err) {
      resolve({
        ok: false,
        code: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        spawnError: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout?.on("data", (d: Buffer) => {
      if (stdout.length < MAX_OUTPUT) stdout += d.toString("utf-8");
    });
    child.stderr?.on("data", (d: Buffer) => {
      if (stderr.length < MAX_OUTPUT) stderr += d.toString("utf-8");
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ ok: false, code: null, stdout, stderr, timedOut, spawnError: err.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: !timedOut && code === 0, code, stdout, stderr, timedOut });
    });
  });
}
