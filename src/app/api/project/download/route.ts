import { deflateRawSync } from "node:zlib";
import { readdirSync, readFileSync, statSync, type Dirent } from "node:fs";
import { join, relative, sep } from "node:path";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/project/download — the WHOLE SwarmScan project as a zip.
 *
 * Zero-dependency ZIP writer (local headers + central directory + EOCD,
 * deflate via node:zlib): no bundler-sensitive CJS libs, nothing for
 * Turbopack to wedge on. Ships source, configs, prisma schema + seeded
 * DB, mini-service sources, public assets and the worklog, plus a
 * generated PROJECT_MANIFEST.txt. Dev artifacts (node_modules, .next,
 * logs, uploads, tool-results) are pruned during the walk.
 */

const ROOT = process.cwd();

/** Directories never descended into (pruned mid-walk — fast). */
const PRUNE_DIRS = new Set([
  "node_modules",
  ".next",
  ".git",
  "tool-results",
  "agent-ctx",
  "upload",
  ".zscripts",
  ".turbo",
]);

/** Root-level files that never ship. */
const PRUNE_ROOT_FILES = new Set([
  "dev.log",
  "--full-page",
  ".env",
]);

/** File suffixes never shipped. */
const PRUNE_SUFFIXES = [".log", ".db-journal", ".png"];

/** Top-level paths that DO ship (walked, pruned by the rules above). */
const INCLUDE_TOP = [
  "src",
  "prisma",
  "db",
  "public",
  "mini-services",
  "examples",
];

/** Root files that ship. */
const INCLUDE_ROOT_FILES = [
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "next.config.ts",
  "next-env.d.ts",
  "tailwind.config.ts",
  "postcss.config.mjs",
  "eslint.config.mjs",
  "components.json",
  "Caddyfile",
  ".gitignore",
  "README.md",
  "worklog.md",
];

// ─── Minimal ZIP writer ──────────────────────────────────────────────────────

/** CRC-32 (IEEE 802.3) over the polymomial 0xEDB88320 — standard table impl. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/** DOS date/time pair from a JS Date (zip's 1980-based 2s-granularity clock). */
function dosDateTime(d: Date): { time: number; date: number } {
  const time =
    ((d.getHours() & 0x1f) << 11) |
    ((d.getMinutes() & 0x3f) << 5) |
    ((Math.floor(d.getSeconds() / 2)) & 0x1f);
  const date =
    (((d.getFullYear() - 1980) & 0x7f) << 9) |
    (((d.getMonth() + 1) & 0x0f) << 5) |
    (d.getDate() & 0x1f);
  return { time, date };
}

interface ZipEntry {
  nameBuf: Buffer;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  method: number; // 8 = deflate, 0 = store
  offset: number;
  time: number;
  date: number;
}

/** Assemble a complete zip archive from {path → content} in archive order. */
function buildZip(files: { name: string; data: Buffer; mtime: Date }[]): Buffer {
  const chunks: Buffer[] = [];
  const entries: ZipEntry[] = [];
  let offset = 0;

  for (const file of files) {
    const nameBuf = Buffer.from(file.name, "utf8");
    const deflated = deflateRawSync(file.data, { level: 9 });
    // Store when deflate cannot win (tiny files, already-compressed data).
    const useDeflate = deflated.length < file.data.length;
    const payload = useDeflate ? deflated : file.data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(file.data);
    const { time, date } = dosDateTime(file.mtime);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed (2.0 — deflate)
    local.writeUInt16LE(0, 6); // flags (no UTF-8 bit — names are ASCII)
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18); // compressed size
    local.writeUInt32LE(file.data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra length

    chunks.push(local, nameBuf, payload);
    entries.push({
      nameBuf,
      crc,
      compressedSize: payload.length,
      uncompressedSize: file.data.length,
      method,
      offset,
      time,
      date,
    });
    offset += local.length + nameBuf.length + payload.length;
  }

  // Central directory.
  const centralChunks: Buffer[] = [];
  let centralSize = 0;
  for (const entry of entries) {
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); // central dir signature
    central.writeUInt16LE(0x0314, 4); // version made by (UNIX, zip 2.0)
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8); // flags
    central.writeUInt16LE(entry.method, 10);
    central.writeUInt16LE(entry.time, 12);
    central.writeUInt16LE(entry.date, 14);
    central.writeUInt32LE(entry.crc, 16);
    central.writeUInt32LE(entry.compressedSize, 20);
    central.writeUInt32LE(entry.uncompressedSize, 24);
    central.writeUInt16LE(entry.nameBuf.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk start
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attrs (unix -rw-r--r--)
    central.writeUInt32LE(entry.offset, 42);
    centralChunks.push(central, entry.nameBuf);
    centralSize += central.length + entry.nameBuf.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // this disk
  eocd.writeUInt16LE(0, 6); // disk with central dir
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16); // central dir offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...chunks, ...centralChunks, eocd]);
}

// ─── Project walker ──────────────────────────────────────────────────────────

function walk(dir: string, out: string[]) {
  let dirents: Dirent[];
  try {
    dirents = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable dir — skip silently
  }
  for (const dirent of dirents) {
    if (dirent.isDirectory()) {
      if (PRUNE_DIRS.has(dirent.name)) continue;
      walk(join(dir, dirent.name), out);
    } else if (dirent.isFile()) {
      if (PRUNE_SUFFIXES.some((sfx) => dirent.name.endsWith(sfx))) continue;
      out.push(join(dir, dirent.name));
    }
  }
}

function collectProjectFiles(): { name: string; data: Buffer; mtime: Date }[] {
  const files: { name: string; data: Buffer; mtime: Date }[] = [];

  const push = (absolute: string) => {
    try {
      const st = statSync(absolute);
      if (!st.isFile()) return;
      files.push({
        name: relative(ROOT, absolute).split(sep).join("/"),
        data: readFileSync(absolute),
        mtime: st.mtime,
      });
    } catch {
      // vanished mid-walk — skip
    }
  };

  for (const top of INCLUDE_TOP) {
    const abs = join(ROOT, top);
    try {
      const st = statSync(abs);
      if (st.isDirectory()) {
        const found: string[] = [];
        walk(abs, found);
        found.sort().forEach(push);
      } else if (st.isFile()) {
        push(abs);
      }
    } catch {
      // top-level path missing — skip
    }
  }

  for (const name of INCLUDE_ROOT_FILES) {
    const abs = join(ROOT, name);
    try {
      if (statSync(abs).isFile() && !PRUNE_ROOT_FILES.has(name)) push(abs);
    } catch {
      // optional root file missing — skip
    }
  }

  return files;
}

// ─── Route handler ───────────────────────────────────────────────────────────

export async function GET() {
  try {
    const files = collectProjectFiles();
    files.push({
      name: "PROJECT_MANIFEST.txt",
      data: Buffer.from(buildManifest(files.length), "utf8"),
      mtime: new Date(),
    });
    files.sort((a, b) => a.name.localeCompare(b.name));

    const zip = buildZip(files);
    const stamp = new Date().toISOString().slice(0, 10);

    return new NextResponse(new Uint8Array(zip), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="swarmscan-project-${stamp}.zip"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    return NextResponse.json(
      {
        error: `Project archive failed — ${e instanceof Error ? e.message : "unknown error"}`,
      },
      { status: 500 }
    );
  }
}

function buildManifest(fileCount: number): string {
  const now = new Date().toISOString();
  return [
    "SwarmScan — Autonomous Vulnerability Scanner Platform",
    "=".repeat(56),
    "",
    `Archived:  ${now}`,
    `Entries:   ${fileCount} files`,
    "Stack:     Next.js 16 (App Router) · TypeScript · Tailwind CSS 4 · shadcn/ui ·",
    "           Prisma (SQLite) · TanStack Query · Zustand · socket.io · Framer Motion",
    "",
    "Layout",
    "------",
    "  src/                 Control-plane app (18 views, API routes, engine clients)",
    "  prisma/schema.prisma Data model (scans, findings, WORM evidence, policies…)",
    "  db/                  SQLite database (seedless — fills from real scans only)",
    "  mini-services/       scan-engine execution plane (port 3003, socket.io bus)",
    "  examples/            WebSocket reference demo",
    "  public/              Static assets",
    "",
    "Restore",
    "-------",
    "  1. npm install",
    "  2. npm run db:push        (regenerate the Prisma client)",
    "  3. npm run dev            (control plane on :3000)",
    "  4. cd mini-services/scan-engine && npm install && npm run dev   (engine on :3003)",
    "",
    "Excluded from this archive: node_modules, .next build output, dev logs,",
    "tool-results, agent contexts, uploads and QA screenshots.",
    "",
    "© 2025 SwarmScan Labs — deterministic plans · WORM ledger active.",
  ].join("\n");
}
