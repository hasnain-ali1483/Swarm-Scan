// Copy static assets + public/ into the Next standalone output so
// `node .next/standalone/server.js` serves them. Cross-platform replacement
// for the old `cp -r` build step (worked only on bun/unix).
import { cp, access } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";

const root = process.cwd();
const standalone = path.join(root, ".next", "standalone");

async function exists(p) {
  try {
    await access(p, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  if (!(await exists(standalone))) {
    console.warn("[postbuild] .next/standalone missing — skipping asset copy (is output:'standalone' set?)");
    return;
  }
  await cp(path.join(root, ".next", "static"), path.join(standalone, ".next", "static"), {
    recursive: true,
  });
  if (await exists(path.join(root, "public"))) {
    await cp(path.join(root, "public"), path.join(standalone, "public"), { recursive: true });
  }
  console.log("[postbuild] copied static + public into .next/standalone");
}

main().catch((err) => {
  console.error("[postbuild] failed:", err);
  process.exit(1);
});
