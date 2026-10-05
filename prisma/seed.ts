// ─── SwarmScan is seedless — all data is real & operational ──────────────────
//
// This platform does NOT ship or inject demo/sample data. Every scan, finding,
// evidence item, attack chain, event, target, policy and integration row is
// produced by real operator actions and real engine runs:
//   • Targets are registered + authorized by the operator (Targets view).
//   • Scans run the real engine (mini-services/scan-engine) against those
//     authorized targets; findings/evidence/chains are parsed from real probes.
//   • Integrations are merged from the code catalog and configured for real.
//
// The former demo seed was removed intentionally. This file is kept as a no-op
// so `prisma db seed` / tooling does not fail, and so no fabricated rows can be
// reintroduced. Do not add create() calls here.

async function main(): Promise<void> {
  console.log(
    "[seed] SwarmScan is seedless — no demo data is injected. " +
      "Register a target in the Targets view and launch a real scan."
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
