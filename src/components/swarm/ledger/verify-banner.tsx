"use client";

// ─── Ledger integrity verification banner ────────────────────────────────────
// GET /api/ledger/verify → green "chain intact" / destructive "CHAIN BROKEN".
// Auto-verifies once per view mount.

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, ShieldCheck, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api, type LedgerVerifyResponse } from "@/lib/swarm/types";
import { formatHash } from "@/lib/swarm/format";

export function VerifyBanner() {
  const [result, setResult] = useState<LedgerVerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const autoRan = useRef(false);

  const runVerify = useCallback(async () => {
    setVerifying(true);
    setError(null);
    try {
      const res = await api<LedgerVerifyResponse>("/api/ledger/verify");
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification request failed");
    } finally {
      setVerifying(false);
    }
  }, []);

  // Auto-verify once per mount (ref guards against React StrictMode double-runs).
  useEffect(() => {
    if (autoRan.current) return;
    autoRan.current = true;
    void runVerify();
  }, [runVerify]);

  const checkedAt = result?.checkedAt ? new Date(result.checkedAt).toLocaleTimeString() : "";

  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Walk the full hash chain (genesis → head) and confirm every link re-hashes.
        </p>
        <Button
          size="sm"
          onClick={() => void runVerify()}
          disabled={verifying}
          className="gap-2"
          aria-label="Verify chain integrity"
        >
          {verifying ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <ShieldCheck className="h-4 w-4" aria-hidden />}
          {verifying ? "Verifying…" : "Verify chain integrity"}
        </Button>
      </div>

      {error ? (
        <div role="alert" className="flex items-start gap-2.5 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-400">
          <ShieldX className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>Verification unavailable — {error}</span>
        </div>
      ) : null}

      {result && result.valid ? (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          role="status"
          className="flex items-start gap-2.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300"
        >
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
          <span>
            Chain intact — <span className="font-semibold">{result.checked}</span> links verified · head{" "}
            <span className="font-mono text-emerald-400">{formatHash(result.headHash)}</span>
            {checkedAt ? <> · checked {checkedAt}</> : null}
          </span>
        </motion.div>
      ) : null}

      {result && !result.valid ? (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-md border border-red-500/50 bg-red-500/10 p-3 text-xs text-red-400"
        >
          <ShieldX className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <span className="font-semibold uppercase">Chain broken</span> at link #
            {result.brokenAt ?? "?"} — entries from this sequence onward no longer re-hash. Preserve
            the export and investigate tampering.
          </span>
        </div>
      ) : null}

      {verifying ? <p className="sr-only" role="status">Verifying chain integrity…</p> : null}
    </div>
  );
}
