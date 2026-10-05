"use client";

// ─── Download whole project — footer action ──────────────────────────────────
// Fetches /api/project/download (same-origin, gateway-safe — identical path
// shape to every other API call) and hands the blob to the browser as a file
// save. No navigation, so the SPA state and socket bus stay untouched.

import { useCallback, useState } from "react";
import { Button } from "@/components/ui/button";
import { FolderDown, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export function DownloadProjectButton() {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);

  const handleDownload = useCallback(async () => {
    setBusy(true);
    // Abort a wedged request so the button always recovers.
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), 90_000);
    try {
      const res = await fetch("/api/project/download", { signal: controller.signal });
      if (!res.ok) {
        throw new Error(`archive request failed (${res.status})`);
      }
      const blob = await res.blob();
      // Prefer the server's filename; fall back to a dated default.
      const disposition = res.headers.get("Content-Disposition") ?? "";
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const filename = match?.[1] ?? `swarmscan-project-${new Date().toISOString().slice(0, 10)}.zip`;

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      toast({
        title: "Project archive downloaded",
        description: `${filename} · ${(blob.size / 1024 / 1024).toFixed(1)} MB — source, configs, prisma schema, seeded DB and engine service, with a restore manifest at the archive root.`,
      });
    } catch (e) {
      toast({
        title: "Download failed",
        description:
          e instanceof Error && e.name === "AbortError"
            ? "The archive build timed out — try again in a moment."
            : e instanceof Error
              ? e.message
              : "The archive could not be built.",
        variant: "destructive",
      });
    } finally {
      clearTimeout(abortTimer);
      setBusy(false);
    }
  }, [toast]);

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={handleDownload}
      disabled={busy}
      className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground hover:text-foreground"
      aria-label="Download the whole SwarmScan project as a zip archive"
    >
      {busy ? (
        <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
      ) : (
        <FolderDown className="h-3 w-3" aria-hidden />
      )}
      Download project
    </Button>
  );
}
