"use client";

// ─── Shared loading / error / empty states for SwarmScan views ───────────────
// Used by findings, ledger and attack-graph views (all owned by task 4-b).

import type { ReactNode } from "react";
import { AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/swarm/format";

export function ErrorState({
  message,
  onRetry,
  title = "Failed to load data",
  retrying = false,
}: {
  message?: string;
  onRetry?: () => void;
  title?: string;
  retrying?: boolean;
}) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-10 text-center"
    >
      <AlertCircle className="h-6 w-6 text-destructive" aria-hidden />
      <div>
        <p className="text-sm font-medium">{title}</p>
        {message ? <p className="mt-1 max-w-md text-xs text-muted-foreground break-words">{message}</p> : null}
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying} className="gap-2">
          <AlertCircle className="h-3.5 w-3.5" aria-hidden />
          {retrying ? "Retrying…" : "Retry"}
        </Button>
      ) : null}
    </div>
  );
}

export function ListSkeleton({ rows = 6, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} aria-hidden>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 rounded-lg border bg-card/40 px-4 py-3">
          <Skeleton className="h-5 w-16 rounded" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-2/5" />
            <Skeleton className="h-3 w-3/5" />
          </div>
          <Skeleton className="h-5 w-20 rounded" />
          <Skeleton className="hidden h-5 w-14 rounded sm:block" />
        </div>
      ))}
    </div>
  );
}

export function BlockSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("space-y-4", className)} aria-hidden>
      <div className="flex items-center gap-3">
        <Skeleton className="h-8 w-8 rounded-full" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-3 w-1/2" />
        </div>
      </div>
      <Skeleton className="h-40 w-full rounded-lg" />
      <Skeleton className="h-24 w-full rounded-lg" />
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 rounded-lg border border-dashed bg-card/30 px-6 py-14 text-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-zinc-700/60 bg-zinc-900/60 text-zinc-400">
        {icon}
      </div>
      <p className="text-sm font-medium text-zinc-300">{title}</p>
      <p className="max-w-md text-xs text-muted-foreground">{description}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
