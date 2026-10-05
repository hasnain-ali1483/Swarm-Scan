"use client";

// ─── Live event bus feed (Overview row 3a) ───────────────────────────────────
// Terminal-aesthetic feed. Also exports the presentational EventFeedList that
// the scan detail timeline re-uses.

import { AnimatePresence, motion } from "framer-motion";
import { Terminal } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EVENT_TYPE_STYLES, cn } from "@/lib/swarm/format";
import type { EngineEventNew, EventLogItem } from "@/lib/swarm/types";

export function eventStyle(type: string): { text: string; label: string } {
  return (
    EVENT_TYPE_STYLES[type] ?? {
      text: "text-zinc-400",
      label: (type || "event").toUpperCase().slice(0, 8),
    }
  );
}

export function eventTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

/** Map a live socket event to the EventLogItem shape used by the feed. */
export function toEventItem(e: EngineEventNew): EventLogItem {
  return {
    id: `live-${e.ts}-${Math.random().toString(36).slice(2, 7)}`,
    scanId: e.scanId ?? null,
    type: e.type,
    message: e.message,
    meta: null,
    createdAt: e.ts,
  };
}

export function EventLine({ event }: { event: EventLogItem }) {
  const style = eventStyle(event.type);
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: "easeOut" }}
      className="grid grid-cols-[56px_54px_1fr] items-baseline gap-x-2 rounded px-1 py-1 font-mono text-[11px] leading-5 transition-colors hover:bg-muted/40 sm:grid-cols-[62px_62px_1fr_72px]"
    >
      <time className="shrink-0 text-zinc-500" dateTime={event.createdAt}>
        {eventTime(event.createdAt)}
      </time>
      <span className={cn("shrink-0 text-[10px] font-semibold uppercase tracking-wider", style.text)}>
        {style.label}
      </span>
      <span className="break-words text-zinc-300" title={event.message}>{event.message}</span>
      {event.scanId && (
        <span
          className="hidden truncate text-right text-zinc-600 sm:block"
          title={event.scanId}
        >
          {event.scanId.slice(0, 8)}
        </span>
      )}
    </motion.div>
  );
}

export function EventFeedList({
  events,
  maxHeightClass = "max-h-[420px]",
  emptyText = "awaiting events…",
}: {
  events: EventLogItem[];
  maxHeightClass?: string;
  emptyText?: string;
}) {
  return (
    <div
      className={`${maxHeightClass} overflow-y-auto swarm-scroll pr-1`}
      role="log"
      aria-label="Engine event log"
    >
      {events.length === 0 ? (
        <p className="py-8 text-center font-mono text-xs text-muted-foreground">
          {emptyText}
        </p>
      ) : (
        <AnimatePresence initial={false}>
          {events.map((e) => (
            <EventLine key={e.id} event={e} />
          ))}
        </AnimatePresence>
      )}
    </div>
  );
}

export function LiveEventFeed({
  connected,
  events,
}: {
  connected: boolean;
  events: EventLogItem[];
}) {
  return (
    <Card className="h-full gap-3 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Terminal className="h-4 w-4 text-primary" aria-hidden />
          Event Bus
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-2 text-xs">
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded border px-1.5 py-px font-mono text-[10px] font-semibold uppercase tracking-wider",
              connected
                ? "border-primary/40 bg-primary/10 text-primary"
                : "border-red-500/40 bg-red-500/10 text-red-400"
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                connected ? "bg-primary swarm-pulse" : "bg-red-500"
              )}
              aria-hidden
            />
            {connected ? "LIVE" : "OFFLINE"}
          </span>
          <span className="font-mono text-zinc-500">{events.length}/80 buffered</span>
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <EventFeedList events={events} />
      </CardContent>
    </Card>
  );
}
