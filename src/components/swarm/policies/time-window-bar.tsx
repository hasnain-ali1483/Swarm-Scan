"use client";

// ─── 24h time-window visual — aggressive-scan policy window, pure CSS ─────────

import { useEffect, useState } from "react";
import { Clock } from "lucide-react";
import { cn } from "@/lib/swarm/format";

const RESTRICTED_START = 9; // 09:00 inclusive
const RESTRICTED_END = 18; // 17:59 exclusive (hour < 18)

const HATCHED =
  "repeating-linear-gradient(135deg, rgba(245,158,11,0.38) 0px, rgba(245,158,11,0.38) 3px, rgba(245,158,11,0.08) 3px, rgba(245,158,11,0.08) 7px)";

function isRestricted(hour: number) {
  return hour >= RESTRICTED_START && hour < RESTRICTED_END;
}

export function TimeWindowBar() {
  // Client clock only — starts null to avoid SSR hydration mismatch; the first
  // paint is scheduled off the effect body (async), then refreshed every minute.
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    const tick = () => setNow(new Date());
    const raf = requestAnimationFrame(tick);
    const timer = setInterval(tick, 60_000);
    return () => {
      cancelAnimationFrame(raf);
      clearInterval(timer);
    };
  }, []);

  const hours = Array.from({ length: 24 }, (_, h) => h);
  const nowPct = now ? ((now.getHours() + now.getMinutes() / 60) / 24) * 100 : null;

  return (
    <section
      aria-labelledby="time-window-heading"
      className="rounded-lg border border-zinc-800 bg-card/60 p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="time-window-heading" className="text-sm font-semibold tracking-tight">
          Scanning Time Window
        </h3>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-zinc-500">
          <Clock className="h-3 w-3" aria-hidden />
          {now
            ? `local time ${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
            : "—"}
        </span>
      </div>

      {/* 24h bar */}
      <div
        className="relative mt-4 h-9 overflow-hidden rounded-md border border-zinc-800"
        role="img"
        aria-label="24 hour time window: aggressive scanning permitted outside 09:00 to 17:59; business hours are restricted"
      >
        <div className="flex h-full">
          {hours.map((h) => (
            <div
              key={h}
              title={`${String(h).padStart(2, "0")}:00 – ${String(h).padStart(2, "0")}:59${
                isRestricted(h) ? " · no aggressive scanning" : " · aggressive permitted"
              }`}
              className={cn(
                "flex-1 border-r border-zinc-800/50 last:border-r-0",
                !isRestricted(h) && "bg-emerald-500/15"
              )}
              style={isRestricted(h) ? { background: HATCHED } : undefined}
            />
          ))}
        </div>
        {/* now marker */}
        {nowPct !== null && (
          <div
            className="pointer-events-none absolute inset-y-0 z-10"
            style={{ left: `calc(${nowPct}% - 1px)` }}
            aria-hidden
          >
            <div className="h-full w-0.5 bg-zinc-100 shadow-[0_0_6px_rgba(255,255,255,0.6)]" />
            <span className="absolute -top-0.5 left-1 rounded-sm bg-zinc-100 px-1 font-mono text-[9px] font-semibold uppercase text-zinc-900">
              now
            </span>
          </div>
        )}
      </div>

      {/* hour scale */}
      <div className="relative mt-1.5 h-4 font-mono text-[10px] text-zinc-600">
        {[0, 6, 12, 18].map((h) => (
          <span
            key={h}
            className="absolute -translate-x-1/2"
            style={{ left: `${(h / 24) * 100}%` }}
          >
            {String(h).padStart(2, "0")}
          </span>
        ))}
        <span className="absolute right-0">23</span>
      </div>

      {/* legend */}
      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[11px] text-zinc-400">
        <span className="flex items-center gap-1.5">
          <span
            className="h-3 w-4 rounded-sm border border-amber-500/30"
            style={{ background: HATCHED }}
            aria-hidden
          />
          09:00–17:59 · no aggressive scanning
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-4 rounded-sm border border-emerald-500/30 bg-emerald-500/15" aria-hidden />
          aggressive permitted
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-0.5 bg-zinc-100" aria-hidden />
          now
        </span>
      </div>

      <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
        Time-window policies are evaluated per request — aggressive tiers automatically downgrade to
        standard inside business hours.
      </p>
    </section>
  );
}
