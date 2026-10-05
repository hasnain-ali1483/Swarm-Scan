"use client";

// ─── Severity distribution bar chart (Overview row 2a) ───────────────────────

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_STYLES } from "@/lib/swarm/format";
import { SEVERITY_ORDER, type Severity } from "@/lib/swarm/types";

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#eab308",
  info: "#a1a1aa",
};

/** Dark, minimal recharts tooltip shared by the overview charts. */
export function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: ReadonlyArray<{
    name?: string | number;
    value?: string | number;
    payload?: { fill?: string };
  }>;
  label?: string | number;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow-lg">
      {label !== undefined && label !== "" && (
        <div className="mb-0.5 text-muted-foreground">{label}</div>
      )}
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 font-mono">
          <span
            className="h-2 w-2 rounded-full"
            style={{ background: entry.payload?.fill ?? "#a1a1aa" }}
            aria-hidden
          />
          <span className="text-zinc-400">{entry.name}</span>
          <span className="font-semibold text-foreground">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export function SeverityChart({ severity }: { severity: Record<Severity, number> }) {
  const data = SEVERITY_ORDER.map((s) => ({
    label: SEVERITY_STYLES[s].label,
    count: severity?.[s] ?? 0,
    fill: SEVERITY_HEX[s],
  }));
  const total = data.reduce((acc, d) => acc + d.count, 0);

  return (
    <Card className="h-full gap-3 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="text-sm">Severity Distribution</CardTitle>
        <CardDescription className="text-xs">
          Findings by severity class · total {total}
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0 pb-1">
        {total === 0 ? (
          <div className="flex h-[220px] items-center justify-center font-mono text-xs text-muted-foreground">
            no findings yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart
              layout="vertical"
              data={data}
              margin={{ top: 4, right: 12, bottom: 4, left: 4 }}
              barCategoryGap="30%"
            >
              <CartesianGrid horizontal={false} stroke="#27272a" strokeDasharray="3 3" />
              <XAxis
                type="number"
                allowDecimals={false}
                tick={{ fill: "#71717a", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                type="category"
                dataKey="label"
                width={60}
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
              <Bar dataKey="count" name="findings" radius={[0, 4, 4, 0]} barSize={16}>
                {data.map((d) => (
                  <Cell key={d.label} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
