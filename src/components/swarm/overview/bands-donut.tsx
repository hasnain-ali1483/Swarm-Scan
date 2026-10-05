"use client";

// ─── Confidence bands donut (Overview row 2b) ────────────────────────────────

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BAND_STYLES } from "@/lib/swarm/format";
import type { ConfidenceBand } from "@/lib/swarm/types";
import { ChartTooltip } from "./severity-chart";

const BAND_HEX: Record<ConfidenceBand, string> = {
  confirmed: "#10b981",
  likely: "#f59e0b",
  suspected: "#a1a1aa",
};

const BAND_ORDER: ConfidenceBand[] = ["confirmed", "likely", "suspected"];

export function BandsDonut({ bands }: { bands: Record<ConfidenceBand, number> }) {
  const data = BAND_ORDER.map((b) => ({
    name: BAND_STYLES[b].label,
    value: bands?.[b] ?? 0,
    fill: BAND_HEX[b],
  }));
  const total = data.reduce((acc, d) => acc + d.value, 0);

  return (
    <Card className="h-full gap-3 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="text-sm">Confidence Bands</CardTitle>
        <CardDescription className="text-xs">
          Bayesian posterior classification of findings
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col px-0 pb-1">
        {total === 0 ? (
          <div className="flex h-[220px] items-center justify-center font-mono text-xs text-muted-foreground">
            no findings yet
          </div>
        ) : (
          <>
            <div className="relative mx-auto h-[180px] w-full max-w-[240px]">
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Tooltip content={<ChartTooltip />} />
                  <Pie
                    data={data}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={58}
                    outerRadius={84}
                    paddingAngle={3}
                    strokeWidth={0}
                    startAngle={90}
                    endAngle={-270}
                  >
                    {data.map((d) => (
                      <Cell key={d.name} fill={d.fill} />
                    ))}
                  </Pie>
                  <text
                    x="50%"
                    y="46%"
                    textAnchor="middle"
                    className="fill-foreground font-mono text-xl font-semibold"
                  >
                    {total}
                  </text>
                  <text
                    x="50%"
                    y="58%"
                    textAnchor="middle"
                    className="fill-zinc-500 text-[9px] uppercase tracking-widest"
                  >
                    findings
                  </text>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <ul className="mt-2 flex items-center justify-center gap-4">
              {data.map((d) => {
                const band = BAND_ORDER.find((b) => BAND_STYLES[b].label === d.name)!;
                return (
                  <li
                    key={d.name}
                    className="flex items-center gap-1.5"
                    title={BAND_STYLES[band].hint}
                  >
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ background: d.fill }}
                      aria-hidden
                    />
                    <span className="text-[11px] text-zinc-400">{d.name}</span>
                    <span className="font-mono text-[11px] font-semibold text-zinc-200">
                      {d.value}
                    </span>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}
