import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { AGENTS_CATALOG } from "@/lib/swarm/agents-catalog";
import type { AgentRegistryResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

export async function GET() {
  const [runGroups, findingGroups] = await Promise.all([
    db.agentRun.groupBy({ by: ["agentKey"], _count: { _all: true } }),
    db.finding.groupBy({ by: ["agentKey"], _count: { _all: true }, _avg: { confidence: true } }),
  ]);

  const runsByAgent = new Map(runGroups.map((g) => [g.agentKey, g._count._all]));
  const findingsByAgent = new Map(findingGroups.map((g) => [g.agentKey, g]));

  const body: AgentRegistryResponse = {
    agents: AGENTS_CATALOG.map((agent) => {
      const stats = findingsByAgent.get(agent.key);
      return {
        ...agent,
        runs: runsByAgent.get(agent.key) ?? 0,
        findings: stats?._count._all ?? 0,
        avgConfidence: Math.round((stats?._avg.confidence ?? 0) * 10) / 10,
      };
    }),
  };
  return NextResponse.json(body);
}
