import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializePolicy, serializeScopeRule } from "@/lib/swarm/server/serialize";
import type { PoliciesResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const createPolicySchema = z.object({
  name: z.string().trim().min(1).max(120),
  kind: z.enum(["rate_limit", "payload_class", "time_window", "target_deny", "data_touching"]),
  code: z.string().min(1),
  enabled: z.boolean().optional(),
});

export async function GET() {
  const [policies, scopeRules] = await Promise.all([
    db.policy.findMany({ orderBy: { updatedAt: "desc" } }),
    db.scopeRule.findMany({ orderBy: { name: "asc" } }),
  ]);
  const body: PoliciesResponse = {
    policies: policies.map(serializePolicy),
    scopeRules: scopeRules.map(serializeScopeRule),
  };
  return NextResponse.json(body);
}

export async function POST(req: NextRequest) {
  const raw = await req.json().catch(() => null);
  const parsed = createPolicySchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid policy", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { name, kind, code, enabled } = parsed.data;

  const policy = await db.policy.create({
    data: { name, kind, code, enabled: enabled ?? true },
  });
  await db.eventLog.create({
    data: {
      type: "policy",
      message: `Policy "${name}" created (${kind})`,
    },
  });
  return NextResponse.json(serializePolicy(policy), { status: 201 });
}
