import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { serializeScopeRule } from "@/lib/swarm/server/serialize";
import { scopeRuleSchema } from "@/lib/swarm/server/validators";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  const raw = await req.json().catch(() => null);
  const parsed = scopeRuleSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid scope rule", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { name, cidrs, mode, enforced } = parsed.data;
  const rule = await db.scopeRule.create({
    data: { name, cidrs: JSON.stringify(cidrs), mode, enforced },
  });
  return NextResponse.json(serializeScopeRule(rule), { status: 201 });
}
