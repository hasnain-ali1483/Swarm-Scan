"use client";

// ─── Access Control view — 14th view (Task 9-b) ──────────────────────────────
// RBAC directory + permission matrix + SSO connections (SAML/OIDC/SCIM) +
// live sessions + scoped API keys + the "acting as" role simulator that
// re-gates the global Kill Switch and New Scan wizard platform-wide.

import { motion } from "framer-motion";
import { Fingerprint, Globe2, KeyRound, ShieldCheck, Users2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ErrorState } from "@/components/swarm/findings/states";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import type { AccessRole } from "@/lib/swarm/types";
import { ApiKeysSection } from "@/components/swarm/access/api-keys-section";
import { RoleMatrix } from "@/components/swarm/access/role-matrix";
import { RoleSimulator } from "@/components/swarm/access/role-simulator";
import { SessionsSection } from "@/components/swarm/access/sessions-section";
import { SsoSection } from "@/components/swarm/access/sso-section";
import { UsersSection } from "@/components/swarm/access/users-section";
import { useAccess } from "@/components/swarm/access/use-access";

function KpiStrip({
  stats,
}: {
  stats: { users: number; activeSessions: number; mfaCoverage: number; ssoCoverage: number; activeKeys: number };
}) {
  const items = [
    { icon: Users2, label: "members", value: String(stats.users), tone: "text-primary" },
    { icon: Globe2, label: "active sessions", value: String(stats.activeSessions), tone: "text-teal-300" },
    { icon: ShieldCheck, label: "MFA coverage", value: `${stats.mfaCoverage}%`, tone: stats.mfaCoverage >= 80 ? "text-emerald-400" : "text-amber-400" },
    { icon: Fingerprint, label: "SSO coverage", value: `${stats.ssoCoverage}%`, tone: "text-violet-300" },
    { icon: KeyRound, label: "active keys", value: String(stats.activeKeys), tone: "text-zinc-300" },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      {items.map((it, i) => {
        const Icon = it.icon;
        return (
          <motion.div
            key={it.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, duration: 0.25 }}
            className="flex h-[62px] items-center gap-3 rounded-lg border bg-card/60 px-3.5"
          >
            <Icon className={`h-4.5 w-4.5 shrink-0 ${it.tone}`} aria-hidden />
            <div className="min-w-0 flex flex-col justify-center gap-0.5">
              <div className={`font-mono text-lg leading-none font-semibold tabular-nums ${it.tone}`}>{it.value}</div>
              <div className="truncate text-[10px] uppercase tracking-wider leading-none text-muted-foreground">
                {it.label}
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}

export function AccessView() {
  const { data, isLoading, error, refetch, isFetching } = useAccess();
  const actingRole = useSwarmUi((s) => s.actingRole) as AccessRole;

  if (error) {
    return (
      <div className="p-4 sm:p-6">
        <ErrorState message={error instanceof Error ? error.message : undefined} onRetry={() => void refetch()} retrying={isFetching} />
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-wrap items-center justify-between gap-3"
      >
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint className="h-4.5 w-4.5 text-primary" aria-hidden />
            <h2 className="text-lg font-semibold tracking-tight">Enterprise access control</h2>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            RBAC · SSO (SAML / OIDC / SCIM) · session management · scoped API keys — every change
            lands in the audit event log.
          </p>
        </div>
      </motion.div>

      {isLoading || !data ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-16" />
            ))}
          </div>
          <Skeleton className="h-64" />
        </div>
      ) : (
        <div className="space-y-6">
          <KpiStrip stats={data.stats} />

          <Tabs defaultValue="directory" className="gap-4">
            <TabsList className="h-auto max-w-full flex-wrap justify-start sm:h-9 sm:flex-nowrap">
              <TabsTrigger value="directory" className="text-xs gap-1.5">
                <Users2 className="h-3.5 w-3.5" aria-hidden />
                Directory
              </TabsTrigger>
              <TabsTrigger value="sso" className="text-xs gap-1.5">
                <Fingerprint className="h-3.5 w-3.5" aria-hidden />
                SSO &amp; SCIM
              </TabsTrigger>
              <TabsTrigger value="sessions" className="text-xs gap-1.5">
                <Globe2 className="h-3.5 w-3.5" aria-hidden />
                Sessions
              </TabsTrigger>
              <TabsTrigger value="keys" className="text-xs gap-1.5">
                <KeyRound className="h-3.5 w-3.5" aria-hidden />
                API keys
              </TabsTrigger>
            </TabsList>

            <TabsContent value="directory" className="space-y-4 mt-0">
              <Card className="border-border/80 bg-card/40">
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center justify-between gap-2 text-sm">
                    <span className="flex items-center gap-2">
                      <Users2 className="h-4 w-4 text-primary" aria-hidden />
                      Members
                    </span>
                    <span className="text-[11px] font-normal text-muted-foreground">
                      {data.stats.users} members · {data.stats.mfaCoverage}% MFA
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pb-4">
                  <UsersSection data={data} />
                </CardContent>
              </Card>

              <Card className="border-border/80 bg-card/40">
                <CardHeader className="pb-3">
                  <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
                    <span className="flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-primary" aria-hidden />
                      Permission matrix
                    </span>
                    <span className="text-[11px] font-normal text-muted-foreground">
                      acting-role column highlighted · grants enforced at the API route level
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pb-4">
                  <RoleMatrix actingRole={actingRole} />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="sso" className="mt-0">
              <Card className="border-border/80 bg-card/40">
                <CardHeader className="pb-3">
                  <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
                    <span className="flex items-center gap-2">
                      <Fingerprint className="h-4 w-4 text-primary" aria-hidden />
                      Identity providers
                    </span>
                    <span className="text-[11px] font-normal text-muted-foreground">
                      disabling an IdP rejects new logins instantly — sessions stay until revoked
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pb-4">
                  <SsoSection connections={data.sso} />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="sessions" className="mt-0">
              <Card className="border-border/80 bg-card/40">
                <CardHeader className="pb-3">
                  <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
                    <span className="flex items-center gap-2">
                      <Globe2 className="h-4 w-4 text-primary" aria-hidden />
                      Active sessions
                    </span>
                    <span className="text-[11px] font-normal text-muted-foreground">
                      {data.sessions.length} live · revocation is immediate
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pb-4">
                  <SessionsSection sessions={data.sessions} />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="keys" className="mt-0">
              <Card className="border-border/80 bg-card/40">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <KeyRound className="h-4 w-4 text-primary" aria-hidden />
                    API keys
                  </CardTitle>
                </CardHeader>
                <CardContent className="pb-4">
                  <ApiKeysSection keys={data.apiKeys} />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          <Card className="border-primary/25 bg-gradient-to-br from-primary/[0.05] to-transparent">
            <CardHeader className="pb-3">
              <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" aria-hidden />
                  Role simulator — live enforcement
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">useSwarmUi.actingRole</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-4">
              <RoleSimulator />
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
