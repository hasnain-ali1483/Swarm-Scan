// ─── Access control — server data layer (Task 9-b) ──────────────────────────
// RBAC users/sessions, SSO connections (SAML/OIDC/SCIM) and scoped API keys.
// Seedless: the directory starts empty and fills only from real operator
// actions. Every mutation writes an EventLog row (type "access") so the audit
// trail shows up on the Overview feed.

import { db } from "@/lib/db";
import { PERMISSION_CATALOG } from "@/lib/swarm/access-roles";
import type {
  AccessResponse,
  AccessAction,
  AccessMutationResponse,
  AccessRole,
  AccessSessionItem,
  AccessUser,
  ApiKeyItem,
  SsoConnectionItem,
} from "@/lib/swarm/types";

/**
 * Seedless: the access directory starts EMPTY and fills only from real
 * operator actions (API-key creation, SSO provisioning/SCIM, real sign-ins).
 * The former demo bootstrap (9 synthetic users / 4 SSO / 3 keys) was removed —
 * no fabricated identities are injected. Kept as a no-op so getAccess() can
 * call it unconditionally.
 */
export async function bootstrapAccess(): Promise<void> {
  return;
}

// ─── Serialization ───────────────────────────────────────────────────────────

function toUser(u: {
  id: string;
  email: string;
  name: string;
  role: string;
  team: string;
  status: string;
  mfa: boolean;
  provider: string;
  lastLoginAt: Date | null;
  createdAt: Date;
}): AccessUser {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role as AccessRole,
    team: u.team,
    status: u.status === "suspended" ? "suspended" : "active",
    mfa: u.mfa,
    provider: u.provider,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
  };
}

function toSession(s: {
  id: string;
  ip: string;
  ua: string;
  location: string;
  method: string;
  startedAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  user: {
    name: string;
    email: string;
    role: string;
  };
}): AccessSessionItem {
  return {
    id: s.id,
    userName: s.user.name,
    userEmail: s.user.email,
    role: s.user.role as AccessRole,
    ip: s.ip,
    ua: s.ua,
    location: s.location,
    method: s.method,
    startedAt: s.startedAt.toISOString(),
    lastSeenAt: s.lastSeenAt.toISOString(),
    expiresAt: s.expiresAt.toISOString(),
  };
}

function toKey(k: {
  id: string;
  label: string;
  prefix: string;
  scopes: string;
  createdBy: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}): ApiKeyItem {
  return {
    id: k.id,
    label: k.label,
    prefix: k.prefix,
    scopes: k.scopes.split(",").filter(Boolean),
    createdBy: k.createdBy,
    createdAt: k.createdAt.toISOString(),
    lastUsedAt: k.lastUsedAt?.toISOString() ?? null,
    revokedAt: k.revokedAt?.toISOString() ?? null,
  };
}

function toSso(s: {
  id: string;
  kind: string;
  name: string;
  status: string;
  domain: string;
  detail: string;
  userCount: number;
  lastSyncAt: Date | null;
}): SsoConnectionItem {
  return {
    id: s.id,
    kind: s.kind === "oidc" ? "oidc" : s.kind === "scim" ? "scim" : "saml",
    name: s.name,
    status: s.status === "pending" ? "pending" : s.status === "disabled" ? "disabled" : "connected",
    domain: s.domain,
    detail: s.detail,
    userCount: s.userCount,
    lastSyncAt: s.lastSyncAt?.toISOString() ?? null,
  };
}

// ─── Reads ───────────────────────────────────────────────────────────────────

export async function getAccess(): Promise<AccessResponse> {
  await bootstrapAccess();

  const [userRows, sessionRows, keyRows, ssoRows] = await Promise.all([
    db.accessUser.findMany({ orderBy: [{ status: "desc" }, { lastLoginAt: "desc" }] }),
    db.accessSession.findMany({
      where: { expiresAt: { gt: new Date() } },
      include: { user: true },
      orderBy: { lastSeenAt: "desc" },
    }),
    db.apiKey.findMany({ orderBy: { createdAt: "desc" } }),
    db.ssoConnection.findMany({ orderBy: [{ status: "desc" }, { userCount: "desc" }] }),
  ]);

  const users = userRows.map(toUser);
  const active = users.filter((u) => u.status === "active");
  const mfaCoverage = users.length ? Math.round((active.filter((u) => u.mfa).length / users.length) * 1000) / 10 : 0;
  const ssoCoverage = users.length
    ? Math.round((users.filter((u) => u.provider !== "local").length / users.length) * 1000) / 10
    : 0;

  return {
    users,
    sessions: sessionRows.map(toSession),
    apiKeys: keyRows.map(toKey),
    sso: ssoRows.map(toSso),
    permissions: PERMISSION_CATALOG.map(({ group: _group, ...row }) => row),
    stats: {
      users: users.length,
      activeSessions: sessionRows.length,
      mfaCoverage,
      ssoCoverage,
      activeKeys: keyRows.filter((k) => !k.revokedAt).length,
    },
  };
}

// ─── Mutations (each writes an audit event) ──────────────────────────────────

const audit = async (message: string, meta?: Record<string, unknown>) =>
  db.eventLog.create({
    data: { type: "access", message, meta: meta ? JSON.stringify(meta) : null },
  });

const ROLES: AccessRole[] = ["owner", "admin", "operator", "auditor", "viewer"];

/** Generate a display-only key secret fragment (full secret is returned once, never stored). */
function generateSecret(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return `ssk_live_${out}`;
}

export async function applyAccessAction(action: AccessAction): Promise<AccessMutationResponse> {
  switch (action.action) {
    case "user.role": {
      if (!ROLES.includes(action.role)) throw new Error(`Invalid role: ${action.role}`);
      const user = await db.accessUser.findUnique({ where: { id: action.id } });
      if (!user) throw new Error("User not found");
      if (user.role === action.role) return { ok: true, message: `${user.email} already ${action.role}` };
      // Owner role confers the destructive-oracle class — only an Owner may grant
      // or revoke it. Admin (and below) cannot mint or remove Owners, so they can
      // never confer destructive-oracle authority indirectly.
      if ((action.role === "owner" || user.role === "owner") && action.actor !== "owner") {
        throw new Error(
          "Only an Owner can grant or revoke the Owner role — Admin cannot confer destructive-oracle authority"
        );
      }
      if (user.role === "owner") {
        const owners = await db.accessUser.count({ where: { role: "owner", status: "active" } });
        if (owners <= 1) throw new Error("Cannot demote the last active owner");
      }
      await db.accessUser.update({ where: { id: action.id }, data: { role: action.role } });
      await audit(`Role changed ${user.role} → ${action.role} for ${user.email}`, { userId: user.id });
      return { ok: true, message: `${user.email} is now ${action.role}` };
    }

    case "user.status": {
      const user = await db.accessUser.findUnique({ where: { id: action.id } });
      if (!user) throw new Error("User not found");
      if (user.role === "owner" && action.status === "suspended") {
        const owners = await db.accessUser.count({ where: { role: "owner", status: "active" } });
        if (owners <= 1) throw new Error("Cannot suspend the last active owner");
      }
      await db.accessUser.update({ where: { id: action.id }, data: { status: action.status } });
      if (action.status === "suspended") {
        // Deprovision sessions immediately (SCIM-style disable semantics)
        await db.accessSession.deleteMany({ where: { userId: action.id } });
      }
      await audit(`User ${user.email} ${action.status === "suspended" ? "suspended — sessions revoked" : "reactivated"}`, {
        userId: user.id,
      });
      return {
        ok: true,
        message:
          action.status === "suspended"
            ? `${user.email} suspended — ${"all sessions revoked"}`
            : `${user.email} reactivated`,
      };
    }

    case "session.revoke": {
      const session = await db.accessSession.findUnique({ where: { id: action.id }, include: { user: true } });
      if (!session) throw new Error("Session not found");
      await db.accessSession.delete({ where: { id: action.id } });
      await audit(`Session revoked for ${session.user.email} (${session.ip})`, { sessionId: action.id });
      return { ok: true, message: `Session for ${session.user.email} revoked` };
    }

    case "key.create": {
      const label = action.label.trim();
      if (label.length < 3) throw new Error("Key label must be at least 3 characters");
      if (action.scopes.length === 0) throw new Error("Select at least one scope");
      const secret = generateSecret();
      const row = await db.apiKey.create({
        data: {
          label,
          prefix: `${secret.slice(0, 12)}…`,
          scopes: action.scopes.join(","),
          createdBy: "maya.chen@swarmscan.io", // acting owner
          lastUsedAt: null,
          revokedAt: null,
        },
      });
      await audit(`API key created — "${label}" (${action.scopes.join(", ")})`, { keyId: row.id });
      return { ok: true, message: `API key "${label}" created — secret shown once`, key: { id: row.id, secret, label } };
    }

    case "key.revoke": {
      const key = await db.apiKey.findUnique({ where: { id: action.id } });
      if (!key) throw new Error("Key not found");
      if (key.revokedAt) return { ok: true, message: `Key "${key.label}" already revoked` };
      await db.apiKey.update({ where: { id: action.id }, data: { revokedAt: new Date() } });
      await audit(`API key revoked — "${key.label}"`, { keyId: key.id });
      return { ok: true, message: `API key "${key.label}" revoked` };
    }

    case "sso.status": {
      const conn = await db.ssoConnection.findUnique({ where: { id: action.id } });
      if (!conn) throw new Error("SSO connection not found");
      if (conn.status === action.status) return { ok: true, message: `${conn.name} already ${action.status}` };
      await db.ssoConnection.update({ where: { id: action.id }, data: { status: action.status } });
      await audit(`SSO connection ${conn.name} → ${action.status}`, { ssoId: conn.id });
      return {
        ok: true,
        message:
          action.status === "disabled"
            ? `${conn.name} disabled — logins via ${conn.domain} will be rejected`
            : `${conn.name} set to ${action.status}`,
      };
    }

    default:
      throw new Error("Unknown action");
  }
}
