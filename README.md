# SwarmScan

Autonomous vulnerability scanner platform.

**Stack:** Next.js 16 (App Router) · TypeScript · Tailwind CSS 4 · shadcn/ui · Prisma (SQLite) · TanStack Query · Zustand · socket.io · Framer Motion

## Layout

| Path | Purpose |
|------|---------|
| `src/` | Control-plane app (views, API routes, engine clients) |
| `prisma/schema.prisma` | Data model (scans, findings, WORM evidence, policies) |
| `db/` | SQLite database (created locally, not committed) |
| `mini-services/scan-engine/` | Scan execution plane (port 3003, socket.io bus) |
| `examples/` | WebSocket reference demo |
| `public/` | Static assets |

## Setup (Node.js 20+)

```bash
cp .env.example .env
npm install
npm run db:push
npm run dev                      # control plane on :3000

cd mini-services/scan-engine
npm install
npm run dev                      # engine on :3003
```

## Usage

Only scan targets you own or are explicitly authorized to test.
