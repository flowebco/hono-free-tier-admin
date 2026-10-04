# Hono Free-Tier Admin

Hono-only admin panel for Cloudflare Workers Free.

## Principles

- Hono is the only application framework, including the UI.
- UI starts with Hono HTML and can use `hono/jsx` and `hono/jsx/dom` later.
- D1 stores authentication, RBAC, settings, and audit data.
- No React, Preact, Vue, Svelte, HTMX, Tailwind, Auth.js, Better Auth, Lucia, ORM, Agents SDK, or Vercel AI SDK.
- No paid-only bindings such as Worker Loader, Dynamic Workers, or Workers for Platforms.

## Setup

```sh
npm install
# Create a D1 database, then replace database_id in wrangler.jsonc
npm run db:migrate:local
# Set local secrets in .dev.vars (never commit them):
# SESSION_SECRET=use-a-long-random-secret
# SETUP_TOKEN=use-a-one-time-bootstrap-token
npm run dev
```

Open `/setup` once to create the owner, then delete or rotate `SETUP_TOKEN` before production. Before deployment, set the real D1 database ID and secrets:

```sh
wrangler secret put SESSION_SECRET
wrangler secret put SETUP_TOKEN
npm run db:migrate:remote
npm run deploy
```

Login uses PBKDF2-SHA256 with per-user salts, signed HttpOnly/Secure/SameSite cookies, D1-backed sessions, session expiry, logout revocation, and audit events. Benchmark `PBKDF2_ITERATIONS` on the deployed Free Worker before production; the 10ms CPU budget is tight.
