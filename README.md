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
npm run dev
```

Before deployment, set the real D1 database ID and apply the migration remotely:

```sh
npm run db:migrate:remote
npm run deploy
```

The first migration creates the users, sessions, roles, permissions, user-role, role-permission, and audit-log tables. Authentication and RBAC routes are the next implementation slice.
