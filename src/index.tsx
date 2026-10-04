import { Hono } from 'hono'
import { html } from 'hono/html'
import { secureHeaders } from 'hono/secure-headers'

type Bindings = {
  ADMIN_DB: D1Database
  ASSETS: Fetcher
}

const app = new Hono<{ Bindings: Bindings }>()
app.use('*', secureHeaders())

app.get('/', (c) => c.html(html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Hono Admin</title>
    <style>${styles}</style>
  </head>
  <body>
    <main class="shell">
      <p class="eyebrow">HONO FREE-TIER ADMIN</p>
      <h1>Admin panel foundation</h1>
      <p class="lede">Hono-only UI, Cloudflare Workers Free constraints, and D1-ready RBAC.</p>
      <a class="button" href="/health">Check health</a>
    </main>
  </body>
</html>`))

app.get('/health', (c) => c.json({ ok: true, service: 'hono-free-tier-admin' }))

app.notFound((c) => c.json({ error: 'Not found' }, 404))

const styles = `
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #101114; color: #f5f7fa; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; }
.shell { width: min(680px, calc(100% - 40px)); padding: 48px; border: 1px solid #2d313a; border-radius: 20px; background: #17191f; box-shadow: 0 20px 60px #0006; }
.eyebrow { color: #9ea7ff; letter-spacing: .12em; font-size: .75rem; font-weight: 700; }
h1 { font-size: clamp(2.2rem, 7vw, 4.5rem); line-height: .95; margin: 20px 0; }
.lede { color: #b7bdc9; font-size: 1.1rem; line-height: 1.6; }
.button { display: inline-block; margin-top: 20px; padding: 12px 18px; border-radius: 10px; background: #9ea7ff; color: #101114; text-decoration: none; font-weight: 700; }
`

export default app
