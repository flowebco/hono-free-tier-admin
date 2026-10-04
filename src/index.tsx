import { Hono } from 'hono'
import { html } from 'hono/html'
import { secureHeaders } from 'hono/secure-headers'
import { hashPassword, verifyPassword, createSession, destroySession, requireAuth, can, isLoginBlocked, recordLoginFailure, MAX_PASSWORD_LENGTH } from './auth'

type Bindings = { ADMIN_DB: D1Database; SESSION_SECRET: string; SETUP_TOKEN: string }
const app = new Hono<{ Bindings: Bindings }>()
app.use('*', secureHeaders())
app.use('*', async (c, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method)) {
    const origin = c.req.header('Origin')
    if (!origin || origin !== new URL(c.req.url).origin) return c.text('Invalid request origin', 403)
  }
  await next()
})

app.get('/', (c) => c.html(page('Hono Admin', `<p class="eyebrow">HONO FREE-TIER ADMIN</p><h1>Admin panel foundation</h1><p class="lede">Hono-only UI, Cloudflare Workers Free constraints, and D1-ready RBAC.</p><a class="button" href="/login">Sign in</a>`)))
app.get('/health', (c) => c.json({ ok: true, service: 'hono-free-tier-admin' }))

app.get('/login', (c) => c.html(page('Login', `<p class="eyebrow">HONO ADMIN</p><h1>Sign in</h1><form method="post"><label>Email<input name="email" type="email" maxlength="320" autocomplete="username" required /></label><label>Password<input name="password" type="password" maxlength="${MAX_PASSWORD_LENGTH}" autocomplete="current-password" required /></label><button class="button" type="submit">Sign in</button></form>`)))
app.post('/login', async (c) => {
  const form = await c.req.parseBody()
  const email = String(form.email ?? '').trim().toLowerCase().slice(0, 320)
  const password = String(form.password ?? '')
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown'
  if (await isLoginBlocked(c.env.ADMIN_DB, email, ip)) return c.html(page('Login', `<p class="error">Too many attempts. Try again later.</p>`), 429)
  const row = await c.env.ADMIN_DB.prepare('SELECT id, email, status, password_hash, password_salt, password_iterations FROM users WHERE email = ? LIMIT 1').bind(email).first<{ id: string; email: string; status: 'active' | 'disabled'; password_hash: string; password_salt: string; password_iterations: number }>()
  const valid = row && row.status === 'active' && await verifyPassword(password, row.password_hash, row.password_salt, row.password_iterations)
  if (!valid) { await recordLoginFailure(c.env.ADMIN_DB, email, ip); return c.html(page('Login', `<p class="error">Invalid email or password.</p><a href="/login">Try again</a>`), 401) }
  await createSession(c, row)
  await c.env.ADMIN_DB.batch([
    c.env.ADMIN_DB.prepare('DELETE FROM login_attempts WHERE key = ?').bind(`${email}|${ip}`.slice(0, 512)),
    c.env.ADMIN_DB.prepare('INSERT INTO audit_log (id, user_id, action, target) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), row.id, 'auth.login', row.id)
  ])
  return c.redirect('/admin', 303)
})

app.post('/logout', async (c) => { await destroySession(c); return c.redirect('/login', 303) })

app.get('/setup', async (c) => {
  const count = await c.env.ADMIN_DB.prepare('SELECT COUNT(*) as count FROM users').first<{ count: number }>()
  if (count?.count) return c.text('Setup is already complete', 409)
  return c.html(page('Initial setup', `<p class="eyebrow">ONE-TIME SETUP</p><h1>Create owner</h1><form method="post"><label>Setup token<input name="token" type="password" required /></label><label>Email<input name="email" type="email" maxlength="320" required /></label><label>Password<input name="password" type="password" minlength="12" maxlength="${MAX_PASSWORD_LENGTH}" required /></label><button class="button" type="submit">Create owner</button></form>`))
})
app.post('/setup', async (c) => {
  const count = await c.env.ADMIN_DB.prepare('SELECT COUNT(*) as count FROM users').first<{ count: number }>()
  const form = await c.req.parseBody()
  if (count?.count || String(form.token ?? '') !== c.env.SETUP_TOKEN) return c.text('Not found', 404)
  const email = String(form.email ?? '').trim().toLowerCase().slice(0, 320); const password = String(form.password ?? '')
  if (!email || password.length < 12 || password.length > MAX_PASSWORD_LENGTH) return c.text('Email and a 12-128 character password are required', 400)
  const hashed = await hashPassword(password)
  const userId = crypto.randomUUID()
  await c.env.ADMIN_DB.batch([
    c.env.ADMIN_DB.prepare('INSERT INTO users (id, email, password_hash, password_salt, password_iterations) VALUES (?, ?, ?, ?, ?)').bind(userId, email, hashed.hash, hashed.salt, hashed.iterations),
    c.env.ADMIN_DB.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').bind(userId, 'role_owner'),
    c.env.ADMIN_DB.prepare('INSERT INTO audit_log (id, user_id, action, target) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), userId, 'auth.bootstrap', userId)
  ])
  await createSession(c, { id: userId, email, status: 'active' }); return c.redirect('/admin', 303)
})

app.use('/admin', requireAuth)
app.use('/admin/*', requireAuth)
app.get('/admin', can('*'), (c) => c.html(page('Dashboard', `<p class="eyebrow">SIGNED IN</p><h1>Dashboard</h1><p class="lede">${escapeHtml(c.get('user').email)}</p><form method="post" action="/logout"><button class="button" type="submit">Sign out</button></form>`)))
app.notFound((c) => c.json({ error: 'Not found' }, 404))

async function cleanupExpiredData(db: D1Database) {
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"),
    db.prepare("DELETE FROM login_attempts WHERE window_started_at <= datetime('now', '-1 day')")
  ])
}

function escapeHtml(value: string) { return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]!)) }
function page(title: string, content: string) { return html`<!doctype html><html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>${title}</title><style>${styles}</style></head><body><main class="shell">${html([content] as unknown as TemplateStringsArray)}</main></body></html>` }
const styles = `:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #101114; color: #f5f7fa; } body { margin: 0; min-height: 100vh; display: grid; place-items: center; } .shell { width: min(680px, calc(100% - 40px)); padding: 48px; border: 1px solid #2d313a; border-radius: 20px; background: #17191f; box-shadow: 0 20px 60px #0006; } .eyebrow { color: #9ea7ff; letter-spacing: .12em; font-size: .75rem; font-weight: 700; } h1 { font-size: clamp(2.2rem, 7vw, 4.5rem); line-height: .95; margin: 20px 0; } .lede { color: #b7bdc9; font-size: 1.1rem; line-height: 1.6; } label { display: grid; gap: 8px; margin: 16px 0; } input { padding: 12px; border-radius: 8px; border: 1px solid #3a3e48; background: #101114; color: inherit; } .button { display: inline-block; margin-top: 20px; padding: 12px 18px; border: 0; border-radius: 10px; background: #9ea7ff; color: #101114; text-decoration: none; font-weight: 700; cursor: pointer; } .error { color: #ff8e8e; }`

export default {
  fetch: (request: Request, env: Bindings, ctx: ExecutionContext) => app.fetch(request, env, ctx),
  scheduled: (_controller: ScheduledController, env: Bindings, ctx: ExecutionContext) => {
    ctx.waitUntil(cleanupExpiredData(env.ADMIN_DB))
  }
} satisfies ExportedHandler<Bindings>
