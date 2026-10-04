import { getSignedCookie, setSignedCookie, deleteCookie } from 'hono/cookie'
import { createMiddleware } from 'hono/factory'
import type { Context } from 'hono'

export const SESSION_COOKIE = 'admin_session'
export const PBKDF2_ITERATIONS = 100_000
export const MAX_PASSWORD_LENGTH = 128
const LOGIN_WINDOW_SECONDS = 15 * 60
const LOGIN_LIMIT = 5

type Env = {
  Bindings: { ADMIN_DB: D1Database; SESSION_SECRET: string; SETUP_TOKEN: string }
  Variables: { user: User; permissions: string[] }
}

export type User = { id: string; email: string; status: 'active' | 'disabled' }

const bytesToBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
const base64ToBytes = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0))

export async function hashPassword(password: string, salt = crypto.getRandomValues(new Uint8Array(16)), iterations = PBKDF2_ITERATIONS) {
  if (password.length < 12 || password.length > MAX_PASSWORD_LENGTH) throw new Error('Password length is invalid')
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256)
  return { hash: bytesToBase64(new Uint8Array(bits)), salt: bytesToBase64(salt), iterations }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i]
  return result === 0
}

export async function verifyPassword(password: string, encodedHash: string, encodedSalt: string, iterations: number) {
  try {
    if (password.length > MAX_PASSWORD_LENGTH || iterations < 10_000 || iterations > 500_000) return false
    const { hash } = await hashPassword(password, base64ToBytes(encodedSalt), iterations)
    return constantTimeEqual(base64ToBytes(hash), base64ToBytes(encodedHash))
  } catch { return false }
}

function rateKey(email: string, ip: string) { return `${email}|${ip}`.slice(0, 512) }

export async function isLoginBlocked(db: D1Database, email: string, ip: string) {
  const row = await db.prepare("SELECT attempts, window_started_at FROM login_attempts WHERE key = ? AND window_started_at > datetime('now', ?)").bind(rateKey(email, ip), `-${LOGIN_WINDOW_SECONDS} seconds`).first<{ attempts: number }>()
  return !!row && row.attempts >= LOGIN_LIMIT
}

export async function recordLoginFailure(db: D1Database, email: string, ip: string) {
  const key = rateKey(email, ip)
  await db.prepare("INSERT INTO login_attempts (key, attempts, window_started_at) VALUES (?, 1, datetime('now')) ON CONFLICT(key) DO UPDATE SET attempts = CASE WHEN window_started_at <= datetime('now', ? ) THEN 1 ELSE attempts + 1 END, window_started_at = CASE WHEN window_started_at <= datetime('now', ? ) THEN datetime('now') ELSE window_started_at END").bind(key, `-${LOGIN_WINDOW_SECONDS} seconds`, `-${LOGIN_WINDOW_SECONDS} seconds`).run()
}

export async function createSession(c: Context<Env>, user: User) {
  const id = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString()
  const ip = c.req.header('CF-Connecting-IP') ?? null
  const userAgent = c.req.header('User-Agent')?.slice(0, 512) ?? null
  await c.env.ADMIN_DB.batch([
    c.env.ADMIN_DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    c.env.ADMIN_DB.prepare('INSERT INTO sessions (id, user_id, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)').bind(id, user.id, expiresAt, ip, userAgent)
  ])
  await setSignedCookie(c, SESSION_COOKIE, id, c.env.SESSION_SECRET, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 24 * 7 })
}

export async function destroySession(c: Context<Env>) {
  const id = await getSignedCookie(c, c.env.SESSION_SECRET, SESSION_COOKIE)
  if (id) await c.env.ADMIN_DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run()
  deleteCookie(c, SESSION_COOKIE, { path: '/' })
}

export const requireAuth = createMiddleware<Env>(async (c, next) => {
  const id = await getSignedCookie(c, c.env.SESSION_SECRET, SESSION_COOKIE)
  if (!id) return c.redirect('/login')
  const row = await c.env.ADMIN_DB.prepare("SELECT u.id, u.email, u.status, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') LIMIT 1").bind(id).first<User & { expires_at: string }>()
  if (!row || row.status !== 'active') { await destroySession(c); return c.redirect('/login') }
  c.set('user', row)
  await next()
})

export const hasPermission = (permissions: string[], required: string) => {
  const [resource] = required.split(':')
  return permissions.includes('*') || permissions.includes(required) || permissions.includes(`${resource}:*`)
}

export const can = (permission: string) => createMiddleware<Env>(async (c, next) => {
  const user = c.get('user')
  const result = await c.env.ADMIN_DB.prepare('SELECT p.key FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = ?').bind(user.id).all<{ key: string }>()
  const permissions = result.results.map((row) => row.key)
  c.set('permissions', permissions)
  if (!hasPermission(permissions, permission)) return c.text('Forbidden', 403)
  await next()
})
