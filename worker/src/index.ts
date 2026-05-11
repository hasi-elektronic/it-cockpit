/**
 * Hasi IT-Cockpit — Cloudflare Worker API v0.1
 * Endpoints:
 *  POST /api/auth/login
 *  GET  /api/stats
 *  GET  /api/devices             (filter ?status=active)
 *  POST /api/devices             (create single)
 *  POST /api/devices/bulk-import (CSV batch)
 *  DELETE /api/devices/:id
 *  GET  /api/licenses
 *  POST /api/licenses
 *  DELETE /api/licenses/:id
 *  GET  /health
 */

export interface Env {
  DB: D1Database;
  PW_SALT: string;       // wrangler secret put PW_SALT
  TOKEN_SECRET: string;  // wrangler secret put TOKEN_SECRET
}

interface Session {
  token: string;
  tenant_id: number;
  tenant_slug: string;
  tenant_name: string;
  plan: string;
  user_id: number;
  user_email: string;
  role: string;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '86400',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

function json(body: any, status = 200, extra: Record<string,string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...SECURITY_HEADERS, ...extra }
  });
}

function jsonError(message: string, status = 400) {
  return json({ error: message }, status);
}

// ---------- Crypto ----------
async function hashPassword(password: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100_000, hash: 'SHA-256' },
    keyMat, 256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function makeToken(secret: string, payload: object): Promise<string> {
  const body = btoa(JSON.stringify(payload));
  const sigData = new TextEncoder().encode(body + '|' + secret);
  const sigBuf = await crypto.subtle.digest('SHA-256', sigData);
  const sig = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2,'0')).join('');
  return body + '.' + sig.slice(0, 32);
}

async function verifyToken(secret: string, token: string): Promise<any | null> {
  try {
    const [body, sig] = token.split('.');
    const sigData = new TextEncoder().encode(body + '|' + secret);
    const sigBuf = await crypto.subtle.digest('SHA-256', sigData);
    const expected = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 32);
    if (sig !== expected) return null;
    return JSON.parse(atob(body));
  } catch { return null; }
}

async function authenticate(req: Request, env: Env): Promise<Session | null> {
  const auth = req.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;
  const payload = await verifyToken(env.TOKEN_SECRET, auth.slice(7));
  if (!payload) return null;
  if (payload.exp < Date.now()) return null;
  return payload as Session;
}

async function logAudit(env: Env, sess: Session, action: string, entity: string, entityId: number|null, details: any) {
  try {
    await env.DB.prepare(
      'INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, details) VALUES (?,?,?,?,?,?)'
    ).bind(sess.tenant_id, sess.user_id, action, entity, entityId, JSON.stringify(details)).run();
  } catch(e) { console.error('Audit fail:', e); }
}

// ---------- Routes ----------

async function handleLogin(req: Request, env: Env): Promise<Response> {
  const { tenant, email, password } = await req.json<any>();
  if (!tenant || !email || !password) return jsonError('tenant, email, password erforderlich');

  const t = await env.DB.prepare('SELECT id, slug, name, plan FROM tenants WHERE slug = ? AND status = ?')
    .bind(tenant, 'active').first<any>();
  if (!t) return jsonError('Tenant nicht gefunden', 401);

  const u = await env.DB.prepare('SELECT id, email, role, pw_hash, pw_salt, active FROM users WHERE tenant_id = ? AND email = ?')
    .bind(t.id, email).first<any>();
  if (!u || !u.active) return jsonError('Login fehlgeschlagen', 401);

  const hashCheck = await hashPassword(password, u.pw_salt || env.PW_SALT);
  if (hashCheck !== u.pw_hash) return jsonError('Login fehlgeschlagen', 401);

  await env.DB.prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?').bind(u.id).run();

  const session: Session = {
    token: '',
    tenant_id: t.id, tenant_slug: t.slug, tenant_name: t.name, plan: t.plan,
    user_id: u.id, user_email: u.email, role: u.role
  };
  const tokenPayload = { ...session, exp: Date.now() + 8 * 3600 * 1000 }; // 8h
  session.token = await makeToken(env.TOKEN_SECRET, tokenPayload);

  await logAudit(env, session, 'login', 'session', null, { ip: req.headers.get('CF-Connecting-IP') });

  return json(session);
}

async function handleStats(req: Request, env: Env, sess: Session): Promise<Response> {
  const d = await env.DB.prepare(
    "SELECT COUNT(*) as total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active, " +
    "SUM(CASE WHEN warranty_until IS NOT NULL AND warranty_until < date('now','+60 days') AND warranty_until >= date('now') THEN 1 ELSE 0 END) as warranty_warn " +
    "FROM devices WHERE tenant_id = ?"
  ).bind(sess.tenant_id).first<any>();

  const l = await env.DB.prepare(
    "SELECT COUNT(*) as total, COALESCE(SUM(seats_total),0) as seats, COALESCE(SUM(cost_per_year),0) as cost " +
    "FROM licenses WHERE tenant_id = ?"
  ).bind(sess.tenant_id).first<any>();

  return json({
    devices_total: d?.total || 0,
    devices_active: d?.active || 0,
    warranty_warning: d?.warranty_warn || 0,
    licenses_total: l?.total || 0,
    licenses_seats: l?.seats || 0,
    license_cost_yearly: Math.round(l?.cost || 0)
  });
}

async function handleDevicesList(req: Request, env: Env, sess: Session): Promise<Response> {
  const url = new URL(req.url);
  const status = url.searchParams.get('status');
  let sql = `SELECT d.*, u.email as assigned_user FROM devices d
             LEFT JOIN users u ON u.id = d.assigned_to
             WHERE d.tenant_id = ?`;
  const args: any[] = [sess.tenant_id];
  if (status) { sql += ' AND d.status = ?'; args.push(status); }
  sql += ' ORDER BY d.hostname';
  const res = await env.DB.prepare(sql).bind(...args).all();
  return json({ items: res.results });
}

async function handleDeviceCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  if (!body.hostname) return jsonError('hostname erforderlich');

  const r = await env.DB.prepare(
    `INSERT INTO devices (tenant_id, hostname, device_type, manufacturer, model, serial_number, os, location, warranty_until, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.tenant_id, body.hostname, body.device_type || 'desktop',
    body.manufacturer || null, body.model || null, body.serial_number || null,
    body.os || null, body.location || null, body.warranty_until || null,
    body.status || 'active', body.notes || null
  ).run();

  await logAudit(env, sess, 'create', 'device', r.meta.last_row_id as number, body);
  return json({ id: r.meta.last_row_id, ok: true });
}

async function handleBulkImport(req: Request, env: Env, sess: Session): Promise<Response> {
  const { devices } = await req.json<any>();
  if (!Array.isArray(devices)) return jsonError('devices array erforderlich');

  let imported = 0, skipped = 0;
  for (const d of devices) {
    if (!d.hostname) { skipped++; continue; }
    try {
      // Lookup assigned user by email
      let assignedId: number | null = null;
      if (d.assigned_email) {
        const u = await env.DB.prepare('SELECT id FROM users WHERE tenant_id = ? AND email = ?')
          .bind(sess.tenant_id, d.assigned_email).first<any>();
        assignedId = u?.id || null;
      }
      await env.DB.prepare(
        `INSERT INTO devices (tenant_id, hostname, device_type, manufacturer, model, serial_number, os, location, assigned_to, warranty_until, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id, hostname) DO UPDATE SET
           device_type=excluded.device_type, manufacturer=excluded.manufacturer, model=excluded.model,
           serial_number=excluded.serial_number, os=excluded.os, location=excluded.location,
           assigned_to=excluded.assigned_to, warranty_until=excluded.warranty_until, status=excluded.status,
           updated_at=datetime('now')`
      ).bind(
        sess.tenant_id, d.hostname, d.device_type || 'desktop',
        d.manufacturer || null, d.model || null, d.serial_number || null,
        d.os || null, d.location || null, assignedId,
        d.warranty_until || null, d.status || 'active'
      ).run();
      imported++;
    } catch(e) { console.error('Import row fail:', d.hostname, e); skipped++; }
  }

  await logAudit(env, sess, 'import', 'device', null, { imported, skipped, total: devices.length });
  return json({ imported, skipped, total: devices.length });
}

async function handleDeviceDelete(id: number, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare('DELETE FROM devices WHERE id = ? AND tenant_id = ?')
    .bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Gerät nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'device', id, {});
  return json({ ok: true });
}

async function handleLicensesList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    'SELECT * FROM licenses WHERE tenant_id = ? ORDER BY software_name'
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

async function handleLicenseCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  if (!body.software_name) return jsonError('software_name erforderlich');
  const r = await env.DB.prepare(
    `INSERT INTO licenses (tenant_id, software_name, vendor, license_type, license_key, seats_total, cost_per_year, expires_at, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.tenant_id, body.software_name, body.vendor || null,
    body.license_type || 'subscription', body.license_key || null,
    body.seats_total || 1, body.cost_per_year || null,
    body.expires_at || null, body.notes || null
  ).run();
  await logAudit(env, sess, 'create', 'license', r.meta.last_row_id as number, body);
  return json({ id: r.meta.last_row_id, ok: true });
}

async function handleLicenseDelete(id: number, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare('DELETE FROM licenses WHERE id = ? AND tenant_id = ?')
    .bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Lizenz nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'license', id, {});
  return json({ ok: true });
}

// ---------- Main fetch handler ----------
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    const url = new URL(req.url);
    const path = url.pathname;

    try {
      if (path === '/health') return json({ status: 'ok', version: '0.1.0', time: new Date().toISOString() });

      if (path === '/api/auth/login' && req.method === 'POST') return handleLogin(req, env);

      // All other endpoints require auth
      const sess = await authenticate(req, env);
      if (!sess) return jsonError('Unauthorized', 401);

      if (path === '/api/stats') return handleStats(req, env, sess);

      if (path === '/api/devices' && req.method === 'GET') return handleDevicesList(req, env, sess);
      if (path === '/api/devices' && req.method === 'POST') return handleDeviceCreate(req, env, sess);
      if (path === '/api/devices/bulk-import' && req.method === 'POST') return handleBulkImport(req, env, sess);
      const devMatch = path.match(/^\/api\/devices\/(\d+)$/);
      if (devMatch && req.method === 'DELETE') return handleDeviceDelete(Number(devMatch[1]), env, sess);

      if (path === '/api/licenses' && req.method === 'GET') return handleLicensesList(req, env, sess);
      if (path === '/api/licenses' && req.method === 'POST') return handleLicenseCreate(req, env, sess);
      const licMatch = path.match(/^\/api\/licenses\/(\d+)$/);
      if (licMatch && req.method === 'DELETE') return handleLicenseDelete(Number(licMatch[1]), env, sess);

      return jsonError('Not Found', 404);
    } catch(e: any) {
      console.error(e);
      return jsonError(e.message || 'Internal error', 500);
    }
  }
};
