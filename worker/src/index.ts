/**
 * Hasi IT-Cockpit — Cloudflare Worker API v0.1.1
 */

export interface Env {
  DB: D1Database;
  PW_SALT: string;
  TOKEN_SECRET: string;
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

function json(body: any, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...SECURITY_HEADERS }
  });
}
function jsonError(message: string, status = 400) { return json({ error: message }, status); }

async function hashPassword(password: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
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

async function logAudit(env: Env, sess: Session, action: string, entity: string, entityId: number|null, details: any, ip: string|null) {
  try {
    await env.DB.prepare(
      'INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, details, ip_address) VALUES (?,?,?,?,?,?,?)'
    ).bind(sess.tenant_id, sess.user_id, action, entity, entityId, JSON.stringify(details), ip).run();
  } catch(e) { console.error('Audit fail:', e); }
}

// ============== AUTH ==============
async function handleLogin(req: Request, env: Env): Promise<Response> {
  const { tenant, email, password } = await req.json<any>();
  if (!tenant || !email || !password) return jsonError('tenant, email, password erforderlich');

  const t = await env.DB.prepare('SELECT id, slug, name, plan FROM tenants WHERE slug = ? AND status = ?').bind(tenant, 'active').first<any>();
  if (!t) return jsonError('Tenant nicht gefunden', 401);

  const u = await env.DB.prepare('SELECT id, email, role, pw_hash, pw_salt, active FROM users WHERE tenant_id = ? AND email = ?').bind(t.id, email).first<any>();
  if (!u || !u.active) return jsonError('Login fehlgeschlagen', 401);

  const hashCheck = await hashPassword(password, u.pw_salt || env.PW_SALT);
  if (hashCheck !== u.pw_hash) return jsonError('Login fehlgeschlagen', 401);

  await env.DB.prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?').bind(u.id).run();

  const session: Session = {
    token: '', tenant_id: t.id, tenant_slug: t.slug, tenant_name: t.name, plan: t.plan,
    user_id: u.id, user_email: u.email, role: u.role
  };
  const tokenPayload = { ...session, exp: Date.now() + 8 * 3600 * 1000 };
  session.token = await makeToken(env.TOKEN_SECRET, tokenPayload);

  await logAudit(env, session, 'login', 'session', null, {}, req.headers.get('CF-Connecting-IP'));
  return json(session);
}

// ============== STATS ==============
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

  const u = await env.DB.prepare("SELECT COUNT(*) as total FROM users WHERE tenant_id = ? AND active = 1").bind(sess.tenant_id).first<any>();

  return json({
    devices_total: d?.total || 0,
    devices_active: d?.active || 0,
    warranty_warning: d?.warranty_warn || 0,
    licenses_total: l?.total || 0,
    licenses_seats: l?.seats || 0,
    license_cost_yearly: Math.round(l?.cost || 0),
    users_total: u?.total || 0
  });
}

// ============== DEVICES ==============
async function handleDevicesList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT d.*, u.email as assigned_email, u.full_name as assigned_name
     FROM devices d LEFT JOIN users u ON u.id = d.assigned_to
     WHERE d.tenant_id = ? ORDER BY d.hostname`
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

async function handleDeviceCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  if (!body.hostname) return jsonError('hostname erforderlich');

  if (body.assigned_to) {
    const owner = await env.DB.prepare('SELECT id FROM users WHERE id = ? AND tenant_id = ?').bind(body.assigned_to, sess.tenant_id).first();
    if (!owner) body.assigned_to = null;
  }

  const r = await env.DB.prepare(
    `INSERT INTO devices (tenant_id, hostname, device_type, manufacturer, model, serial_number, os, cpu, ram_gb, storage_gb, location, assigned_to, purchase_date, warranty_until, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.tenant_id, body.hostname.trim(), body.device_type || 'desktop',
    body.manufacturer || null, body.model || null, body.serial_number || null,
    body.os || null, body.cpu || null,
    body.ram_gb ? Number(body.ram_gb) : null, body.storage_gb ? Number(body.storage_gb) : null,
    body.location || null, body.assigned_to || null,
    body.purchase_date || null, body.warranty_until || null,
    body.status || 'active', body.notes || null
  ).run();

  await logAudit(env, sess, 'create', 'device', r.meta.last_row_id as number, body, req.headers.get('CF-Connecting-IP'));
  return json({ id: r.meta.last_row_id, ok: true });
}

async function handleDeviceUpdate(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  const existing = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!existing) return jsonError('Gerät nicht gefunden', 404);

  if (body.assigned_to) {
    const owner = await env.DB.prepare('SELECT id FROM users WHERE id = ? AND tenant_id = ?').bind(body.assigned_to, sess.tenant_id).first();
    if (!owner) body.assigned_to = null;
  }

  await env.DB.prepare(
    `UPDATE devices SET hostname=?, device_type=?, manufacturer=?, model=?, serial_number=?, os=?, cpu=?,
       ram_gb=?, storage_gb=?, location=?, assigned_to=?, purchase_date=?, warranty_until=?,
       status=?, notes=?, updated_at=datetime('now')
     WHERE id=? AND tenant_id=?`
  ).bind(
    body.hostname?.trim(), body.device_type || 'desktop',
    body.manufacturer || null, body.model || null, body.serial_number || null,
    body.os || null, body.cpu || null,
    body.ram_gb ? Number(body.ram_gb) : null, body.storage_gb ? Number(body.storage_gb) : null,
    body.location || null, body.assigned_to || null,
    body.purchase_date || null, body.warranty_until || null,
    body.status || 'active', body.notes || null,
    id, sess.tenant_id
  ).run();

  await logAudit(env, sess, 'update', 'device', id, body, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

async function handleBulkImport(req: Request, env: Env, sess: Session): Promise<Response> {
  const { devices } = await req.json<any>();
  if (!Array.isArray(devices)) return jsonError('devices array erforderlich');

  let imported = 0, skipped = 0;
  for (const d of devices) {
    if (!d.hostname) { skipped++; continue; }
    try {
      let assignedId: number | null = null;
      if (d.assigned_email) {
        const u = await env.DB.prepare('SELECT id FROM users WHERE tenant_id = ? AND email = ?').bind(sess.tenant_id, d.assigned_email).first<any>();
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
        sess.tenant_id, d.hostname.trim(), d.device_type || 'desktop',
        d.manufacturer || null, d.model || null, d.serial_number || null,
        d.os || null, d.location || null, assignedId,
        d.warranty_until || null, d.status || 'active'
      ).run();
      imported++;
    } catch(e) { console.error('Import row fail:', d.hostname, e); skipped++; }
  }

  await logAudit(env, sess, 'import', 'device', null, { imported, skipped, total: devices.length }, req.headers.get('CF-Connecting-IP'));
  return json({ imported, skipped, total: devices.length });
}

async function handleDeviceDelete(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare('DELETE FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Gerät nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'device', id, {}, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

// ============== LICENSES ==============
async function handleLicensesList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare('SELECT * FROM licenses WHERE tenant_id = ? ORDER BY software_name').bind(sess.tenant_id).all();
  return json({ items: res.results });
}

async function handleLicenseCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  if (!body.software_name) return jsonError('software_name erforderlich');
  const r = await env.DB.prepare(
    `INSERT INTO licenses (tenant_id, software_name, vendor, license_type, license_key, seats_total, cost_per_year, purchase_date, expires_at, renewal_auto, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.tenant_id, body.software_name.trim(), body.vendor || null,
    body.license_type || 'subscription', body.license_key || null,
    body.seats_total ? Number(body.seats_total) : 1,
    body.cost_per_year ? Number(body.cost_per_year) : null,
    body.purchase_date || null, body.expires_at || null,
    body.renewal_auto ? 1 : 0, body.notes || null
  ).run();
  await logAudit(env, sess, 'create', 'license', r.meta.last_row_id as number, body, req.headers.get('CF-Connecting-IP'));
  return json({ id: r.meta.last_row_id, ok: true });
}

async function handleLicenseUpdate(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const body = await req.json<any>();
  const existing = await env.DB.prepare('SELECT id FROM licenses WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!existing) return jsonError('Lizenz nicht gefunden', 404);

  await env.DB.prepare(
    `UPDATE licenses SET software_name=?, vendor=?, license_type=?, license_key=?, seats_total=?,
       cost_per_year=?, purchase_date=?, expires_at=?, renewal_auto=?, notes=?, updated_at=datetime('now')
     WHERE id=? AND tenant_id=?`
  ).bind(
    body.software_name?.trim(), body.vendor || null,
    body.license_type || 'subscription', body.license_key || null,
    body.seats_total ? Number(body.seats_total) : 1,
    body.cost_per_year ? Number(body.cost_per_year) : null,
    body.purchase_date || null, body.expires_at || null,
    body.renewal_auto ? 1 : 0, body.notes || null,
    id, sess.tenant_id
  ).run();
  await logAudit(env, sess, 'update', 'license', id, body, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

async function handleLicenseDelete(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare('DELETE FROM licenses WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Lizenz nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'license', id, {}, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

// ============== USERS ==============
async function handleUsersList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT u.id, u.email, u.full_name, u.department, u.role, u.active, u.last_login, u.created_at,
            (SELECT COUNT(*) FROM devices d WHERE d.assigned_to = u.id) AS device_count
     FROM users u WHERE u.tenant_id = ?
     ORDER BY u.full_name, u.email`
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

async function handleUserCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const body = await req.json<any>();
  if (!body.email) return jsonError('email erforderlich');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE tenant_id = ? AND email = ?').bind(sess.tenant_id, body.email).first();
  if (existing) return jsonError('User mit dieser Email existiert bereits', 409);

  let pwHash: string | null = null;
  let pwSalt: string | null = null;
  if (body.password && body.password.length >= 6) {
    pwSalt = env.PW_SALT;
    pwHash = await hashPassword(body.password, pwSalt);
  }

  const r = await env.DB.prepare(
    `INSERT INTO users (tenant_id, email, full_name, department, role, pw_hash, pw_salt, active)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.tenant_id, body.email.trim().toLowerCase(),
    body.full_name || null, body.department || null,
    body.role || 'user', pwHash, pwSalt,
    body.active === false ? 0 : 1
  ).run();

  await logAudit(env, sess, 'create', 'user', r.meta.last_row_id as number, { email: body.email, role: body.role }, req.headers.get('CF-Connecting-IP'));
  return json({ id: r.meta.last_row_id, ok: true });
}

async function handleUserUpdate(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const body = await req.json<any>();
  const existing = await env.DB.prepare('SELECT id FROM users WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!existing) return jsonError('User nicht gefunden', 404);

  let pwUpdate = '';
  const args: any[] = [
    body.email?.trim().toLowerCase(),
    body.full_name || null,
    body.department || null,
    body.role || 'user',
    body.active === false ? 0 : 1
  ];

  if (body.password && body.password.length >= 6) {
    const salt = env.PW_SALT;
    const hash = await hashPassword(body.password, salt);
    pwUpdate = ', pw_hash=?, pw_salt=?';
    args.push(hash, salt);
  }
  args.push(id, sess.tenant_id);

  await env.DB.prepare(
    `UPDATE users SET email=?, full_name=?, department=?, role=?, active=? ${pwUpdate} WHERE id=? AND tenant_id=?`
  ).bind(...args).run();

  await logAudit(env, sess, 'update', 'user', id, { email: body.email }, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

async function handleUserDelete(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  if (id === sess.user_id) return jsonError('Eigenes Konto nicht löschbar', 400);
  const r = await env.DB.prepare('DELETE FROM users WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('User nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'user', id, {}, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

// ============== AUDIT ==============
async function handleAuditList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT a.*, u.email AS user_email FROM audit_log a
     LEFT JOIN users u ON u.id = a.user_id
     WHERE a.tenant_id = ? ORDER BY a.created_at DESC LIMIT 100`
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

// ============== ROUTER ==============
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    const url = new URL(req.url);
    const path = url.pathname;
    const m = req.method;

    try {
      if (path === '/health') return json({ status: 'ok', version: '0.1.1', time: new Date().toISOString() });
      if (path === '/api/auth/login' && m === 'POST') return handleLogin(req, env);

      const sess = await authenticate(req, env);
      if (!sess) return jsonError('Unauthorized', 401);

      if (path === '/api/stats') return handleStats(req, env, sess);
      if (path === '/api/audit' && m === 'GET') return handleAuditList(req, env, sess);

      if (path === '/api/devices' && m === 'GET') return handleDevicesList(req, env, sess);
      if (path === '/api/devices' && m === 'POST') return handleDeviceCreate(req, env, sess);
      if (path === '/api/devices/bulk-import' && m === 'POST') return handleBulkImport(req, env, sess);
      let mt = path.match(/^\/api\/devices\/(\d+)$/);
      if (mt && m === 'PUT') return handleDeviceUpdate(Number(mt[1]), req, env, sess);
      if (mt && m === 'DELETE') return handleDeviceDelete(Number(mt[1]), req, env, sess);

      if (path === '/api/licenses' && m === 'GET') return handleLicensesList(req, env, sess);
      if (path === '/api/licenses' && m === 'POST') return handleLicenseCreate(req, env, sess);
      mt = path.match(/^\/api\/licenses\/(\d+)$/);
      if (mt && m === 'PUT') return handleLicenseUpdate(Number(mt[1]), req, env, sess);
      if (mt && m === 'DELETE') return handleLicenseDelete(Number(mt[1]), req, env, sess);

      if (path === '/api/users' && m === 'GET') return handleUsersList(req, env, sess);
      if (path === '/api/users' && m === 'POST') return handleUserCreate(req, env, sess);
      mt = path.match(/^\/api\/users\/(\d+)$/);
      if (mt && m === 'PUT') return handleUserUpdate(Number(mt[1]), req, env, sess);
      if (mt && m === 'DELETE') return handleUserDelete(Number(mt[1]), req, env, sess);

      return jsonError('Not Found', 404);
    } catch(e: any) {
      console.error(e);
      return jsonError(e.message || 'Internal error', 500);
    }
  }
};
