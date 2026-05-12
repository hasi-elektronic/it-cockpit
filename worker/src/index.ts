/**
 * Hasi IT-Cockpit — Cloudflare Worker API v0.3
 * Adds: alert evaluator (cron), Telegram notifications, alert management endpoints
 */

import { evaluateAlerts, sendTestTelegram } from './alerts';

export interface Env {
  DB: D1Database;
  AGENTS: R2Bucket;
  PW_SALT: string;
  TOKEN_SECRET: string;
}

interface Session {
  token: string; tenant_id: number; tenant_slug: string; tenant_name: string;
  plan: string; user_id: number; user_email: string; role: string;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Agent-Token',
  'Access-Control-Max-Age': '86400',
};
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

function json(body: any, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...SECURITY_HEADERS }
  });
}
function jsonError(message: string, status = 400) { return json({ error: message }, status); }
function textResponse(body: string, status = 200, ct = 'text/plain') {
  return new Response(body, { status, headers: { 'Content-Type': ct + '; charset=utf-8', ...CORS_HEADERS } });
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100_000, hash: 'SHA-256' },
    keyMat, 256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(prefix: string, bytes = 24): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return prefix + Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
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

async function handleStats(req: Request, env: Env, sess: Session): Promise<Response> {
  const d = await env.DB.prepare(
    "SELECT COUNT(*) as total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active, " +
    "SUM(CASE WHEN warranty_until IS NOT NULL AND warranty_until < date('now','+60 days') AND warranty_until >= date('now') THEN 1 ELSE 0 END) as warranty_warn, " +
    "SUM(CASE WHEN agent_status='online' THEN 1 ELSE 0 END) as agent_online, " +
    "SUM(CASE WHEN agent_status='offline' OR agent_status='no_agent' OR agent_status IS NULL THEN 1 ELSE 0 END) as agent_offline " +
    "FROM devices WHERE tenant_id = ?"
  ).bind(sess.tenant_id).first<any>();

  const l = await env.DB.prepare(
    "SELECT COUNT(*) as total, COALESCE(SUM(seats_total),0) as seats, COALESCE(SUM(cost_per_year),0) as cost FROM licenses WHERE tenant_id = ?"
  ).bind(sess.tenant_id).first<any>();
  const u = await env.DB.prepare("SELECT COUNT(*) as total FROM users WHERE tenant_id = ? AND active = 1").bind(sess.tenant_id).first<any>();

  return json({
    devices_total: d?.total || 0,
    devices_active: d?.active || 0,
    warranty_warning: d?.warranty_warn || 0,
    agent_online: d?.agent_online || 0,
    agent_offline: d?.agent_offline || 0,
    licenses_total: l?.total || 0,
    licenses_seats: l?.seats || 0,
    license_cost_yearly: Math.round(l?.cost || 0),
    users_total: u?.total || 0
  });
}

// Dashboard: rich aggregated view for Overview page
async function handleDashboard(req: Request, env: Env, sess: Session): Promise<Response> {
  // 1. Fleet health: average security_score across all devices with score
  const health = await env.DB.prepare(`
    SELECT
      ROUND(AVG(s.security_score), 0) AS avg_score,
      MIN(s.security_score) AS min_score,
      MAX(s.security_score) AS max_score,
      COUNT(s.device_id) AS scored_devices,
      SUM(CASE WHEN s.security_score >= 80 THEN 1 ELSE 0 END) AS healthy,
      SUM(CASE WHEN s.security_score BETWEEN 60 AND 79 THEN 1 ELSE 0 END) AS moderate,
      SUM(CASE WHEN s.security_score < 60 THEN 1 ELSE 0 END) AS poor
    FROM security_status s
    JOIN devices d ON d.id = s.device_id
    WHERE d.tenant_id = ?
  `).bind(sess.tenant_id).first<any>();

  // 2. Weakest 5 devices (lowest score, online)
  const weakest = await env.DB.prepare(`
    SELECT d.id, d.hostname, d.manufacturer, d.model, d.agent_status, s.security_score,
           s.bitlocker_enabled, s.av_enabled, s.wu_critical_count
    FROM devices d JOIN security_status s ON s.device_id = d.id
    WHERE d.tenant_id = ?
    ORDER BY s.security_score ASC LIMIT 5
  `).bind(sess.tenant_id).all();

  // 3. Recent alerts (last 5 open)
  const recentAlerts = await env.DB.prepare(`
    SELECT a.id, a.severity, a.title, a.value, a.first_seen, d.hostname AS device_hostname
    FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
    WHERE a.tenant_id = ? AND a.status IN ('open','acknowledged')
    ORDER BY
      CASE a.severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END,
      a.first_seen DESC
    LIMIT 5
  `).bind(sess.tenant_id).all();

  // 4. Disk usage distribution (latest telemetry per device)
  const diskDist = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN disk < 50 THEN 1 ELSE 0 END) AS low,
      SUM(CASE WHEN disk BETWEEN 50 AND 79 THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN disk BETWEEN 80 AND 94 THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN disk >= 95 THEN 1 ELSE 0 END) AS critical
    FROM (
      SELECT (SELECT disk_c_percent FROM device_telemetry t WHERE t.device_id = d.id ORDER BY t.id DESC LIMIT 1) AS disk
      FROM devices d WHERE d.tenant_id = ?
    ) WHERE disk IS NOT NULL
  `).bind(sess.tenant_id).first<any>();

  // 5. Security feature compliance (% of devices with each feature on)
  const compliance = await env.DB.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN bitlocker_enabled=1 THEN 1 ELSE 0 END) AS bitlocker,
      SUM(CASE WHEN av_enabled=1 THEN 1 ELSE 0 END) AS av,
      SUM(CASE WHEN av_up_to_date=1 THEN 1 ELSE 0 END) AS av_current,
      SUM(CASE WHEN tpm_ready=1 THEN 1 ELSE 0 END) AS tpm,
      SUM(CASE WHEN secure_boot=1 THEN 1 ELSE 0 END) AS secure_boot,
      SUM(CASE WHEN firewall_domain=1 AND firewall_private=1 AND firewall_public=1 THEN 1 ELSE 0 END) AS firewall
    FROM security_status WHERE tenant_id = ?
  `).bind(sess.tenant_id).first<any>();

  // 6. Alerts by severity (resolution time avg in last 30 days)
  const alertStats = await env.DB.prepare(`
    SELECT
      COUNT(*) AS total_fired_30d,
      SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved,
      SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical
    FROM alerts WHERE tenant_id = ?
      AND first_seen >= datetime('now','-30 days')
  `).bind(sess.tenant_id).first<any>();

  return json({
    fleet_health: {
      avg_score: health?.avg_score || null,
      min_score: health?.min_score || null,
      max_score: health?.max_score || null,
      scored_devices: health?.scored_devices || 0,
      healthy: health?.healthy || 0,
      moderate: health?.moderate || 0,
      poor: health?.poor || 0,
    },
    weakest_devices: weakest.results || [],
    recent_alerts: recentAlerts.results || [],
    disk_distribution: {
      low: diskDist?.low || 0,
      medium: diskDist?.medium || 0,
      high: diskDist?.high || 0,
      critical: diskDist?.critical || 0,
    },
    compliance: {
      total: compliance?.total || 0,
      bitlocker: compliance?.bitlocker || 0,
      av: compliance?.av || 0,
      av_current: compliance?.av_current || 0,
      tpm: compliance?.tpm || 0,
      secure_boot: compliance?.secure_boot || 0,
      firewall: compliance?.firewall || 0,
    },
    alert_stats_30d: {
      total: alertStats?.total_fired_30d || 0,
      resolved: alertStats?.resolved || 0,
      critical: alertStats?.critical || 0,
    },
  });
}

// ============== DEVICES ==============
async function handleDevicesList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT d.*, u.email as assigned_email, u.full_name as assigned_name,
            s.security_score, s.bitlocker_enabled, s.av_enabled, s.av_up_to_date, s.wu_pending_count
     FROM devices d
     LEFT JOIN users u ON u.id = d.assigned_to
     LEFT JOIN security_status s ON s.device_id = d.id
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

async function handleDeviceTelemetry(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const res = await env.DB.prepare(
    `SELECT recorded_at, cpu_percent, ram_percent, disk_c_percent, logged_in_user, uptime_seconds, ip_internal
     FROM device_telemetry WHERE device_id = ? AND recorded_at >= datetime('now','-7 days')
     ORDER BY recorded_at DESC LIMIT 1000`
  ).bind(id).all();
  return json({ items: res.results });
}

async function handleDeviceSecurity(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare('SELECT * FROM security_status WHERE device_id = ?').bind(id).first();
  return json(r || { device_id: id, security_score: null });
}

async function handleDeviceSoftware(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare(
    `SELECT name, version, publisher, install_date, first_seen, last_seen
     FROM installed_software WHERE device_id = ? ORDER BY name`
  ).bind(id).all();
  return json({ items: r.results });
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
     FROM users u WHERE u.tenant_id = ? ORDER BY u.full_name, u.email`
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
    body.full_name || null, body.department || null,
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

async function handleAuditList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT a.*, u.email AS user_email FROM audit_log a
     LEFT JOIN users u ON u.id = a.user_id
     WHERE a.tenant_id = ? ORDER BY a.created_at DESC LIMIT 100`
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

// ============== AGENTS (admin) ==============
async function handleAgentsList(req: Request, env: Env, sess: Session): Promise<Response> {
  const res = await env.DB.prepare(
    `SELECT a.*, d.hostname FROM agents a
     LEFT JOIN devices d ON d.id = a.device_id
     WHERE a.tenant_id = ? ORDER BY a.last_seen DESC`
  ).bind(sess.tenant_id).all();
  return json({ items: res.results });
}

async function handleAgentEnroll(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const body = await req.json<any>().catch(() => ({}));
  const enrollToken = randomToken('ENR-', 16);
  const r = await env.DB.prepare(
    `INSERT INTO agents (tenant_id, device_id, enroll_token, status) VALUES (?, ?, ?, 'pending')`
  ).bind(sess.tenant_id, body.device_id || null, enrollToken).run();
  await logAudit(env, sess, 'create', 'agent', r.meta.last_row_id as number, { device_id: body.device_id }, req.headers.get('CF-Connecting-IP'));
  const url = new URL(req.url);
  const installUrl = `${url.origin}/api/install-script/${enrollToken}`;
  return json({
    agent_id: r.meta.last_row_id,
    enroll_token: enrollToken,
    install_url: installUrl,
    install_command: `iex (irm '${installUrl}')`
  });
}

async function handleAgentRevoke(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const r = await env.DB.prepare(
    "UPDATE agents SET status='revoked', revoked_at=datetime('now') WHERE id=? AND tenant_id=?"
  ).bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Agent nicht gefunden', 404);
  await logAudit(env, sess, 'revoke', 'agent', id, {}, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

// ============== AGENT-FACING (public) ==============
async function handleAgentRegister(req: Request, env: Env): Promise<Response> {
  const body = await req.json<any>();
  if (!body.enroll_token || !body.hostname) return jsonError('enroll_token + hostname erforderlich');

  const agent = await env.DB.prepare(
    `SELECT id, tenant_id, device_id, status FROM agents WHERE enroll_token = ?`
  ).bind(body.enroll_token).first<any>();
  if (!agent) return jsonError('Invalid enroll token', 401);
  if (agent.status === 'revoked') return jsonError('Token revoked', 403);

  const ip = req.headers.get('CF-Connecting-IP') || '';
  const agentToken = randomToken('AGT-', 32);

  let deviceId = agent.device_id;
  if (!deviceId) {
    const existing = await env.DB.prepare(
      'SELECT id FROM devices WHERE tenant_id = ? AND hostname = ?'
    ).bind(agent.tenant_id, body.hostname).first<any>();
    if (existing) {
      deviceId = existing.id;
      await env.DB.prepare(
        `UPDATE devices SET manufacturer=COALESCE(?,manufacturer), model=COALESCE(?,model),
           serial_number=COALESCE(?,serial_number), os=COALESCE(?,os), cpu=COALESCE(?,cpu),
           ram_gb=COALESCE(?,ram_gb), storage_gb=COALESCE(?,storage_gb), mac_address=COALESCE(?,mac_address),
           agent_status='online', agent_last_seen=datetime('now'), agent_version=?,
           updated_at=datetime('now') WHERE id=?`
      ).bind(
        body.manufacturer || null, body.model || null, body.serial_number || null,
        body.os || null, body.cpu || null,
        body.ram_gb || null, body.storage_gb || null, body.mac_address || null,
        body.agent_version, deviceId
      ).run();
    } else {
      const created = await env.DB.prepare(
        `INSERT INTO devices (tenant_id, hostname, device_type, manufacturer, model, serial_number,
           os, cpu, ram_gb, storage_gb, mac_address, status, agent_status, agent_last_seen,
           agent_version, auto_discovered)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'online', datetime('now'), ?, 1)`
      ).bind(
        agent.tenant_id, body.hostname,
        body.os_platform === 'windows' ? 'desktop' : (body.os_platform === 'darwin' ? 'laptop' : 'other'),
        body.manufacturer || null, body.model || null, body.serial_number || null,
        body.os || null, body.cpu || null, body.ram_gb || null, body.storage_gb || null,
        body.mac_address || null, body.agent_version
      ).run();
      deviceId = created.meta.last_row_id as number;
    }
  } else {
    await env.DB.prepare(
      `UPDATE devices SET agent_status='online', agent_last_seen=datetime('now'),
         agent_version=?, updated_at=datetime('now') WHERE id=? AND tenant_id=?`
    ).bind(body.agent_version, deviceId, agent.tenant_id).run();
  }

  await env.DB.prepare(
    `UPDATE agents SET status='active', device_id=?, agent_token=?, agent_version=?,
       os_platform=?, hostname_reported=?, last_seen=datetime('now'), last_ip=? WHERE id=?`
  ).bind(deviceId, agentToken, body.agent_version, body.os_platform, body.hostname, ip, agent.id).run();

  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (tenant_id, action, entity_type, entity_id, details, ip_address)
       VALUES (?, 'register', 'agent', ?, ?, ?)`
    ).bind(agent.tenant_id, agent.id, JSON.stringify({ hostname: body.hostname, platform: body.os_platform }), ip).run();
  } catch(e) {}

  return json({
    agent_token: agentToken,
    agent_id: agent.id,
    device_id: deviceId,
    tenant_id: agent.tenant_id,
    heartbeat_interval_seconds: 900
  });
}

function computeSecurityScore(s: any): number {
  let score = 0;
  if (s.bitlocker_enabled) score += 20;
  if (s.av_enabled) score += 15;
  if (s.av_up_to_date) score += 10;
  if (s.av_signature_age_days != null && s.av_signature_age_days < 7) score += 5;
  if (s.tpm_present && s.tpm_ready) score += 10;
  if (s.secure_boot) score += 10;
  if (s.firewall_domain && s.firewall_private && s.firewall_public) score += 10;
  if (s.wu_critical_count === 0) score += 10;
  else if (s.wu_critical_count != null && s.wu_critical_count <= 2) score += 5;
  if (s.wu_pending_count != null && s.wu_pending_count < 10) score += 10;
  return Math.min(score, 100);
}

async function handleAgentHeartbeat(req: Request, env: Env): Promise<Response> {
  const agentTokenHdr = req.headers.get('X-Agent-Token');
  if (!agentTokenHdr) return jsonError('X-Agent-Token header erforderlich', 401);

  const agent = await env.DB.prepare(
    `SELECT id, tenant_id, device_id, status FROM agents WHERE agent_token = ?`
  ).bind(agentTokenHdr).first<any>();
  if (!agent) return jsonError('Invalid agent token', 401);
  if (agent.status !== 'active') return jsonError('Agent revoked', 403);

  const body = await req.json<any>();
  const ip = req.headers.get('CF-Connecting-IP') || '';

  await env.DB.prepare(
    `INSERT INTO device_telemetry (tenant_id, device_id, agent_id, uptime_seconds, logged_in_user,
       cpu_percent, ram_percent, ram_total_gb, ram_used_gb, disk_c_percent, disk_c_total_gb,
       disk_c_free_gb, ip_internal, ip_external, last_boot)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    agent.tenant_id, agent.device_id, agent.id,
    body.uptime_seconds || null, body.logged_in_user || null,
    body.cpu_percent || null, body.ram_percent || null,
    body.ram_total_gb || null, body.ram_used_gb || null,
    body.disk_c_percent || null, body.disk_c_total_gb || null, body.disk_c_free_gb || null,
    body.ip_internal || null, ip, body.last_boot || null
  ).run();

  await env.DB.prepare(
    `UPDATE devices SET agent_status='online', agent_last_seen=datetime('now'),
       ip_address=COALESCE(?,ip_address), updated_at=datetime('now') WHERE id=?`
  ).bind(body.ip_internal || null, agent.device_id).run();

  await env.DB.prepare(`UPDATE agents SET last_seen=datetime('now'), last_ip=? WHERE id=?`).bind(ip, agent.id).run();

  if (body.security) {
    const s = body.security;
    const score = computeSecurityScore(s);
    await env.DB.prepare(
      `INSERT INTO security_status (device_id, tenant_id, bitlocker_enabled, bitlocker_status_text,
         av_product, av_enabled, av_up_to_date, av_signature_age_days,
         wu_last_search, wu_last_install, wu_pending_count, wu_critical_count,
         tpm_present, tpm_ready, secure_boot, firewall_domain, firewall_private, firewall_public,
         security_score, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(device_id) DO UPDATE SET
         bitlocker_enabled=excluded.bitlocker_enabled,
         bitlocker_status_text=excluded.bitlocker_status_text,
         av_product=excluded.av_product, av_enabled=excluded.av_enabled,
         av_up_to_date=excluded.av_up_to_date, av_signature_age_days=excluded.av_signature_age_days,
         wu_last_search=excluded.wu_last_search, wu_last_install=excluded.wu_last_install,
         wu_pending_count=excluded.wu_pending_count, wu_critical_count=excluded.wu_critical_count,
         tpm_present=excluded.tpm_present, tpm_ready=excluded.tpm_ready,
         secure_boot=excluded.secure_boot, firewall_domain=excluded.firewall_domain,
         firewall_private=excluded.firewall_private, firewall_public=excluded.firewall_public,
         security_score=excluded.security_score, updated_at=datetime('now')`
    ).bind(
      agent.device_id, agent.tenant_id,
      s.bitlocker_enabled ? 1 : 0, s.bitlocker_status || null,
      s.av_product || null, s.av_enabled ? 1 : 0,
      s.av_up_to_date ? 1 : 0, s.av_signature_age_days != null ? s.av_signature_age_days : null,
      s.wu_last_search || null, s.wu_last_install || null,
      s.wu_pending_count != null ? s.wu_pending_count : null,
      s.wu_critical_count != null ? s.wu_critical_count : null,
      s.tpm_present ? 1 : 0, s.tpm_ready ? 1 : 0,
      s.secure_boot ? 1 : 0,
      s.firewall_domain ? 1 : 0, s.firewall_private ? 1 : 0, s.firewall_public ? 1 : 0,
      score
    ).run();
  }

  if (body.software && Array.isArray(body.software) && body.software.length > 0) {
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    for (const s of body.software.slice(0, 200)) {
      try {
        await env.DB.prepare(
          `INSERT INTO installed_software (tenant_id, device_id, name, version, publisher, install_date, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id, name, version) DO UPDATE SET last_seen=excluded.last_seen,
             publisher=COALESCE(excluded.publisher, publisher),
             install_date=COALESCE(excluded.install_date, install_date)`
        ).bind(
          agent.tenant_id, agent.device_id, s.name, s.version || '', s.publisher || null,
          s.install_date || null, now, now
        ).run();
      } catch(e) {}
    }
  }

  return json({ ok: true, next_heartbeat_seconds: 900 });
}

// ============== INSTALL SCRIPT (public) ==============
function generateWindowsInstallScript(enrollToken: string, apiUrl: string): string {
  return `# Hasi IT-Cockpit Agent - Windows Installer
# Token: ${enrollToken.slice(0, 12)}...
# Erfordert: Administrator-PowerShell

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "================================================"
Write-Host "  Hasi IT-Cockpit Agent - Installer"
Write-Host "================================================"
Write-Host ""

# ---------- 1) Admin-Check (robust, mehrere Methoden) ----------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $true }
    } catch {}
    # Fallback: whoami /groups
    try {
        $g = whoami /groups 2>&1
        if ($g -match 'S-1-16-12288' -or $g -match 'BUILTIN\\\\Administratoren' -or $g -match 'BUILTIN\\\\Administrators') {
            return $true
        }
    } catch {}
    # Fallback: schreibversuch in Programme
    try {
        $t = "$env:ProgramFiles\\\\.hasi_admin_test"
        New-Item -ItemType File -Force -Path $t -ErrorAction Stop | Out-Null
        Remove-Item $t -Force -ErrorAction SilentlyContinue
        return $true
    } catch {}
    return $false
}

$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Write-Host "WARNUNG: Adminrechte konnten nicht eindeutig verifiziert werden." -ForegroundColor Yellow
    Write-Host "         Installation wird fortgesetzt - bei Fehlern bitte als Admin starten." -ForegroundColor Yellow
    Write-Host ""
}

# ---------- 2) Verzeichnis vorbereiten ----------
$installDir = "$env:ProgramFiles\\\\HasiCockpit"
$null = New-Item -ItemType Directory -Force -Path $installDir
Write-Host "[OK] Verzeichnis: $installDir" -ForegroundColor Green

# ---------- 3) Konfiguration schreiben - BOM-frei! ----------
$config = [ordered]@{
    enroll_token      = "${enrollToken}"
    api_url           = "${apiUrl}"
    heartbeat_seconds = 900
} | ConvertTo-Json

$configPath = "$installDir\\\\config.json"
$utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($configPath, $config, $utf8NoBom)
Write-Host "[OK] Konfiguration: $configPath" -ForegroundColor Green

# ---------- 4) Agent-Binary herunterladen ----------
$agentUrl  = "${apiUrl.replace('/api', '')}/agent-binary/hasi-agent-windows-amd64.exe"
$agentPath = "$installDir\\\\hasi-agent.exe"

Write-Host "-> Lade Agent herunter..."
try {
    Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -UseBasicParsing -ErrorAction Stop
    $size = [math]::Round((Get-Item $agentPath).Length / 1MB, 1)
    Write-Host "[OK] Agent installiert: $agentPath ($size MB)" -ForegroundColor Green
} catch {
    Write-Host "FEHLER beim Download: $_" -ForegroundColor Red
    Write-Host "  URL: $agentUrl"
    exit 1
}

# ---------- 5) Erster Heartbeat - sofortige Registrierung ----------
Write-Host "-> Erster Heartbeat (Geraet registrieren)..."
try {
    $output = & $agentPath --once 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Geraet erfolgreich registriert" -ForegroundColor Green
    } else {
        Write-Host "WARNUNG: Erster Heartbeat fehlgeschlagen:" -ForegroundColor Yellow
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    }
} catch {
    Write-Host "FEHLER: $_" -ForegroundColor Red
}

# ---------- 6) Autostart einrichten ----------
$serviceName = "HasiCockpitAgent"
$autostartOk = $false

# Versuch A: Windows Service (benoetigt echte Adminrechte)
Write-Host "-> Versuche Windows Service..."
try {
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    $binPathArg = '"' + $agentPath + '" --service'
    $createResult = sc.exe create $serviceName binPath= $binPathArg start= auto DisplayName= "Hasi IT-Cockpit Agent" 2>&1
    if ($LASTEXITCODE -eq 0) {
        sc.exe description $serviceName "Hasi IT-Cockpit - Endpoint Inventory Agent" | Out-Null
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-Host "[OK] Service aktiv: $serviceName" -ForegroundColor Green
        $autostartOk = $true
    } else {
        Write-Host "  Service-Erstellung fehlgeschlagen (Adminrechte fehlen)." -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "  Service-Erstellung uebersprungen." -ForegroundColor DarkYellow
}

# Versuch B: Task Scheduler (Fallback - funktioniert auch ohne Service-Rechte)
if (-not $autostartOk) {
    Write-Host "-> Fallback: Task Scheduler..."
    try {
        $taskName = "HasiCockpitAgent"
        # Alten Task entfernen
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        $action    = New-ScheduledTaskAction -Execute $agentPath
        $triggers  = @(
            New-ScheduledTaskTrigger -AtStartup
            New-ScheduledTaskTrigger -AtLogOn
        )
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Description "Hasi IT-Cockpit - Endpoint Inventory Agent" -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Host "[OK] Task Scheduler aktiv: $taskName (Start bei Boot + Login)" -ForegroundColor Green
        $autostartOk = $true
    } catch {
        Write-Host "  Task Scheduler fehlgeschlagen: $_" -ForegroundColor DarkYellow
    }
}

# Versuch C: Letzter Fallback - Run-Key in Registry (User-Login)
if (-not $autostartOk) {
    try {
        $runKey = 'HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
        Set-ItemProperty -Path $runKey -Name "HasiCockpitAgent" -Value $agentPath -Force
        Write-Host "[OK] Autostart via Registry (HKCU Run)" -ForegroundColor Green
        $autostartOk = $true
    } catch {
        Write-Host "WARNUNG: Kein Autostart eingerichtet - Agent muss manuell gestartet werden." -ForegroundColor Yellow
    }
}

# ---------- 7) Abschluss ----------
Write-Host ""
Write-Host "================================================"
Write-Host "[OK] Installation abgeschlossen!" -ForegroundColor Green
Write-Host "================================================"
Write-Host "  Konfiguration: $configPath"
Write-Host "  Agent:         $agentPath"
Write-Host "  Heartbeat:     alle 15 Minuten"
Write-Host ""
Write-Host "  Cockpit:       https://it-cockpit.pages.dev"
Write-Host ""
`;
}

async function handleInstallScript(token: string, req: Request, env: Env): Promise<Response> {
  const agent = await env.DB.prepare(`SELECT id, status FROM agents WHERE enroll_token = ?`).bind(token).first<any>();
  if (!agent) return textResponse('# Invalid enroll token\nWrite-Host "FEHLER: Token ungueltig" -ForegroundColor Red\nexit 1', 401);
  if (agent.status === 'revoked') return textResponse('# Token revoked\nWrite-Host "FEHLER: Token gesperrt" -ForegroundColor Red\nexit 1', 403);
  const url = new URL(req.url);
  const apiUrl = `${url.origin}/api`;
  // Convert LF -> CRLF for Windows PowerShell compatibility
  const script = generateWindowsInstallScript(token, apiUrl).replace(/\r?\n/g, '\r\n');
  return textResponse(script, 200, 'text/plain');
}

// ============== AGENT BINARY (public, R2-served) ==============
async function handleAgentBinary(filename: string, env: Env): Promise<Response> {
  // Only allow whitelisted filenames
  const allowed = [
    'hasi-agent-windows-amd64.exe',
    'hasi-agent-darwin-amd64',
    'hasi-agent-linux-amd64',
  ];
  if (!allowed.includes(filename)) {
    return new Response('Not Found', { status: 404 });
  }

  const obj = await env.AGENTS.get(`latest/${filename}`);
  if (!obj) return new Response('Binary not found', { status: 404 });

  const isExe = filename.endsWith('.exe');
  return new Response(obj.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'public, max-age=300, must-revalidate',
      'ETag': obj.httpEtag,
      ...CORS_HEADERS,
    }
  });
}

// ============== ALERT MANAGEMENT ==============

async function handleAlertsList(req: Request, env: Env, sess: Session): Promise<Response> {
  const url = new URL(req.url);
  const status = url.searchParams.get('status') || 'open';
  const res = await env.DB.prepare(`
    SELECT a.*, d.hostname AS device_hostname
    FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
    WHERE a.tenant_id = ?
      AND (? = 'all' OR a.status = ? OR (? = 'open' AND a.status IN ('open','acknowledged')))
    ORDER BY
      CASE a.severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END,
      a.last_seen DESC
    LIMIT 200
  `).bind(sess.tenant_id, status, status, status).all();
  return json({ items: res.results });
}

async function handleAlertAck(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare(`
    UPDATE alerts SET status='acknowledged', acknowledged_at=datetime('now'), acknowledged_by=?
    WHERE id=? AND tenant_id=? AND status='open'
  `).bind(sess.user_id, id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Alert nicht gefunden oder bereits bearbeitet', 404);
  await env.DB.prepare(`INSERT INTO alert_history (tenant_id, alert_id, rule_key, severity, event)
    SELECT tenant_id, id, rule_key, severity, 'acknowledged' FROM alerts WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}

async function handleAlertResolve(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare(`
    UPDATE alerts SET status='resolved', resolved_at=datetime('now')
    WHERE id=? AND tenant_id=? AND status IN ('open','acknowledged')
  `).bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Alert nicht gefunden', 404);
  return json({ ok: true });
}

async function handleAlertSettings(req: Request, env: Env, sess: Session): Promise<Response> {
  if (req.method === 'GET') {
    const s = await env.DB.prepare(`SELECT * FROM alert_settings WHERE tenant_id = ?`).bind(sess.tenant_id).first();
    if (!s) {
      await env.DB.prepare(`INSERT INTO alert_settings (tenant_id) VALUES (?)`).bind(sess.tenant_id).run();
      const fresh = await env.DB.prepare(`SELECT * FROM alert_settings WHERE tenant_id = ?`).bind(sess.tenant_id).first();
      return json(fresh);
    }
    return json(s);
  }
  if (req.method === 'PUT') {
    if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
    const body = await req.json<any>();
    const allowedKeys = [
      'telegram_enabled','telegram_bot_token','telegram_chat_id',
      'email_enabled','email_recipient',
      'rule_disk_critical','rule_disk_warning','rule_av_disabled','rule_av_outdated',
      'rule_bitlocker_off','rule_agent_offline','rule_wu_critical','rule_new_device',
      'disk_critical_pct','disk_warning_pct','av_signature_days',
      'agent_offline_warn_h','agent_offline_crit_h','wu_critical_count'
    ];
    const setParts: string[] = [];
    const values: any[] = [];
    for (const k of allowedKeys) {
      if (k in body) {
        setParts.push(`${k} = ?`);
        values.push(body[k]);
      }
    }
    if (setParts.length === 0) return jsonError('Keine Aenderungen', 400);
    setParts.push(`updated_at = datetime('now')`);
    values.push(sess.tenant_id);
    await env.DB.prepare(`
      INSERT INTO alert_settings (tenant_id) VALUES (?) ON CONFLICT(tenant_id) DO NOTHING
    `).bind(sess.tenant_id).run();
    await env.DB.prepare(`UPDATE alert_settings SET ${setParts.join(', ')} WHERE tenant_id = ?`).bind(...values).run();
    await logAudit(env, sess, 'update', 'alert_settings', sess.tenant_id, {}, req.headers.get('CF-Connecting-IP'));
    return json({ ok: true });
  }
  return jsonError('Method not allowed', 405);
}

async function handleAlertTestTelegram(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const r = await sendTestTelegram(env, sess.tenant_id);
  return json(r);
}

async function handleAlertEvaluate(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const r = await evaluateAlerts(env);
  await logAudit(env, sess, 'evaluate', 'alerts', null, r, req.headers.get('CF-Connecting-IP'));
  return json(r);
}

async function handleAlertCount(req: Request, env: Env, sess: Session): Promise<Response> {
  const r = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN severity='critical' AND status IN ('open','acknowledged') THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN severity='warning' AND status IN ('open','acknowledged') THEN 1 ELSE 0 END) AS warning,
      SUM(CASE WHEN severity='info' AND status IN ('open','acknowledged') THEN 1 ELSE 0 END) AS info
    FROM alerts WHERE tenant_id = ?
  `).bind(sess.tenant_id).first<any>();
  return json({
    critical: r?.critical || 0,
    warning: r?.warning || 0,
    info: r?.info || 0,
    total: (r?.critical || 0) + (r?.warning || 0) + (r?.info || 0),
  });
}

// ============== ROUTER ==============
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    const url = new URL(req.url);
    const path = url.pathname;
    const m = req.method;

    try {
      if (path === '/health') return json({ status: 'ok', version: '0.3.0', time: new Date().toISOString() });
      if (path === '/api/auth/login' && m === 'POST') return handleLogin(req, env);

      // Public agent endpoints
      if (path === '/api/agent/register' && m === 'POST') return handleAgentRegister(req, env);
      if (path === '/api/agent/heartbeat' && m === 'POST') return handleAgentHeartbeat(req, env);
      const isMatch = path.match(/^\/api\/install-script\/(.+)$/);
      if (isMatch && m === 'GET') return handleInstallScript(isMatch[1], req, env);

      // Public binary download
      const bm = path.match(/^\/agent-binary\/(.+)$/);
      if (bm && m === 'GET') return handleAgentBinary(bm[1], env);

      const sess = await authenticate(req, env);
      if (!sess) return jsonError('Unauthorized', 401);

      if (path === '/api/stats') return handleStats(req, env, sess);
      if (path === '/api/dashboard') return handleDashboard(req, env, sess);
      if (path === '/api/audit' && m === 'GET') return handleAuditList(req, env, sess);

      if (path === '/api/devices' && m === 'GET') return handleDevicesList(req, env, sess);
      if (path === '/api/devices' && m === 'POST') return handleDeviceCreate(req, env, sess);
      if (path === '/api/devices/bulk-import' && m === 'POST') return handleBulkImport(req, env, sess);
      let mt = path.match(/^\/api\/devices\/(\d+)$/);
      if (mt && m === 'PUT') return handleDeviceUpdate(Number(mt[1]), req, env, sess);
      if (mt && m === 'DELETE') return handleDeviceDelete(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/telemetry$/);
      if (mt && m === 'GET') return handleDeviceTelemetry(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/security$/);
      if (mt && m === 'GET') return handleDeviceSecurity(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/software$/);
      if (mt && m === 'GET') return handleDeviceSoftware(Number(mt[1]), req, env, sess);

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

      if (path === '/api/agents' && m === 'GET') return handleAgentsList(req, env, sess);
      if (path === '/api/agents/enroll' && m === 'POST') return handleAgentEnroll(req, env, sess);
      mt = path.match(/^\/api\/agents\/(\d+)\/revoke$/);
      if (mt && m === 'POST') return handleAgentRevoke(Number(mt[1]), req, env, sess);

      // Alerts
      if (path === '/api/alerts' && m === 'GET') return handleAlertsList(req, env, sess);
      if (path === '/api/alerts/count' && m === 'GET') return handleAlertCount(req, env, sess);
      if (path === '/api/alerts/settings' && (m === 'GET' || m === 'PUT')) return handleAlertSettings(req, env, sess);
      if (path === '/api/alerts/test-telegram' && m === 'POST') return handleAlertTestTelegram(req, env, sess);
      if (path === '/api/alerts/evaluate' && m === 'POST') return handleAlertEvaluate(req, env, sess);
      mt = path.match(/^\/api\/alerts\/(\d+)\/acknowledge$/);
      if (mt && m === 'POST') return handleAlertAck(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/alerts\/(\d+)\/resolve$/);
      if (mt && m === 'POST') return handleAlertResolve(Number(mt[1]), req, env, sess);

      return jsonError('Not Found', 404);
    } catch(e: any) {
      console.error(e);
      return jsonError(e.message || 'Internal error', 500);
    }
  },

  // ============== CRON: alert evaluator (every 15 min) ==============
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log(`[cron] alert evaluation triggered at ${new Date().toISOString()}`);
    try {
      const result = await evaluateAlerts(env);
      console.log(`[cron] result:`, JSON.stringify(result));
    } catch (e: any) {
      console.error(`[cron] error:`, e.message || e);
    }
  }
};
