/**
 * Hasi IT-Cockpit — Cloudflare Worker API v0.3
 * Adds: alert evaluator (cron), Telegram notifications, alert management endpoints
 */

import { evaluateAlerts, sendTestTelegram, sendTestEmail } from './alerts';
import { generateMonthlyReports } from './monthly_report';

export interface Env {
  DB: D1Database;
  AGENTS: R2Bucket;
  PW_SALT: string;
  TOKEN_SECRET: string;
  RESEND_API_KEY?: string;
  BROWSER_RENDERING_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
}

interface Session {
  token: string; tenant_id: number; tenant_slug: string; tenant_name: string;
  plan: string; user_id: number; user_email: string; role: string;
  home_tenant_id: number; home_tenant_slug: string; home_tenant_name: string;
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
    user_id: u.id, user_email: u.email, role: u.role,
    home_tenant_id: t.id, home_tenant_slug: t.slug, home_tenant_name: t.name
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
      SUM(CASE WHEN firewall_domain=1 AND firewall_private=1 AND firewall_public=1 THEN 1 ELSE 0 END) AS firewall,
      SUM(CASE WHEN uac_enabled=1 THEN 1 ELSE 0 END) AS uac_on,
      SUM(CASE WHEN rdp_enabled=0 OR rdp_enabled IS NULL THEN 1 ELSE 0 END) AS no_rdp,
      SUM(CASE WHEN auto_login_enabled=0 OR auto_login_enabled IS NULL THEN 1 ELSE 0 END) AS no_auto_login,
      SUM(CASE WHEN defender_tamper_on=1 THEN 1 ELSE 0 END) AS tamper_on,
      SUM(CASE WHEN pending_reboot=0 OR pending_reboot IS NULL THEN 1 ELSE 0 END) AS no_pending_reboot
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
      uac_on: compliance?.uac_on || 0,
      no_rdp: compliance?.no_rdp || 0,
      no_auto_login: compliance?.no_auto_login || 0,
      tamper_on: compliance?.tamper_on || 0,
      no_pending_reboot: compliance?.no_pending_reboot || 0,
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

async function handleDeviceDisks(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare(
    `SELECT mount, label, filesystem, total_gb, free_gb, percent, smart_health, disk_type, last_seen
     FROM device_disks WHERE device_id = ? ORDER BY mount`
  ).bind(id).all();
  return json({ items: r.results });
}

async function handleDeviceProcesses(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare(
    `SELECT name, pid, ram_mb, cpu_pct, rank, captured_at FROM device_processes
     WHERE device_id = ? ORDER BY rank ASC LIMIT 20`
  ).bind(id).all();
  return json({ items: r.results });
}

async function handleDeviceBrowsers(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare(
    `SELECT browser_name, version, outdated, last_seen FROM device_browsers
     WHERE device_id = ? ORDER BY browser_name`
  ).bind(id).all();
  return json({ items: r.results });
}

async function handleDeviceAntivirus(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const own = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND tenant_id = ?').bind(id, sess.tenant_id).first();
  if (!own) return jsonError('Gerät nicht gefunden', 404);
  const r = await env.DB.prepare(
    `SELECT name, enabled, up_to_date, is_defender, product_state, last_seen
     FROM device_antivirus WHERE device_id = ? ORDER BY enabled DESC, name`
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
  // Total 100 points, gewichtet nach Sicherheitsrelevanz
  let score = 0;
  // Verschluesselung & Auth (25)
  if (s.bitlocker_enabled) score += 15;
  if (s.uac_enabled) score += 5;
  if (!s.auto_login_enabled) score += 5;
  // Antivirus (20)
  if (s.av_enabled) score += 10;
  if (s.av_up_to_date) score += 7;
  if (s.av_signature_age_days != null && s.av_signature_age_days < 7) score += 3;
  // Defender tamper protection (5) — gilt nur wenn Defender genutzt
  if (s.defender_tamper_on) score += 5;
  // Hardware-Trust (15)
  if (s.tpm_present && s.tpm_ready) score += 8;
  if (s.secure_boot) score += 7;
  // Firewall (10)
  if (s.firewall_domain && s.firewall_private && s.firewall_public) score += 10;
  else if (s.firewall_private || s.firewall_public) score += 4;
  // Updates (15)
  if (s.wu_critical_count === 0) score += 10;
  else if (s.wu_critical_count != null && s.wu_critical_count <= 2) score += 5;
  if (s.wu_pending_count != null && s.wu_pending_count < 10) score += 5;
  // Pending reboot (-5) — wartet auf Reboot ist Risiko
  if (s.pending_reboot) score -= 5;
  // Failed logons (-5) — Brute-Force-Indikator
  if (s.failed_logons_24h != null && s.failed_logons_24h > 20) score -= 5;
  // Local admin count (-3) — zu viele Admins
  if (s.local_admin_count != null && s.local_admin_count > 3) score -= 3;
  // RDP exposed (-5) — Risikoflache
  if (s.rdp_enabled) score -= 3;
  // Hygiene (10)
  if (s.open_ports_count != null && s.open_ports_count < 30) score += 10;
  else if (s.open_ports_count != null && s.open_ports_count < 60) score += 5;
  return Math.max(0, Math.min(score, 100));
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
       disk_c_free_gb, ip_internal, ip_external, last_boot,
       cpu_temp_c, battery_wear_pct, battery_health, boot_time_sec, outdated_sw_count)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    agent.tenant_id, agent.device_id, agent.id,
    body.uptime_seconds || null, body.logged_in_user || null,
    body.cpu_percent || null, body.ram_percent || null,
    body.ram_total_gb || null, body.ram_used_gb || null,
    body.disk_c_percent || null, body.disk_c_total_gb || null, body.disk_c_free_gb || null,
    body.ip_internal || null, ip, body.last_boot || null,
    body.cpu_temp_c || null, body.battery_wear_pct || null, body.battery_health || null,
    body.boot_time_sec || null, body.outdated_sw_count || null
  ).run();

  await env.DB.prepare(
    `UPDATE devices SET agent_status='online', agent_last_seen=datetime('now'),
       ip_address=COALESCE(?,ip_address), updated_at=datetime('now') WHERE id=?`
  ).bind(body.ip_internal || null, agent.device_id).run();

  // v0.5.3: parse agent version from User-Agent header (HasiCockpitAgent/X.Y.Z)
  const uaHeader = req.headers.get('User-Agent') || '';
  const versionMatch = uaHeader.match(/HasiCockpitAgent\/(\S+)/);
  const agentVersion = versionMatch ? versionMatch[1] : null;
  if (agentVersion) {
    await env.DB.prepare(`UPDATE agents SET last_seen=datetime('now'), last_ip=?, agent_version=? WHERE id=?`)
      .bind(ip, agentVersion, agent.id).run();
  } else {
    await env.DB.prepare(`UPDATE agents SET last_seen=datetime('now'), last_ip=? WHERE id=?`).bind(ip, agent.id).run();
  }

  if (body.security) {
    const s = body.security;
    const score = computeSecurityScore(s);
    await env.DB.prepare(
      `INSERT INTO security_status (device_id, tenant_id, bitlocker_enabled, bitlocker_status_text,
         av_product, av_enabled, av_up_to_date, av_signature_age_days,
         wu_last_search, wu_last_install, wu_pending_count, wu_critical_count,
         tpm_present, tpm_ready, secure_boot, firewall_domain, firewall_private, firewall_public,
         security_score,
         defender_tamper_on, uac_enabled, rdp_enabled, auto_login_enabled,
         pending_reboot, pending_reboot_reason, failed_logons_24h, local_admin_count,
         open_ports_count, open_ports_list, open_ports_detail, local_admins_list,
         updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
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
         security_score=excluded.security_score,
         defender_tamper_on=excluded.defender_tamper_on, uac_enabled=excluded.uac_enabled,
         rdp_enabled=excluded.rdp_enabled, auto_login_enabled=excluded.auto_login_enabled,
         pending_reboot=excluded.pending_reboot, pending_reboot_reason=excluded.pending_reboot_reason,
         failed_logons_24h=excluded.failed_logons_24h, local_admin_count=excluded.local_admin_count,
         open_ports_count=excluded.open_ports_count, open_ports_list=excluded.open_ports_list,
         open_ports_detail=excluded.open_ports_detail, local_admins_list=excluded.local_admins_list,
         updated_at=datetime('now')`
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
      score,
      s.defender_tamper_on != null ? (s.defender_tamper_on ? 1 : 0) : null, s.uac_enabled != null ? (s.uac_enabled ? 1 : 0) : null,
      s.rdp_enabled != null ? (s.rdp_enabled ? 1 : 0) : null, s.auto_login_enabled != null ? (s.auto_login_enabled ? 1 : 0) : null,
      s.pending_reboot != null ? (s.pending_reboot ? 1 : 0) : null, s.pending_reboot_reason || null,
      s.failed_logons_24h != null ? s.failed_logons_24h : null,
      s.local_admin_count != null ? s.local_admin_count : null,
      s.open_ports_count != null ? s.open_ports_count : null,
      s.open_ports_list || null,
      s.open_ports_detail || null,
      s.local_admins_list || null
    ).run();
  }

  // v0.5.0: Multi-disk insert/upsert
  if (body.disks && Array.isArray(body.disks)) {
    // Önce eski silmek yerine UPSERT, böylece USB takılıp çıkartılırsa kaybolmaz
    for (const d of body.disks.slice(0, 20)) {
      try {
        await env.DB.prepare(
          `INSERT INTO device_disks (tenant_id, device_id, mount, label, filesystem, total_gb, free_gb, percent, smart_health, disk_type, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(device_id, mount) DO UPDATE SET
             label=excluded.label, filesystem=excluded.filesystem,
             total_gb=excluded.total_gb, free_gb=excluded.free_gb, percent=excluded.percent,
             smart_health=excluded.smart_health, disk_type=excluded.disk_type,
             last_seen=excluded.last_seen`
        ).bind(
          agent.tenant_id, agent.device_id, d.mount, d.label || null,
          d.filesystem || null, d.total_gb || null, d.free_gb || null, d.percent || null,
          d.smart_health || null, d.type || null
        ).run();
      } catch(e) {}
    }
  }

  // v0.5.0: Top processes — eski silinir, yeni 10 eklenir
  if (body.top_processes && Array.isArray(body.top_processes)) {
    await env.DB.prepare(`DELETE FROM device_processes WHERE device_id = ?`).bind(agent.device_id).run();
    let rank = 0;
    for (const p of body.top_processes.slice(0, 10)) {
      rank++;
      try {
        await env.DB.prepare(
          `INSERT INTO device_processes (tenant_id, device_id, name, pid, ram_mb, cpu_pct, rank, captured_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
        ).bind(
          agent.tenant_id, agent.device_id, p.name || 'unknown', p.pid || null,
          p.ram_mb || null, p.cpu_pct || null, rank
        ).run();
      } catch(e) {}
    }
  }

  // v0.5.0: Browsers — UPSERT
  if (body.browsers && Array.isArray(body.browsers)) {
    for (const b of body.browsers.slice(0, 10)) {
      try {
        await env.DB.prepare(
          `INSERT INTO device_browsers (tenant_id, device_id, browser_name, version, outdated, last_seen)
           VALUES (?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(device_id, browser_name) DO UPDATE SET
             version=excluded.version, outdated=excluded.outdated, last_seen=excluded.last_seen`
        ).bind(
          agent.tenant_id, agent.device_id, b.name, b.version || null,
          b.outdated ? 1 : 0
        ).run();
      } catch(e) {}
    }
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

  // v0.5.2: Multi-AV liste (alle erkannten AV-Produkte)
  if (body.security && body.security.av_products && Array.isArray(body.security.av_products)) {
    for (const av of body.security.av_products.slice(0, 10)) {
      try {
        await env.DB.prepare(
          `INSERT INTO device_antivirus (tenant_id, device_id, name, enabled, up_to_date, is_defender, product_state, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(device_id, name) DO UPDATE SET
             enabled=excluded.enabled, up_to_date=excluded.up_to_date,
             is_defender=excluded.is_defender, product_state=excluded.product_state,
             last_seen=excluded.last_seen`
        ).bind(
          agent.tenant_id, agent.device_id, av.name,
          av.enabled ? 1 : 0, av.up_to_date ? 1 : 0,
          av.is_defender ? 1 : 0, av.product_state || null
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
# Selbst-elevation: bei Bedarf wird UAC-Prompt ausgeloest

$ErrorActionPreference = 'Stop'

# ---------- 0) Self-elevate via UAC ----------
# Wenn nicht als Admin gestartet: PowerShell mit -Verb RunAs neu starten
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "Installer benoetigt Admin-Rechte. Starte UAC-Prompt..." -ForegroundColor Yellow
    $scriptUrl = '${apiUrl}/install-script/${enrollToken}'
    $psCommand = 'iex (irm ''' + $scriptUrl + '''); Read-Host ''Fertig - Enter zum Schliessen'''
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $psCommand)
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $psArgs
        Write-Host "Bitte UAC-Prompt bestaetigen. Dieses Fenster kann geschlossen werden." -ForegroundColor Green
    } catch {
        Write-Host "FEHLER: UAC-Elevation nicht moeglich. Bitte manuell als Admin starten." -ForegroundColor Red
    }
    exit 0
}

Write-Host ""
Write-Host "================================================"
Write-Host "  Hasi IT-Cockpit Agent - Installer"
Write-Host "================================================"
Write-Host "  Adminrechte: OK" -ForegroundColor Green
Write-Host ""

# ---------- 1) Verzeichnis vorbereiten ----------
$installDir = "$env:ProgramFiles\\\\HasiCockpit"
$null = New-Item -ItemType Directory -Force -Path $installDir
Write-Host "[OK] Verzeichnis: $installDir" -ForegroundColor Green

# ---------- 2) Konfiguration schreiben (BOM-frei!) ----------
$config = [ordered]@{
    enroll_token      = "${enrollToken}"
    api_url           = "${apiUrl}"
    heartbeat_seconds = 900
} | ConvertTo-Json

$configPath = "$installDir\\\\config.json"
$utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($configPath, $config, $utf8NoBom)
Write-Host "[OK] Konfiguration: $configPath" -ForegroundColor Green

# ---------- 3) Agent-Binary herunterladen ----------
$agentUrl  = "${apiUrl.replace('/api', '')}/agent-binary/hasi-agent-windows-amd64.exe"
$agentPath = "$installDir\\\\hasi-agent.exe"

# Vorbereitung: alles Alte stoppen (Service + Task + Prozess), Datei freigeben
function Stop-AgentCompletely {
    # 1. Windows Service stoppen falls vorhanden
    $existing = Get-Service -Name "HasiCockpitAgent" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "-> Stoppe Windows Service..."
        Stop-Service -Name "HasiCockpitAgent" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    # 2. Scheduled Task stoppen falls vorhanden
    $task = Get-ScheduledTask -TaskName "HasiCockpitAgent" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "-> Stoppe Scheduled Task..."
        Stop-ScheduledTask -TaskName "HasiCockpitAgent" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    # 3. Hartes Kill aller Agent-Prozesse (Fallback)
    $procs = Get-Process -Name "hasi-agent" -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "-> Beende laufende Agent-Prozesse..." -ForegroundColor Yellow
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

Stop-AgentCompletely

# Pruefen ob die Binary noch gelockt ist
if (Test-Path $agentPath) {
    $maxTries = 5
    $tryNum = 0
    while ($tryNum -lt $maxTries) {
        try {
            $fs = [System.IO.File]::Open($agentPath, 'Open', 'ReadWrite', 'None')
            $fs.Close()
            break
        } catch {
            $tryNum++
            Write-Host "-> Datei noch gelockt, warte 2s (Versuch $tryNum/$maxTries)..." -ForegroundColor Yellow
            Stop-AgentCompletely
            Start-Sleep -Seconds 2
        }
    }
}

Write-Host "-> Lade Agent herunter..."
try {
    Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -UseBasicParsing -ErrorAction Stop
    $size = [math]::Round((Get-Item $agentPath).Length / 1MB, 1)
    Write-Host "[OK] Agent installiert: $agentPath ($size MB)" -ForegroundColor Green
    # Version aus dem Binary lesen
    $verOutput = & $agentPath --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Version: $verOutput" -ForegroundColor Green
    }
} catch {
    Write-Host "FEHLER beim Download: $_" -ForegroundColor Red
    Write-Host "  URL: $agentUrl"
    exit 1
}

# ---------- 4) Erster Heartbeat ----------
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

# ---------- 5) Windows Service einrichten ----------
$serviceName = "HasiCockpitAgent"
$autostartOk = $false

Write-Host "-> Richte Windows Service ein..."

# Alten Service entfernen falls vorhanden
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# Neu erstellen
$binPathArg = '"' + $agentPath + '" --service'
$null = sc.exe create $serviceName binPath= $binPathArg start= auto DisplayName= "Hasi IT-Cockpit Agent" 2>&1
if ($LASTEXITCODE -eq 0) {
    sc.exe description $serviceName "Hasi IT-Cockpit - Endpoint Inventory Agent" | Out-Null
    # Failure recovery: bei Crash 2x neustart innerhalb von 60s
    sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    try {
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-Host "[OK] Service aktiv: $serviceName" -ForegroundColor Green
        $autostartOk = $true
    } catch {
        Write-Host "WARNUNG: Service erstellt, aber Start fehlgeschlagen: $_" -ForegroundColor Yellow
    }
}

# ---------- 6) Fallback: Task Scheduler ----------
if (-not $autostartOk) {
    Write-Host "-> Fallback: Task Scheduler..."
    try {
        $taskName = "HasiCockpitAgent"
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

# ---------- 7) Letzter Fallback: Registry Run-Key ----------
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

# ---------- 8) Abschluss ----------
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

// ============== BULK INSTALL (per tenant, hostname-based auto-enrollment) ==============
async function handleBulkInstallPs1(slug: string, req: Request, env: Env): Promise<Response> {
  const t = await env.DB.prepare(
    `SELECT id, slug, name, install_enabled, status FROM tenants WHERE slug = ?`
  ).bind(slug).first<any>();

  if (!t || t.status !== 'active' || !t.install_enabled) {
    return new Response(
      `Write-Host "FEHLER: Tenant '${slug}' nicht verfuegbar" -ForegroundColor Red\r\nRead-Host "Druecken Sie Enter zum Schliessen"\r\n`,
      { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="hasi-install-${slug}.ps1"` } }
    );
  }

  const url = new URL(req.url);
  const apiUrl = `${url.origin}/api`;
  const cockpitUrl = url.origin.replace('-api.hguencavdi.workers.dev', '.pages.dev');

  // Self-contained .ps1 — fancy output, self-elevate, full install
  const ps1 = `# ============================================================
# Hasi IT-Cockpit Installer
# Mandant: ${t.name}
# Datei: hasi-install-${slug}.ps1
# Rechtsklick -> "Mit PowerShell ausfuehren"  ODER  Doppelklick
# ============================================================

# Self-elevate if not already Admin
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  Administrator-Rechte werden angefordert..." -ForegroundColor Yellow
    Write-Host ""
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \\"$scriptPath\\""
    } else {
        # Wenn ueber Web ausgefuehrt (irm | iex), re-fetch und re-execute as Admin
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command \\"irm '${apiUrl}/install/${slug}.ps1' | iex\\""
    }
    exit
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Fenster-Titel + Farben
$Host.UI.RawUI.WindowTitle = "Hasi IT-Cockpit Installer — ${t.name}"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║" -NoNewline -ForegroundColor Cyan
    Write-Host "  HASI IT-COCKPIT                                            " -NoNewline -ForegroundColor White
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║" -NoNewline -ForegroundColor Cyan
    Write-Host "  Mandant: ${t.name.padEnd(54)}" -NoNewline -ForegroundColor Gray
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Step($num, $total, $msg) {
    $padded = "[$num/$total]"
    Write-Host "  $padded " -NoNewline -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor White
}

function OK($msg) {
    Write-Host "        ✓ " -NoNewline -ForegroundColor Green
    Write-Host $msg -ForegroundColor Gray
}

function Fail($msg) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  ✗ INSTALLATION FEHLGESCHLAGEN                               ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Fehler: $msg" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Druecken Sie Enter zum Schliessen"
    exit 1
}

Clear-Host
Write-Banner

$hostname   = $env:COMPUTERNAME
$apiUrl     = "${apiUrl}"
$bulkToken  = "${t.install_token || ''}"
$installDir = "C:\\Program Files\\HasiCockpit"
$exePath    = "$installDir\\hasi-agent.exe"
$configPath = "$installDir\\config.json"
$statePath  = "$installDir\\state.json"
$taskName   = "HasiCockpitAgent"

Write-Host "  Hostname:  " -NoNewline -ForegroundColor Gray
Write-Host $hostname -ForegroundColor White
Write-Host "  Benutzer:  " -NoNewline -ForegroundColor Gray
Write-Host $env:USERNAME -ForegroundColor White
Write-Host ""

# Step 1: Stop existing agent
Step 1 6 "Pruefe bestehenden Agent..."
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
    OK "Vorhandener Task gestoppt"
}
$procs = Get-Process hasi-agent -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    OK "Laufende Prozesse beendet"
}
Start-Sleep -Seconds 2

# Step 2: Create install directory
Step 2 6 "Erstelle Installations-Verzeichnis..."
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}
OK $installDir

# Step 3: Download latest agent
Step 3 6 "Lade neueste Agent-Version herunter..."
$binaryUrl = "${url.origin}/agent-binary/hasi-agent-windows-amd64.exe"
try {
    Invoke-WebRequest -Uri $binaryUrl -OutFile $exePath -UseBasicParsing
    $size = [math]::Round(((Get-Item $exePath).Length / 1MB), 1)
    OK "$size MB heruntergeladen"
} catch {
    Fail "Download fehlgeschlagen: $_"
}

# Step 4: Bulk enroll
Step 4 6 "Registriere Geraet '$hostname'..."
try {
    $mac = $null
    try { $mac = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1).MacAddress } catch {}
    $mfg = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer
    $model = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
    $body = @{
        bulk_token = $bulkToken
        hostname = $hostname
        os_platform = "windows"
        mac_address = $mac
        manufacturer = $mfg
        model = $model
    } | ConvertTo-Json
    $enrollResp = Invoke-RestMethod -Uri "$apiUrl/agent/bulk-enroll" -Method POST -Body $body -ContentType "application/json"
    OK "Device ID: $($enrollResp.device_id) ($($enrollResp.action))"
} catch {
    Fail "Enrollment fehlgeschlagen: $_"
}

# Step 5: Write config
Step 5 6 "Schreibe Konfiguration..."
$config = @{
    api_url = $apiUrl
    agent_token = $enrollResp.agent_token
    heartbeat_interval_seconds = 900
} | ConvertTo-Json -Compress
Set-Content -Path $configPath -Value $config -Encoding UTF8
$state = @{ device_id = $enrollResp.device_id } | ConvertTo-Json -Compress
Set-Content -Path $statePath -Value $state -Encoding UTF8
OK "config.json + state.json geschrieben"

# Step 6: Task Scheduler
Step 6 6 "Konfiguriere Task Scheduler..."
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
$action = New-ScheduledTaskAction -Execute $exePath
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger2 = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet \`
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries \`
    -StartWhenAvailable -RunOnlyIfNetworkAvailable \`
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) \`
    -Settings $settings -Principal $principal \`
    -Description "Hasi IT-Cockpit Agent — alle 15 Min + bei Boot" -Force | Out-Null

# Task verification
$verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($verifyTask) {
    OK "Task '$taskName' eingerichtet ($($verifyTask.State))"
} else {
    Fail "Task konnte nicht erstellt werden"
}

# First heartbeat — direct exec, verbose, capture exit code
Write-Host ""
Write-Host "  Sende ersten Heartbeat..." -ForegroundColor Cyan
$hbOutput = ""
$hbExit = 1
try {
    $hbOutput = & $exePath --once 2>&1 | Out-String
    $hbExit = $LASTEXITCODE
    if ($hbExit -eq 0) {
        Write-Host "        ✓ Heartbeat erfolgreich" -ForegroundColor Green
        if ($hbOutput.Trim()) { Write-Host ($hbOutput.Trim() -replace '(?m)^', '          ') -ForegroundColor DarkGray }
    } else {
        Write-Host "        ⚠ Heartbeat-Exit-Code: $hbExit" -ForegroundColor Yellow
        if ($hbOutput.Trim()) { Write-Host ($hbOutput.Trim() -replace '(?m)^', '          ') -ForegroundColor Yellow }
        Write-Host "        Task laeuft trotzdem in 15 Min automatisch" -ForegroundColor Gray
    }
} catch {
    Write-Host "        ⚠ Erster Heartbeat Exception: $_" -ForegroundColor Yellow
    Write-Host "        Task laeuft trotzdem in 15 Min automatisch" -ForegroundColor Gray
}

# Force task start (SYSTEM context)
try {
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Start-Sleep -Seconds 2
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskInfo) {
        OK "Task gestartet (LastRunTime: $($taskInfo.LastRunTime), Result: 0x$('{0:X8}' -f $taskInfo.LastTaskResult))"
    }
} catch {
    Write-Host "        ⚠ Task konnte nicht manuell gestartet werden: $_" -ForegroundColor Gray
}

# Write install log for debugging
$logFile = "$installDir\\install.log"
@"
[$([DateTime]::UtcNow.ToString('o'))] Install completed
Hostname: $hostname
User: $env:USERNAME
Device ID: $($enrollResp.device_id)
Agent Token: $($enrollResp.agent_token.Substring(0,16))...
Task: $($verifyTask.State)
HB Exit: $hbExit
HB Output: $hbOutput
"@ | Set-Content -Path $logFile -Encoding UTF8

# Success
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  ✓ INSTALLATION ABGESCHLOSSEN                                ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Hostname:    " -NoNewline -ForegroundColor Gray
Write-Host $hostname -ForegroundColor White
Write-Host "  Device ID:   " -NoNewline -ForegroundColor Gray
Write-Host $enrollResp.device_id -ForegroundColor White
Write-Host "  Status:      " -NoNewline -ForegroundColor Gray
Write-Host $enrollResp.action -ForegroundColor White
Write-Host "  Naechster:   " -NoNewline -ForegroundColor Gray
Write-Host "automatisch in 15 Minuten" -ForegroundColor White
Write-Host ""
Write-Host "  Cockpit:     " -NoNewline -ForegroundColor Gray
Write-Host "${cockpitUrl}" -ForegroundColor Cyan
Write-Host ""
Read-Host "  Druecken Sie Enter zum Schliessen"
`;

  return new Response(ps1.replace(/\r?\n/g, '\r\n'), {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="hasi-install-${slug}.ps1"`,
      'Cache-Control': 'no-cache',
    }
  });
}

async function handleBulkInstallBat(slug: string, req: Request, env: Env): Promise<Response> {
  // Tenant kontrolü
  const t = await env.DB.prepare(
    `SELECT id, slug, name, install_enabled, status FROM tenants WHERE slug = ?`
  ).bind(slug).first<any>();

  if (!t || t.status !== 'active' || !t.install_enabled) {
    return new Response(`@echo off\r\necho FEHLER: Tenant '${slug}' nicht verfuegbar\r\npause\r\nexit /b 1\r\n`, {
      status: 200,
      headers: {
        'Content-Type': 'application/x-msdownload',
        'Content-Disposition': `attachment; filename="hasi-install-${slug}.bat"`,
      }
    });
  }

  const url = new URL(req.url);
  const apiUrl = `${url.origin}/api`;

  // .bat içeriği — self-elevate, sonra PowerShell script'i çağır
  const bat = `@echo off
:: ==========================================================
:: Hasi IT-Cockpit - Installer fuer ${t.name}
:: Doppelklick: Selbst-Elevation zu Admin, dann Installation
:: ==========================================================

setlocal enabledelayedexpansion

:: Pruefe Admin-Rechte
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo  =====================================================
    echo   HASI IT-COCKPIT INSTALLATION
    echo   ${t.name}
    echo  =====================================================
    echo.
    echo  Administrator-Rechte werden angefordert...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Wir sind jetzt Admin
title Hasi IT-Cockpit Installer - ${t.name}
color 0B
cls

echo.
echo  =====================================================
echo   HASI IT-COCKPIT INSTALLATION
echo   ${t.name}
echo  =====================================================
echo.
echo  Hostname: %COMPUTERNAME%
echo  Benutzer: %USERNAME%
echo.

:: Run PowerShell install script
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { irm '${apiUrl}/install/${slug}' | iex } catch { Write-Host ''; Write-Host 'FEHLER:' $_ -ForegroundColor Red; exit 1 }"

if %errorLevel% NEQ 0 (
    echo.
    echo  ===================================================
    echo   INSTALLATION FEHLGESCHLAGEN
    echo  ===================================================
    echo.
    pause
    exit /b 1
)

echo.
echo  ===================================================
echo   INSTALLATION ABGESCHLOSSEN
echo  ===================================================
echo.
echo  Naechstes Heartbeat in 15 Minuten (automatisch)
echo  Im Cockpit: ${url.origin.replace('-api.hguencavdi.workers.dev', '.pages.dev')}
echo.
echo  Druecken Sie eine Taste zum Schliessen...
pause >nul
`;

  return new Response(bat.replace(/\r?\n/g, '\r\n'), {
    status: 200,
    headers: {
      'Content-Type': 'application/x-msdownload',
      'Content-Disposition': `attachment; filename="hasi-install-${slug}.bat"`,
      'Cache-Control': 'no-cache',
    }
  });
}

async function handleBulkInstall(slug: string, req: Request, env: Env): Promise<Response> {
  // Tenant'ı bul + install enabled mi
  const t = await env.DB.prepare(
    `SELECT id, slug, name, install_token, install_enabled, status FROM tenants WHERE slug = ?`
  ).bind(slug).first<any>();

  if (!t) return textResponse(`# Tenant nicht gefunden\nWrite-Host "FEHLER: Tenant '${slug}' nicht gefunden" -ForegroundColor Red\nexit 1`, 404);
  if (t.status !== 'active') return textResponse(`# Tenant inaktiv\nWrite-Host "FEHLER: Tenant '${slug}' ist inaktiv" -ForegroundColor Red\nexit 1`, 403);
  if (!t.install_enabled) return textResponse(`# Bulk install deaktiviert\nWrite-Host "FEHLER: Bulk install ist fuer diesen Mandanten deaktiviert" -ForegroundColor Red\nexit 1`, 403);
  if (!t.install_token) return textResponse(`# Kein Install-Token\nWrite-Host "FEHLER: Kein Install-Token konfiguriert" -ForegroundColor Red\nexit 1`, 500);

  const url = new URL(req.url);
  const apiUrl = `${url.origin}/api`;
  const script = generateBulkInstallScript(t.install_token, apiUrl, t.name, t.slug).replace(/\r?\n/g, '\r\n');
  return textResponse(script, 200, 'text/plain');
}

function generateBulkInstallScript(bulkToken: string, apiUrl: string, tenantName: string, tenantSlug: string): string {
  const origin = apiUrl.replace('/api', '');
  return `# ===================================================================
# Hasi IT-Cockpit - Bulk Install Script
# Mandant: ${tenantName}
# ===================================================================
# Usage: irm ${apiUrl.replace('/api', '')}/api/install/${tenantSlug} | iex
#
# Self-elevating: relaunches as Admin if not already

# Self-elevate to Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "🔐 Administrator-Rechte erforderlich. Starte neu..." -ForegroundColor Yellow
    $script = "irm ${apiUrl}/install/${tenantSlug} | iex"
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -Command \\"$script\\""
    exit
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  HASI IT-COCKPIT - Bulk Install                              ║" -ForegroundColor Cyan
Write-Host "║  Mandant: ${tenantName.padEnd(52)}║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$hostname = $env:COMPUTERNAME
$apiUrl   = "${apiUrl}"
$bulkToken = "${bulkToken}"
$installDir = "C:\\Program Files\\HasiCockpit"
$exePath   = "$installDir\\hasi-agent.exe"
$configPath = "$installDir\\config.json"
$statePath = "$installDir\\state.json"
$taskName  = "HasiCockpitAgent"

# Step 1: Stop existing agent (if any)
Write-Host "[1/6] Pruefe bestehenden Agent..." -ForegroundColor White
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
    Write-Host "      Bestehender Task gestoppt" -ForegroundColor Gray
}
Get-Process hasi-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 2: Create install directory
Write-Host "[2/6] Erstelle Installations-Verzeichnis..." -ForegroundColor White
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Step 3: Download latest agent binary
Write-Host "[3/6] Lade Agent v(latest) herunter..." -ForegroundColor White
$binaryUrl = "${origin}/agent-binary/hasi-agent-windows-amd64.exe"
try {
    Invoke-WebRequest -Uri $binaryUrl -OutFile $exePath -UseBasicParsing
    $size = (Get-Item $exePath).Length / 1MB
    Write-Host "      Heruntergeladen: $([math]::Round($size,1)) MB" -ForegroundColor Gray
} catch {
    Write-Host "FEHLER: Download fehlgeschlagen: $_" -ForegroundColor Red
    exit 1
}

# Step 4: Bulk enroll (hostname-based)
Write-Host "[4/6] Registriere Geraet '$hostname'..." -ForegroundColor White
$enrollBody = @{
    bulk_token = $bulkToken
    hostname   = $hostname
    os_platform = "windows"
    mac_address = ((Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1).MacAddress)
    manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
    model       = (Get-CimInstance Win32_ComputerSystem).Model
} | ConvertTo-Json
try {
    $enrollResp = Invoke-RestMethod -Uri "$apiUrl/agent/bulk-enroll" -Method POST -Body $enrollBody -ContentType "application/json"
    Write-Host "      Geraet registriert (ID: $($enrollResp.device_id), Status: $($enrollResp.action))" -ForegroundColor Gray
} catch {
    Write-Host "FEHLER: Enrollment fehlgeschlagen: $_" -ForegroundColor Red
    exit 1
}

# Step 5: Save config + agent token
Write-Host "[5/6] Schreibe Konfiguration..." -ForegroundColor White
$config = @{
    api_url = $apiUrl
    agent_token = $enrollResp.agent_token
    heartbeat_interval_seconds = 900
} | ConvertTo-Json
Set-Content -Path $configPath -Value $config -Encoding UTF8

$state = @{ device_id = $enrollResp.device_id } | ConvertTo-Json
Set-Content -Path $statePath -Value $state -Encoding UTF8

# Step 6: Register Task Scheduler (auto-start every 15 min + at boot)
Write-Host "[6/6] Erstelle Task Scheduler-Eintrag..." -ForegroundColor White
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

$action = New-ScheduledTaskAction -Execute $exePath
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet \`
    -AllowStartIfOnBatteries \`
    -DontStopIfGoingOnBatteries \`
    -StartWhenAvailable \`
    -RunOnlyIfNetworkAvailable \`
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) \`
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1,$trigger2) \`
    -Settings $settings -Principal $principal \`
    -Description "Hasi IT-Cockpit - Endpoint Inventory Agent" -Force | Out-Null

# First heartbeat
Write-Host ""
Write-Host "Erste Heartbeat..." -ForegroundColor White
& $exePath --once
Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

# Done
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✓ FERTIG                                                    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Hostname:    $hostname" -ForegroundColor White
Write-Host "  Device ID:   $($enrollResp.device_id)" -ForegroundColor White
Write-Host "  Status:      $($enrollResp.action)" -ForegroundColor White
Write-Host "  Naechster Heartbeat: in 15 Minuten (automatisch)" -ForegroundColor White
Write-Host ""
Write-Host "  Im Cockpit anzeigen: ${origin.replace('-api.hguencavdi.workers.dev', '.pages.dev')}" -ForegroundColor Cyan
Write-Host ""
`;
}

async function handleBulkEnroll(req: Request, env: Env): Promise<Response> {
  const body = await req.json<any>();
  const bulkToken = String(body.bulk_token || '');
  const hostname = String(body.hostname || '').trim();
  if (!bulkToken || !hostname) return jsonError('bulk_token + hostname erforderlich', 400);

  // Token'a uyan tenant'ı bul
  const t = await env.DB.prepare(
    `SELECT id, slug FROM tenants WHERE install_token = ? AND install_enabled = 1 AND status = 'active'`
  ).bind(bulkToken).first<any>();
  if (!t) return jsonError('Ungueltiges Bulk-Token oder Tenant deaktiviert', 401);

  // Var olan cihaz mı (hostname match — case-insensitive)
  let device = await env.DB.prepare(
    `SELECT id, hostname FROM devices WHERE tenant_id = ? AND LOWER(hostname) = LOWER(?)`
  ).bind(t.id, hostname).first<any>();

  let deviceId: number;
  let action: string;
  if (device) {
    deviceId = device.id;
    action = 're-enrolled';
    // Update meta fields
    await env.DB.prepare(`
      UPDATE devices SET
        manufacturer = COALESCE(?, manufacturer),
        model = COALESCE(?, model),
        mac_address = COALESCE(?, mac_address),
        agent_status = 'pending',
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(body.manufacturer || null, body.model || null, body.mac_address || null, deviceId).run();
  } else {
    // Create new device
    const r = await env.DB.prepare(`
      INSERT INTO devices (tenant_id, hostname, manufacturer, model, mac_address, os, auto_discovered, bulk_enrolled, agent_status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, 1, 'pending', datetime('now'), datetime('now'))
    `).bind(t.id, hostname, body.manufacturer || null, body.model || null, body.mac_address || null, body.os_platform || 'windows').run();
    deviceId = Number(r.meta.last_row_id);
    action = 'new';
  }

  // Revoke old agents for this device
  await env.DB.prepare(
    `UPDATE agents SET status = 'revoked', revoked_at = datetime('now') WHERE device_id = ? AND status = 'active'`
  ).bind(deviceId).run();

  // Create new agent + token (her seferinde UNIQUE enroll_token üret — sadece audit trail için)
  const agentToken = 'AGT-' + crypto.randomUUID().replace(/-/g, '');
  const enrollToken = 'BULK-' + crypto.randomUUID().replace(/-/g, '');
  await env.DB.prepare(`
    INSERT INTO agents (tenant_id, device_id, enroll_token, agent_token, agent_version, os_platform, hostname_reported, status, created_at)
    VALUES (?, ?, ?, ?, '0.5.4', ?, ?, 'active', datetime('now'))
  `).bind(t.id, deviceId, enrollToken, agentToken, body.os_platform || 'windows', hostname).run();

  return json({
    ok: true,
    device_id: deviceId,
    agent_token: agentToken,
    tenant_slug: t.slug,
    action,
  });
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

// v0.5.10: Standalone installer .exe (per tenant, baked-in token)
async function handleInstallerExe(slug: string, env: Env): Promise<Response> {
  // Verify tenant exists + install enabled (security check)
  const t = await env.DB.prepare(
    `SELECT id, status, install_enabled FROM tenants WHERE slug = ?`
  ).bind(slug).first<any>();
  if (!t || t.status !== 'active' || !t.install_enabled) {
    return new Response('Installer not available for this tenant', { status: 404 });
  }

  const obj = await env.AGENTS.get(`installers/hasi-install-${slug}.exe`);
  if (!obj) return new Response('Installer binary not built yet for this tenant', { status: 404 });

  return new Response(obj.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="hasi-install-${slug}.exe"`,
      'Cache-Control': 'no-cache',
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

async function handleAlertTestEmail(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const r = await sendTestEmail(env, sess.tenant_id);
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

// ============== REMOTE COMMANDS ==============

const COMMAND_TYPES = new Set(['ping', 'msg', 'lock', 'reboot', 'ps', 'cmd']);
const DANGEROUS_TYPES = new Set(['reboot', 'ps', 'cmd']);

interface CommandArgs {
  message?: string;       // for 'msg'
  script?: string;        // for 'ps'
  command?: string;       // for 'cmd'
  delay_seconds?: number; // for 'reboot' (default 60)
}

function validateCommand(type: string, args: CommandArgs): { ok: boolean; error?: string } {
  if (!COMMAND_TYPES.has(type)) return { ok: false, error: `Unbekannter Command-Typ: ${type}` };
  if (type === 'msg') {
    if (!args.message || args.message.length < 1) return { ok: false, error: 'message ist erforderlich' };
    if (args.message.length > 500) return { ok: false, error: 'Nachricht zu lang (max 500 Zeichen)' };
  }
  if (type === 'ps') {
    if (!args.script || args.script.length < 1) return { ok: false, error: 'script ist erforderlich' };
    if (args.script.length > 8000) return { ok: false, error: 'Skript zu lang (max 8000 Zeichen)' };
  }
  if (type === 'cmd') {
    if (!args.command || args.command.length < 1) return { ok: false, error: 'command ist erforderlich' };
    if (args.command.length > 4000) return { ok: false, error: 'Befehl zu lang (max 4000 Zeichen)' };
  }
  if (type === 'reboot' && args.delay_seconds != null) {
    if (args.delay_seconds < 0 || args.delay_seconds > 3600) return { ok: false, error: 'delay_seconds 0..3600' };
  }
  return { ok: true };
}

// Cockpit: list commands for a device (history + queue)
async function handleCommandsList(req: Request, env: Env, sess: Session): Promise<Response> {
  const url = new URL(req.url);
  const deviceId = url.searchParams.get('device_id');
  const limit = Math.min(Number(url.searchParams.get('limit') || 50), 200);
  let res;
  if (deviceId) {
    res = await env.DB.prepare(`
      SELECT c.*, u.email AS created_by_email
      FROM commands c LEFT JOIN users u ON u.id = c.created_by
      WHERE c.tenant_id = ? AND c.device_id = ?
      ORDER BY c.id DESC LIMIT ?
    `).bind(sess.tenant_id, Number(deviceId), limit).all();
  } else {
    res = await env.DB.prepare(`
      SELECT c.*, u.email AS created_by_email, d.hostname AS device_hostname
      FROM commands c
      LEFT JOIN users u ON u.id = c.created_by
      LEFT JOIN devices d ON d.id = c.device_id
      WHERE c.tenant_id = ?
      ORDER BY c.id DESC LIMIT ?
    `).bind(sess.tenant_id, limit).all();
  }
  return json({ items: res.results });
}

// Cockpit: dispatch a new command to a device
async function handleCommandDispatch(req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const body = await req.json<any>();
  const deviceId = Number(body.device_id);
  const type = String(body.command_type || '');
  const args = (body.command_args || {}) as CommandArgs;
  const notes = body.notes || null;

  // Validate device belongs to tenant
  const dev = await env.DB.prepare(`SELECT id, tenant_id, hostname FROM devices WHERE id = ? AND tenant_id = ?`)
    .bind(deviceId, sess.tenant_id).first<any>();
  if (!dev) return jsonError('Geraet nicht gefunden', 404);

  // Find active agent for that device
  const agent = await env.DB.prepare(`
    SELECT id FROM agents WHERE tenant_id = ? AND device_id = ? AND status='active' ORDER BY id DESC LIMIT 1
  `).bind(sess.tenant_id, deviceId).first<any>();
  if (!agent) return jsonError('Kein aktiver Agent fuer dieses Geraet', 400);

  const v = validateCommand(type, args);
  if (!v.ok) return jsonError(v.error!, 400);

  // Block too many queued commands for one device
  const queued = await env.DB.prepare(`SELECT COUNT(*) AS n FROM commands WHERE device_id = ? AND status='queued'`)
    .bind(deviceId).first<any>();
  if ((queued?.n || 0) >= 5) return jsonError('Zu viele wartende Befehle. Bitte abwarten oder abbrechen.', 429);

  const r = await env.DB.prepare(`
    INSERT INTO commands (tenant_id, device_id, agent_id, command_type, command_args, status, created_by, notes, timeout_seconds)
    VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)
  `).bind(sess.tenant_id, deviceId, agent.id, type, JSON.stringify(args), sess.user_id, notes,
          type === 'ps' || type === 'cmd' ? 180 : 60).run();

  await logAudit(env, sess, 'dispatch', 'command', r.meta.last_row_id, { type, device_id: deviceId, hostname: dev.hostname }, req.headers.get('CF-Connecting-IP'));

  return json({ ok: true, command_id: r.meta.last_row_id });
}

// Cockpit: cancel a queued command
async function handleCommandCancel(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  if (sess.role !== 'super_admin' && sess.role !== 'admin') return jsonError('Keine Berechtigung', 403);
  const r = await env.DB.prepare(`
    UPDATE commands SET status='cancelled', completed_at=datetime('now'), error_message='Vom Admin abgebrochen'
    WHERE id = ? AND tenant_id = ? AND status='queued'
  `).bind(id, sess.tenant_id).run();
  if (r.meta.changes === 0) return jsonError('Befehl nicht abbrechbar (bereits in Bearbeitung?)', 404);
  return json({ ok: true });
}

// Agent: fetch pending commands (called every heartbeat OR fast-poll)
async function handleAgentCommandsFetch(req: Request, env: Env): Promise<Response> {
  const token = req.headers.get('X-Agent-Token');
  if (!token) return jsonError('Token fehlt', 401);
  const agent = await env.DB.prepare(`SELECT id, tenant_id, device_id, status FROM agents WHERE agent_token = ?`).bind(token).first<any>();
  if (!agent || agent.status !== 'active') return jsonError('Token ungueltig', 401);

  // Pick all queued commands for this agent, mark as 'sent'
  const cmds = await env.DB.prepare(`
    SELECT id, command_type, command_args, timeout_seconds
    FROM commands WHERE agent_id = ? AND status = 'queued'
    ORDER BY id ASC LIMIT 10
  `).bind(agent.id).all<any>();

  const items = (cmds.results || []).map((c: any) => ({
    id: c.id,
    type: c.command_type,
    args: c.command_args ? JSON.parse(c.command_args) : {},
    timeout: c.timeout_seconds,
  }));

  // Mark as sent
  for (const c of items) {
    await env.DB.prepare(`UPDATE commands SET status='sent', picked_at=datetime('now') WHERE id = ? AND status='queued'`)
      .bind(c.id).run();
  }

  // Mark stuck 'sent' commands as timeout (defensive)
  await env.DB.prepare(`
    UPDATE commands SET status='timeout', completed_at=datetime('now'), error_message='Agent hat sich nicht zurueckgemeldet'
    WHERE agent_id = ? AND status IN ('sent','running')
      AND picked_at < datetime('now', '-' || (timeout_seconds + 60) || ' seconds')
  `).bind(agent.id).run();

  return json({ commands: items });
}

// Agent: post command result
async function handleAgentCommandResult(id: number, req: Request, env: Env): Promise<Response> {
  const token = req.headers.get('X-Agent-Token');
  if (!token) return jsonError('Token fehlt', 401);
  const agent = await env.DB.prepare(`SELECT id FROM agents WHERE agent_token = ? AND status='active'`).bind(token).first<any>();
  if (!agent) return jsonError('Token ungueltig', 401);

  const body = await req.json<any>();
  const status = body.status === 'done' || body.status === 'error' ? body.status : 'done';
  const stdout = (body.stdout || '').slice(0, 16000);
  const stderr = (body.stderr || '').slice(0, 4000);
  const exitCode = body.exit_code != null ? Number(body.exit_code) : null;
  const errorMessage = body.error_message || null;

  const r = await env.DB.prepare(`
    UPDATE commands SET status=?, completed_at=datetime('now'),
           result_stdout=?, result_stderr=?, result_exit=?, error_message=?
    WHERE id=? AND agent_id=? AND status IN ('sent','running')
  `).bind(status, stdout, stderr, exitCode, errorMessage, id, agent.id).run();

  if (r.meta.changes === 0) return jsonError('Befehl bereits abgeschlossen oder gehoert nicht zu diesem Agent', 404);
  return json({ ok: true });
}

// ============== TENANT MANAGEMENT (super_admin only) ==============

function requireSuperAdmin(sess: Session): Response | null {
  if (sess.role !== 'super_admin') return jsonError('Nur Super-Admins koennen Mandanten verwalten', 403);
  return null;
}

async function handleTenantsList(req: Request, env: Env, sess: Session): Promise<Response> {
  const err = requireSuperAdmin(sess); if (err) return err;
  const tenants = await env.DB.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM devices WHERE tenant_id = t.id) AS device_count,
      (SELECT COUNT(*) FROM agents WHERE tenant_id = t.id AND status='active') AS agent_count,
      (SELECT COUNT(*) FROM users WHERE tenant_id = t.id) AS user_count,
      (SELECT COUNT(*) FROM alerts WHERE tenant_id = t.id AND status IN ('open','acknowledged') AND severity='critical') AS critical_alerts,
      (SELECT COUNT(*) FROM alerts WHERE tenant_id = t.id AND status IN ('open','acknowledged') AND severity='warning') AS warning_alerts,
      (SELECT ROUND(AVG(s.security_score), 0)
        FROM security_status s JOIN devices d ON d.id = s.device_id
        WHERE d.tenant_id = t.id) AS avg_security_score
    FROM tenants t
    ORDER BY t.id ASC
  `).all();
  return json({ items: tenants.results });
}

async function handleTenantCreate(req: Request, env: Env, sess: Session): Promise<Response> {
  const err = requireSuperAdmin(sess); if (err) return err;
  const body = await req.json<any>();
  const slug = String(body.slug || '').toLowerCase().trim();
  const name = String(body.name || '').trim();
  if (!slug || !name) return jsonError('slug und name erforderlich', 400);
  if (!/^[a-z0-9][a-z0-9-]{1,40}$/.test(slug)) return jsonError('slug: nur Kleinbuchstaben, Zahlen, Bindestrich (2-40 Zeichen)', 400);

  // Check duplicate
  const dup = await env.DB.prepare('SELECT id FROM tenants WHERE slug = ?').bind(slug).first();
  if (dup) return jsonError('Slug bereits vergeben', 400);

  const r = await env.DB.prepare(`
    INSERT INTO tenants (slug, name, plan, device_quota, status, contact_name, contact_email, contact_phone, address, city, industry, monthly_fee, notes, updated_at, created_at)
    VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `).bind(
    slug, name,
    body.plan || 'starter',
    body.device_quota || 50,
    body.contact_name || null,
    body.contact_email || null,
    body.contact_phone || null,
    body.address || null,
    body.city || null,
    body.industry || null,
    Number(body.monthly_fee) || 0,
    body.notes || null
  ).run();

  // Auto-seed alert settings for new tenant
  await env.DB.prepare('INSERT OR IGNORE INTO alert_settings (tenant_id) VALUES (?)').bind(r.meta.last_row_id).run();

  await logAudit(env, sess, 'create', 'tenant', r.meta.last_row_id, { slug, name }, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true, id: r.meta.last_row_id });
}

async function handleTenantUpdate(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const err = requireSuperAdmin(sess); if (err) return err;
  const body = await req.json<any>();
  const allowed = ['name','plan','device_quota','status','contact_name','contact_email','contact_phone','address','city','industry','monthly_fee','notes'];
  const setParts: string[] = []; const values: any[] = [];
  for (const k of allowed) if (k in body) { setParts.push(`${k} = ?`); values.push(body[k]); }
  if (setParts.length === 0) return jsonError('Keine Aenderungen', 400);
  setParts.push(`updated_at = datetime('now')`);
  values.push(id);
  await env.DB.prepare(`UPDATE tenants SET ${setParts.join(', ')} WHERE id = ?`).bind(...values).run();
  await logAudit(env, sess, 'update', 'tenant', id, body, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

async function handleTenantDelete(id: number, req: Request, env: Env, sess: Session): Promise<Response> {
  const err = requireSuperAdmin(sess); if (err) return err;
  if (id === sess.home_tenant_id) return jsonError('Eigener Mandant kann nicht geloescht werden', 400);
  // Cascading delete via FK ON DELETE CASCADE
  const r = await env.DB.prepare('DELETE FROM tenants WHERE id = ?').bind(id).run();
  if (r.meta.changes === 0) return jsonError('Mandant nicht gefunden', 404);
  await logAudit(env, sess, 'delete', 'tenant', id, {}, req.headers.get('CF-Connecting-IP'));
  return json({ ok: true });
}

// Switch active tenant (impersonation for super_admin)
async function handleTenantSwitch(req: Request, env: Env, sess: Session): Promise<Response> {
  const err = requireSuperAdmin(sess); if (err) return err;
  const body = await req.json<any>();
  const targetSlug = String(body.tenant_slug || '');
  if (!targetSlug) return jsonError('tenant_slug erforderlich', 400);

  const t = await env.DB.prepare('SELECT id, slug, name, plan FROM tenants WHERE slug = ? AND status = "active"').bind(targetSlug).first<any>();
  if (!t) return jsonError('Mandant nicht gefunden', 404);

  // Issue new token with switched tenant context
  const newSess: Session = {
    ...sess,
    tenant_id: t.id, tenant_slug: t.slug, tenant_name: t.name, plan: t.plan,
    token: ''
  };
  const tokenPayload = { ...newSess, exp: Date.now() + 8 * 3600 * 1000 };
  const newToken = await makeToken(env.TOKEN_SECRET, tokenPayload);
  newSess.token = newToken;

  await logAudit(env, sess, 'switch', 'tenant', t.id, { from: sess.tenant_slug, to: t.slug }, req.headers.get('CF-Connecting-IP'));
  return json(newSess);
}

// ============== ROUTER ==============
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    const url = new URL(req.url);
    const path = url.pathname;
    const m = req.method;

    try {
      if (path === '/health') return json({ status: 'ok', version: '0.5.10', time: new Date().toISOString() });
      if (path === '/api/auth/login' && m === 'POST') return handleLogin(req, env);

      // Public agent endpoints
      if (path === '/api/agent/register' && m === 'POST') return handleAgentRegister(req, env);
      if (path === '/api/agent/bulk-enroll' && m === 'POST') return handleBulkEnroll(req, env);
      if (path === '/api/agent/heartbeat' && m === 'POST') return handleAgentHeartbeat(req, env);
      if (path === '/api/agent/commands' && m === 'GET') return handleAgentCommandsFetch(req, env);
      const cmdResMatch = path.match(/^\/api\/agent\/commands\/(\d+)\/result$/);
      if (cmdResMatch && m === 'POST') return handleAgentCommandResult(Number(cmdResMatch[1]), req, env);
      const isMatch = path.match(/^\/api\/install-script\/(.+)$/);
      if (isMatch && m === 'GET') return handleInstallScript(isMatch[1], req, env);
      // v0.5.5: Bulk install per tenant — sadece slug ile
      const bulkMatch = path.match(/^\/api\/install\/([a-z0-9_-]+)$/);
      if (bulkMatch && m === 'GET') return handleBulkInstall(bulkMatch[1], req, env);
      // v0.5.6: .bat installer (double-click → Als Admin ausführen)
      const batMatch = path.match(/^\/api\/install\/([a-z0-9_-]+)\.bat$/);
      if (batMatch && m === 'GET') return handleBulkInstallBat(batMatch[1], req, env);
      // v0.5.7: .ps1 installer (fancier — rechtsklick → "Mit PowerShell ausführen")
      const ps1Match = path.match(/^\/api\/install\/([a-z0-9_-]+)\.ps1$/);
      if (ps1Match && m === 'GET') return handleBulkInstallPs1(ps1Match[1], req, env);
      // v0.5.10: Standalone .exe installer (recommended — double-click, self-elevating)
      const exeMatch = path.match(/^\/api\/install\/([a-z0-9_-]+)\.exe$/);
      if (exeMatch && m === 'GET') return handleInstallerExe(exeMatch[1], env);

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
      mt = path.match(/^\/api\/devices\/(\d+)\/disks$/);
      if (mt && m === 'GET') return handleDeviceDisks(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/processes$/);
      if (mt && m === 'GET') return handleDeviceProcesses(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/browsers$/);
      if (mt && m === 'GET') return handleDeviceBrowsers(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/devices\/(\d+)\/antivirus$/);
      if (mt && m === 'GET') return handleDeviceAntivirus(Number(mt[1]), req, env, sess);

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
      if (path === '/api/alerts/test-email' && m === 'POST') return handleAlertTestEmail(req, env, sess);
      if (path === '/api/alerts/evaluate' && m === 'POST') return handleAlertEvaluate(req, env, sess);
      mt = path.match(/^\/api\/alerts\/(\d+)\/acknowledge$/);
      if (mt && m === 'POST') return handleAlertAck(Number(mt[1]), req, env, sess);
      mt = path.match(/^\/api\/alerts\/(\d+)\/resolve$/);
      if (mt && m === 'POST') return handleAlertResolve(Number(mt[1]), req, env, sess);

      // Remote commands
      if (path === '/api/commands' && m === 'GET') return handleCommandsList(req, env, sess);
      if (path === '/api/commands' && m === 'POST') return handleCommandDispatch(req, env, sess);
      mt = path.match(/^\/api\/commands\/(\d+)\/cancel$/);
      if (mt && m === 'POST') return handleCommandCancel(Number(mt[1]), req, env, sess);

      // Tenant management (super_admin)
      if (path === '/api/tenants' && m === 'GET') return handleTenantsList(req, env, sess);
      if (path === '/api/tenants' && m === 'POST') return handleTenantCreate(req, env, sess);
      if (path === '/api/tenants/switch' && m === 'POST') return handleTenantSwitch(req, env, sess);
      mt = path.match(/^\/api\/tenants\/(\d+)$/);
      if (mt && m === 'PUT') return handleTenantUpdate(Number(mt[1]), req, env, sess);
      if (mt && m === 'DELETE') return handleTenantDelete(Number(mt[1]), req, env, sess);

      // v0.5.0: Monatsbericht (manuell triggern, super_admin)
      if (path === '/api/reports/monthly/generate' && m === 'POST') {
        const err = requireSuperAdmin(sess); if (err) return err;
        if (!env.BROWSER_RENDERING_TOKEN || !env.CF_ACCOUNT_ID || !env.RESEND_API_KEY) {
          return jsonError('BROWSER_RENDERING_TOKEN / CF_ACCOUNT_ID / RESEND_API_KEY fehlt', 500);
        }
        try {
          const r = await generateMonthlyReports(env as any);
          return json({ ok: true, ...r });
        } catch(e: any) {
          return jsonError('Report-Generierung fehlgeschlagen: ' + (e.message || e), 500);
        }
      }

      return jsonError('Not Found', 404);
    } catch(e: any) {
      console.error(e);
      return jsonError(e.message || 'Internal error', 500);
    }
  },

  // ============== CRON: alert evaluator (every 15 min) + monthly report (1st of month, 09:00) ==============
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const cron = event.cron;
    console.log(`[cron] triggered: ${cron} at ${new Date().toISOString()}`);
    try {
      if (cron === '0 9 1 * *') {
        // Monthly Hausmeister report
        if (env.BROWSER_RENDERING_TOKEN && env.CF_ACCOUNT_ID && env.RESEND_API_KEY) {
          const r = await generateMonthlyReports(env as any);
          console.log('[cron] monthly report:', JSON.stringify(r));
        } else {
          console.warn('[cron] monthly report skipped — missing BROWSER_RENDERING_TOKEN/CF_ACCOUNT_ID/RESEND_API_KEY');
        }
      } else {
        // Default: */15 * * * * → alert evaluator
        const result = await evaluateAlerts(env);
        console.log(`[cron] alert evaluator result:`, JSON.stringify(result));
      }
    } catch (e: any) {
      console.error(`[cron] error:`, e.message || e);
    }
  }
};
