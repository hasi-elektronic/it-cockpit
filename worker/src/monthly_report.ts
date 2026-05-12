// Aylık Hausmeister Raporu — her ayın 1'inde 09:00 UTC tetiklenir
// CF Browser Rendering ile HTML→PDF, Resend ile e-posta gönder

interface Env {
  DB: D1Database;
  BROWSER_RENDERING_TOKEN: string;
  RESEND_API_KEY: string;
  CF_ACCOUNT_ID: string;
}

interface TenantReportData {
  tenant: {
    id: number;
    name: string;
    contact_name: string | null;
    contact_email: string | null;
    monthly_fee: number | null;
  };
  period: { from: string; to: string; label: string };
  fleet: {
    total_devices: number;
    online: number;
    avg_score: number | null;
    healthy: number;
    moderate: number;
    poor: number;
  };
  alerts: {
    total: number;
    resolved: number;
    by_severity: { critical: number; warning: number; info: number };
    by_rule: Array<{ rule_key: string; count: number }>;
  };
  remoteActions: {
    total: number;
    by_type: Array<{ command_type: string; count: number }>;
  };
  topRisks: Array<{
    hostname: string;
    security_score: number | null;
    issues: string;
  }>;
  patchSummary: {
    devices_with_pending: number;
    total_pending: number;
    avg_pending_per_device: number;
  };
}

export async function generateMonthlyReports(env: Env): Promise<{ generated: number; errors: number }> {
  console.log('[monthly-report] starting…');
  let generated = 0;
  let errors = 0;

  // Hangi tenant'lar e-posta almak istiyor?
  const tenants = await env.DB.prepare(
    `SELECT t.id, t.name, t.contact_name, t.contact_email, t.monthly_fee
     FROM tenants t
     WHERE t.status = 'active' AND t.contact_email IS NOT NULL`
  ).all<any>();

  if (!tenants.results || tenants.results.length === 0) {
    console.log('[monthly-report] no eligible tenants');
    return { generated: 0, errors: 0 };
  }

  // "Geçen ay" tanımı (rapor 1. günde çalışır, geçen ayın 1-30'unu kapsar)
  const now = new Date();
  const firstOfThisMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const lastMonthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const fromISO = lastMonthStart.toISOString().slice(0, 10);
  const toISO = firstOfThisMonth.toISOString().slice(0, 10);
  const monthLabel = lastMonthStart.toLocaleDateString('de-DE', { month: 'long', year: 'numeric' });

  for (const t of tenants.results) {
    try {
      const data = await collectTenantReportData(env, t, { from: fromISO, to: toISO, label: monthLabel });
      const html = renderReportHTML(data);
      const pdfBytes = await htmlToPDF(env, html);
      await sendReportEmail(env, data, pdfBytes);
      generated++;
      console.log(`[monthly-report] sent to ${t.contact_email} (tenant ${t.id})`);
    } catch (e: any) {
      errors++;
      console.error(`[monthly-report] tenant ${t.id} failed:`, e.message || e);
    }
  }

  return { generated, errors };
}

async function collectTenantReportData(env: Env, t: any, period: { from: string; to: string; label: string }): Promise<TenantReportData> {
  // Fleet snapshot
  const fleet = await env.DB.prepare(`
    SELECT COUNT(*) AS total_devices,
      SUM(CASE WHEN agent_status='online' THEN 1 ELSE 0 END) AS online
    FROM devices WHERE tenant_id = ?
  `).bind(t.id).first<any>();

  const health = await env.DB.prepare(`
    SELECT AVG(security_score) AS avg_score,
      SUM(CASE WHEN security_score >= 80 THEN 1 ELSE 0 END) AS healthy,
      SUM(CASE WHEN security_score >= 60 AND security_score < 80 THEN 1 ELSE 0 END) AS moderate,
      SUM(CASE WHEN security_score < 60 THEN 1 ELSE 0 END) AS poor
    FROM security_status WHERE tenant_id = ? AND security_score IS NOT NULL
  `).bind(t.id).first<any>();

  // Alerts in period
  const alerts = await env.DB.prepare(`
    SELECT COUNT(*) AS total,
      SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved,
      SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END) AS warning,
      SUM(CASE WHEN severity='info' THEN 1 ELSE 0 END) AS info
    FROM alerts WHERE tenant_id = ? AND first_seen >= ? AND first_seen < ?
  `).bind(t.id, period.from, period.to).first<any>();

  const alertsByRule = await env.DB.prepare(`
    SELECT rule_key, COUNT(*) AS count
    FROM alerts WHERE tenant_id = ? AND first_seen >= ? AND first_seen < ?
    GROUP BY rule_key ORDER BY count DESC LIMIT 8
  `).bind(t.id, period.from, period.to).all<any>();

  // Remote actions
  const actions = await env.DB.prepare(`
    SELECT COUNT(*) AS total FROM commands WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
  `).bind(t.id, period.from, period.to).first<any>();

  const actionsByType = await env.DB.prepare(`
    SELECT command_type, COUNT(*) AS count
    FROM commands WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
    GROUP BY command_type ORDER BY count DESC
  `).bind(t.id, period.from, period.to).all<any>();

  // Top risks (lowest score devices)
  const topRisks = await env.DB.prepare(`
    SELECT d.hostname, s.security_score,
      CASE
        WHEN s.bitlocker_enabled = 0 THEN 'BitLocker aus'
        WHEN s.av_enabled = 0 THEN 'Antivirus inaktiv'
        WHEN s.tpm_ready = 0 THEN 'TPM nicht bereit'
        WHEN s.pending_reboot = 1 THEN 'Neustart ausstehend'
        WHEN s.wu_critical_count > 0 THEN s.wu_critical_count || ' krit. Updates'
        ELSE 'Mehrere kleinere Punkte'
      END AS issues
    FROM devices d
    LEFT JOIN security_status s ON s.device_id = d.id
    WHERE d.tenant_id = ? AND s.security_score IS NOT NULL
    ORDER BY s.security_score ASC LIMIT 5
  `).bind(t.id).all<any>();

  // Patch summary
  const patches = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN wu_pending_count > 0 THEN 1 ELSE 0 END) AS devices_with_pending,
      SUM(wu_pending_count) AS total_pending,
      AVG(wu_pending_count) AS avg_pending
    FROM security_status WHERE tenant_id = ?
  `).bind(t.id).first<any>();

  return {
    tenant: t,
    period,
    fleet: {
      total_devices: fleet?.total_devices || 0,
      online: fleet?.online || 0,
      avg_score: health?.avg_score ? Math.round(health.avg_score) : null,
      healthy: health?.healthy || 0,
      moderate: health?.moderate || 0,
      poor: health?.poor || 0,
    },
    alerts: {
      total: alerts?.total || 0,
      resolved: alerts?.resolved || 0,
      by_severity: {
        critical: alerts?.critical || 0,
        warning: alerts?.warning || 0,
        info: alerts?.info || 0,
      },
      by_rule: alertsByRule.results || [],
    },
    remoteActions: {
      total: actions?.total || 0,
      by_type: actionsByType.results || [],
    },
    topRisks: topRisks.results || [],
    patchSummary: {
      devices_with_pending: patches?.devices_with_pending || 0,
      total_pending: patches?.total_pending || 0,
      avg_pending_per_device: patches?.avg_pending ? Math.round(patches.avg_pending) : 0,
    },
  };
}

function ruleLabel(key: string): string {
  const map: Record<string, string> = {
    disk_critical: 'Disk kritisch voll',
    disk_warning: 'Disk fuellt sich',
    av_disabled: 'Antivirus aus',
    av_outdated: 'AV-Signaturen alt',
    bitlocker_off: 'BitLocker aus',
    agent_offline_warning: 'Agent offline (warn)',
    agent_offline_critical: 'Agent offline (kritisch)',
    wu_critical: 'Kritische Updates',
    new_device: 'Neues Geraet',
    pending_reboot: 'Neustart ausstehend',
    uptime_long: 'Lange ohne Reboot',
    smart_warning: 'Festplatten-Problem',
    failed_logon_spike: 'Login-Spike',
    browser_outdated: 'Browser veraltet',
    patch_high: 'Viele Updates',
    battery_wear: 'Akku gealtert',
    defender_tamper_off: 'Defender Tamper aus',
  };
  return map[key] || key;
}

function commandLabel(t: string): string {
  const map: Record<string, string> = {
    ping: 'Ping (Status)', msg: 'Nachricht senden', lock: 'PC sperren',
    reboot: 'Neustart', ps: 'PowerShell-Skript', cmd: 'CMD-Befehl',
  };
  return map[t] || t;
}

function renderReportHTML(d: TenantReportData): string {
  const fleetHealth = d.fleet.total_devices > 0
    ? Math.round(((d.fleet.healthy + d.fleet.moderate * 0.6) / d.fleet.total_devices) * 100)
    : 0;

  return `<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>Monatsbericht ${d.period.label}</title>
<style>
  @page { size: A4; margin: 18mm 14mm; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; margin: 0; font-size: 11pt; line-height: 1.5; }
  h1 { color: #0e7490; font-size: 22pt; margin: 0 0 4pt 0; font-weight: 700; }
  h2 { color: #0e7490; font-size: 13pt; margin: 18pt 0 8pt 0; border-bottom: 2pt solid #cffafe; padding-bottom: 4pt; }
  h3 { color: #334155; font-size: 11pt; margin: 12pt 0 4pt 0; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3pt solid #06b6d4; padding-bottom: 12pt; }
  .header-right { text-align: right; font-size: 9pt; color: #64748b; }
  .brand { color: #06b6d4; font-weight: 800; font-size: 14pt; letter-spacing: 0.5pt; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8pt; margin: 8pt 0; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8pt; margin: 8pt 0; }
  .stat { background: #f8fafc; border-left: 3pt solid #06b6d4; padding: 8pt 10pt; border-radius: 4pt; }
  .stat .lbl { font-size: 8pt; text-transform: uppercase; color: #64748b; letter-spacing: 0.5pt; }
  .stat .val { font-size: 18pt; font-weight: 700; color: #0f172a; }
  .stat .sub { font-size: 8pt; color: #64748b; margin-top: 2pt; }
  .stat.good { border-left-color: #10b981; }
  .stat.warn { border-left-color: #f59e0b; }
  .stat.crit { border-left-color: #ef4444; }
  table { width: 100%; border-collapse: collapse; margin: 4pt 0; font-size: 9.5pt; }
  th { text-align: left; background: #f1f5f9; padding: 5pt 8pt; font-weight: 600; color: #334155; border-bottom: 1pt solid #cbd5e1; }
  td { padding: 5pt 8pt; border-bottom: 1pt solid #e2e8f0; }
  .badge { display: inline-block; padding: 1pt 6pt; border-radius: 3pt; font-size: 8pt; font-weight: 600; }
  .badge-good { background: #d1fae5; color: #065f46; }
  .badge-warn { background: #fef3c7; color: #92400e; }
  .badge-crit { background: #fee2e2; color: #991b1b; }
  .note { background: #ecfeff; border: 1pt solid #a5f3fc; border-radius: 4pt; padding: 10pt 12pt; margin: 12pt 0; font-size: 10pt; color: #155e75; }
  .footer { margin-top: 24pt; padding-top: 10pt; border-top: 1pt solid #e2e8f0; font-size: 8.5pt; color: #94a3b8; text-align: center; }
  .progress { background: #e2e8f0; height: 6pt; border-radius: 3pt; overflow: hidden; }
  .progress > div { height: 100%; background: linear-gradient(90deg, #06b6d4, #0e7490); }
</style></head>
<body>
  <div class="header">
    <div>
      <div class="brand">HASI IT-COCKPIT</div>
      <h1>Monatsbericht ${d.period.label}</h1>
      <div style="color:#64748b">Digitaler Hausmeister fuer Ihre IT</div>
    </div>
    <div class="header-right">
      <strong>${d.tenant.name}</strong><br>
      ${d.tenant.contact_name || ''}<br>
      Erstellt: ${new Date().toLocaleDateString('de-DE')}<br>
      Zeitraum: ${d.period.from} bis ${d.period.to}
    </div>
  </div>

  <h2>Auf einen Blick</h2>
  <div class="grid-3">
    <div class="stat ${fleetHealth >= 80 ? 'good' : fleetHealth >= 60 ? 'warn' : 'crit'}">
      <div class="lbl">Fleet-Gesundheit</div>
      <div class="val">${fleetHealth}%</div>
      <div class="sub">${d.fleet.healthy} gesund, ${d.fleet.poor} kritisch</div>
    </div>
    <div class="stat">
      <div class="lbl">Geraete im Betreuung</div>
      <div class="val">${d.fleet.total_devices}</div>
      <div class="sub">${d.fleet.online} aktuell online</div>
    </div>
    <div class="stat ${d.alerts.by_severity.critical > 0 ? 'crit' : 'good'}">
      <div class="lbl">Alerts im Monat</div>
      <div class="val">${d.alerts.total}</div>
      <div class="sub">${d.alerts.resolved} behoben · ${d.alerts.by_severity.critical} kritisch</div>
    </div>
  </div>

  <h2>Was wir fuer Sie gemacht haben</h2>
  ${d.remoteActions.total > 0 ? `
    <p>In <strong>${d.period.label}</strong> haben wir <strong>${d.remoteActions.total} Remote-Aktion(en)</strong> auf Ihren Geraeten durchgefuehrt:</p>
    <table>
      <thead><tr><th>Aktion</th><th style="text-align:right">Anzahl</th></tr></thead>
      <tbody>
        ${d.remoteActions.by_type.map(a => `<tr><td>${commandLabel(a.command_type)}</td><td style="text-align:right">${a.count}</td></tr>`).join('')}
      </tbody>
    </table>
  ` : `<p style="color:#64748b">In diesem Monat wurden keine Remote-Aktionen erforderlich — Ihre Geraete liefen weitgehend stabil.</p>`}

  <h2>Erkannte Probleme</h2>
  ${d.alerts.by_rule.length > 0 ? `
    <table>
      <thead><tr><th>Regel</th><th style="text-align:right">Wie oft</th></tr></thead>
      <tbody>
        ${d.alerts.by_rule.map(r => `<tr><td>${ruleLabel(r.rule_key)}</td><td style="text-align:right">${r.count}</td></tr>`).join('')}
      </tbody>
    </table>
  ` : `<p style="color:#64748b">Keine neuen Probleme erkannt — sehr gut.</p>`}

  <h2>Top-Risiken (aktuell)</h2>
  ${d.topRisks.length > 0 ? `
    <table>
      <thead><tr><th>Geraet</th><th>Score</th><th>Hauptproblem</th></tr></thead>
      <tbody>
        ${d.topRisks.map(r => `<tr>
          <td>${r.hostname}</td>
          <td><span class="badge ${(r.security_score || 0) >= 60 ? 'badge-warn' : 'badge-crit'}">${r.security_score != null ? r.security_score : '—'}</span></td>
          <td>${r.issues || ''}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  ` : `<p style="color:#64748b">Keine Risiko-Geraete identifiziert.</p>`}

  <h2>Patch-Stand</h2>
  <div class="grid-2">
    <div class="stat ${d.patchSummary.devices_with_pending > d.fleet.total_devices * 0.3 ? 'warn' : 'good'}">
      <div class="lbl">Geraete mit ausstehenden Updates</div>
      <div class="val">${d.patchSummary.devices_with_pending} / ${d.fleet.total_devices}</div>
    </div>
    <div class="stat">
      <div class="lbl">Updates pro Geraet (Schnitt)</div>
      <div class="val">${d.patchSummary.avg_pending_per_device}</div>
      <div class="sub">${d.patchSummary.total_pending} insgesamt</div>
    </div>
  </div>

  <div class="note">
    <strong>Hinweis vom Hausmeister:</strong> ${
      fleetHealth >= 80 ? 'Ihre IT laeuft sehr gut. Keine dringenden Massnahmen erforderlich.' :
      fleetHealth >= 60 ? 'Ihre IT ist solide, aber einige Punkte verdienen Aufmerksamkeit in den naechsten Wochen — z.B. ausstehende Updates oder Geraete mit niedrigem Score.' :
      'Es gibt Handlungsbedarf. Wir empfehlen ein kurzes Telefonat, um die kritischsten Punkte priorisiert anzugehen.'
    }
  </div>

  <div class="footer">
    Hasi Elektronic · Grabenstrasse 18 · 71665 Vaihingen/Enz<br>
    h.guencavdi@hasi-elektronic.de · hasi-elektronic.de<br>
    Dieser Bericht wurde automatisch durch Hasi IT-Cockpit generiert.
  </div>
</body></html>`;
}

async function htmlToPDF(env: Env, html: string): Promise<Uint8Array> {
  // CF Browser Rendering API
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/browser-rendering/pdf`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.BROWSER_RENDERING_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      html,
      addStyleTag: [],
      viewport: { width: 1240, height: 1754 }, // A4 @ 150dpi
    }),
  });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Browser Rendering ${resp.status}: ${txt.slice(0, 200)}`);
  }
  const buf = await resp.arrayBuffer();
  return new Uint8Array(buf);
}

async function sendReportEmail(env: Env, data: TenantReportData, pdfBytes: Uint8Array): Promise<void> {
  // Base64 PDF
  let binary = '';
  const len = pdfBytes.length;
  const chunkSize = 0x8000;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(null, Array.from(pdfBytes.subarray(i, i + chunkSize)));
  }
  const pdfB64 = btoa(binary);

  const subject = `Hasi IT-Cockpit · Monatsbericht ${data.period.label}`;
  const filename = `hasi-monatsbericht-${data.period.from.slice(0, 7)}.pdf`;

  const body = `Hallo ${data.tenant.contact_name || ''},

anbei finden Sie unseren automatisch generierten Monatsbericht fuer ${data.period.label}.

Kurz zusammengefasst:
  - ${data.fleet.total_devices} Geraete in Betreuung, ${data.fleet.online} aktuell online
  - ${data.alerts.total} Alerts (davon ${data.alerts.resolved} bereits behoben)
  - ${data.remoteActions.total} Remote-Aktionen durchgefuehrt

Bei Fragen einfach kurz melden.

Beste Gruesse
Hamdi Guencavdi
Hasi Elektronic
`;

  const resendUrl = 'https://api.resend.com/emails';
  const resp = await fetch(resendUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Hasi IT-Cockpit <noreply@machbar24.com>',
      to: [data.tenant.contact_email],
      cc: ['h.guencavdi@hasi-elektronic.de'], // Hamdi her zaman CC
      subject,
      text: body,
      attachments: [{
        filename,
        content: pdfB64,
      }],
    }),
  });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Resend ${resp.status}: ${txt.slice(0, 200)}`);
  }
}
