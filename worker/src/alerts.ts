/**
 * Hasi IT-Cockpit — Alert Evaluator + Notifier
 * Runs every 15 min via cron, checks all devices+settings, fires/resolves alerts
 */

export interface AlertEnv {
  DB: D1Database;
}

interface AlertSettings {
  tenant_id: number;
  telegram_enabled: number;
  telegram_bot_token: string | null;
  telegram_chat_id: string | null;
  email_enabled: number;
  email_recipient: string | null;
  rule_disk_critical: number;
  rule_disk_warning: number;
  rule_av_disabled: number;
  rule_av_outdated: number;
  rule_bitlocker_off: number;
  rule_agent_offline: number;
  rule_wu_critical: number;
  rule_new_device: number;
  disk_critical_pct: number;
  disk_warning_pct: number;
  av_signature_days: number;
  agent_offline_warn_h: number;
  agent_offline_crit_h: number;
  wu_critical_count: number;
}

interface FiredAlert {
  device_id: number | null;
  rule_key: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  value?: string;
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🔴',
  warning: '🟡',
  info: '🟢',
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'KRITISCH',
  warning: 'Warnung',
  info: 'Info',
};

// ---------- Telegram ----------

async function sendTelegram(botToken: string, chatId: string, text: string): Promise<boolean> {
  try {
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    });
    return resp.ok;
  } catch (e) {
    console.error('Telegram error:', e);
    return false;
  }
}

function formatTelegramMessage(alert: FiredAlert, deviceHostname: string | null, tenantName: string): string {
  const emoji = SEVERITY_EMOJI[alert.severity];
  const label = SEVERITY_LABEL[alert.severity];
  let msg = `${emoji} <b>${label}: ${alert.title}</b>\n\n`;
  if (deviceHostname) msg += `💻 <b>Gerät:</b> ${deviceHostname}\n`;
  msg += `🏢 <b>Mandant:</b> ${tenantName}\n`;
  if (alert.value) msg += `📊 <b>Wert:</b> ${alert.value}\n`;
  msg += `\n${alert.message}\n\n`;
  msg += `<a href="https://it-cockpit.pages.dev">→ Cockpit öffnen</a>`;
  return msg;
}

// ---------- Evaluator ----------

export async function evaluateAlerts(env: AlertEnv): Promise<{ tenants: number; fired: number; resolved: number; notified: number }> {
  let firedCount = 0, resolvedCount = 0, notifiedCount = 0;

  // Get all alert settings (one row per tenant)
  const settings = await env.DB.prepare(`SELECT * FROM alert_settings`).all<AlertSettings>();
  if (!settings.results) return { tenants: 0, fired: 0, resolved: 0, notified: 0 };

  for (const tenantSettings of settings.results) {
    const tenantId = tenantSettings.tenant_id;

    // Get tenant info (for messages)
    const tenant = await env.DB.prepare(`SELECT name FROM tenants WHERE id = ?`).bind(tenantId).first<any>();
    const tenantName = tenant?.name || `Tenant ${tenantId}`;

    // Get all devices with latest security/telemetry
    const devices = await env.DB.prepare(`
      SELECT d.id, d.hostname, d.agent_status, d.agent_last_seen, d.auto_discovered, d.created_at,
             s.bitlocker_enabled, s.av_enabled, s.av_up_to_date, s.av_signature_age_days,
             s.wu_critical_count, s.wu_pending_count,
             (SELECT disk_c_percent FROM device_telemetry t WHERE t.device_id = d.id ORDER BY t.id DESC LIMIT 1) AS disk_c_percent
      FROM devices d
      LEFT JOIN security_status s ON s.device_id = d.id
      WHERE d.tenant_id = ?
    `).bind(tenantId).all<any>();

    if (!devices.results) continue;

    // Collect all alerts that SHOULD currently be active
    const shouldFire = new Map<string, FiredAlert>();  // key: device_id:rule_key
    const deviceHostnames = new Map<number, string>();

    for (const dev of devices.results) {
      deviceHostnames.set(dev.id, dev.hostname);

      // ---- Rule: Disk critical ----
      if (tenantSettings.rule_disk_critical && dev.disk_c_percent != null) {
        if (dev.disk_c_percent >= tenantSettings.disk_critical_pct) {
          shouldFire.set(`${dev.id}:disk_critical`, {
            device_id: dev.id,
            rule_key: 'disk_critical',
            severity: 'critical',
            title: 'Disk fast voll',
            message: `Festplatte C: ist zu ${dev.disk_c_percent.toFixed(1)}% voll. Sofortige Aktion empfohlen (Cleanup, Erweiterung).`,
            value: `${dev.disk_c_percent.toFixed(1)}%`,
          });
        }
      }

      // ---- Rule: Disk warning ----
      if (tenantSettings.rule_disk_warning && dev.disk_c_percent != null && tenantSettings.disk_critical_pct > tenantSettings.disk_warning_pct) {
        if (dev.disk_c_percent >= tenantSettings.disk_warning_pct && dev.disk_c_percent < tenantSettings.disk_critical_pct) {
          shouldFire.set(`${dev.id}:disk_warning`, {
            device_id: dev.id,
            rule_key: 'disk_warning',
            severity: 'warning',
            title: 'Disk fuellt sich',
            message: `Festplatte C: zu ${dev.disk_c_percent.toFixed(1)}% voll. Planung zur Bereinigung empfohlen.`,
            value: `${dev.disk_c_percent.toFixed(1)}%`,
          });
        }
      }

      // ---- Rule: AV disabled ----
      if (tenantSettings.rule_av_disabled && dev.av_enabled === 0) {
        shouldFire.set(`${dev.id}:av_disabled`, {
          device_id: dev.id,
          rule_key: 'av_disabled',
          severity: 'critical',
          title: 'Antivirus deaktiviert',
          message: 'Der Virenschutz ist nicht aktiv. Bitte sofort prüfen.',
          value: 'AV inaktiv',
        });
      }

      // ---- Rule: AV signatures outdated ----
      if (tenantSettings.rule_av_outdated && dev.av_signature_age_days != null && dev.av_signature_age_days > tenantSettings.av_signature_days) {
        shouldFire.set(`${dev.id}:av_outdated`, {
          device_id: dev.id,
          rule_key: 'av_outdated',
          severity: 'warning',
          title: 'AV Signaturen veraltet',
          message: `Die Virensignaturen sind seit ${dev.av_signature_age_days} Tagen nicht aktualisiert worden.`,
          value: `${dev.av_signature_age_days} Tage alt`,
        });
      }

      // ---- Rule: BitLocker off ----
      if (tenantSettings.rule_bitlocker_off && dev.bitlocker_enabled === 0) {
        shouldFire.set(`${dev.id}:bitlocker_off`, {
          device_id: dev.id,
          rule_key: 'bitlocker_off',
          severity: 'critical',
          title: 'BitLocker deaktiviert',
          message: 'Die Festplatte ist nicht verschluesselt. Datenschutz-Risiko bei Diebstahl/Verlust.',
          value: 'unverschluesselt',
        });
      }

      // ---- Rule: Agent offline ----
      if (tenantSettings.rule_agent_offline && dev.agent_last_seen) {
        const lastSeen = new Date(dev.agent_last_seen + 'Z').getTime();
        const ageHours = (Date.now() - lastSeen) / (1000 * 3600);

        if (ageHours >= tenantSettings.agent_offline_crit_h) {
          shouldFire.set(`${dev.id}:agent_offline_critical`, {
            device_id: dev.id,
            rule_key: 'agent_offline_critical',
            severity: 'critical',
            title: 'Agent offline (lang)',
            message: `Der Agent hat seit ${Math.round(ageHours)} Stunden keinen Heartbeat mehr gesendet. Geraet pruefen.`,
            value: `${Math.round(ageHours)}h offline`,
          });
        } else if (ageHours >= tenantSettings.agent_offline_warn_h) {
          shouldFire.set(`${dev.id}:agent_offline_warning`, {
            device_id: dev.id,
            rule_key: 'agent_offline_warning',
            severity: 'warning',
            title: 'Agent offline',
            message: `Der Agent hat seit ${Math.round(ageHours)} Stunden keinen Heartbeat mehr gesendet.`,
            value: `${Math.round(ageHours)}h offline`,
          });
        }
      }

      // ---- Rule: Windows Update critical ----
      if (tenantSettings.rule_wu_critical && dev.wu_critical_count != null && dev.wu_critical_count > tenantSettings.wu_critical_count) {
        shouldFire.set(`${dev.id}:wu_critical`, {
          device_id: dev.id,
          rule_key: 'wu_critical',
          severity: 'warning',
          title: 'Kritische Updates ausstehend',
          message: `${dev.wu_critical_count} kritische Windows-Updates sind nicht installiert.`,
          value: `${dev.wu_critical_count} Updates`,
        });
      }

      // ---- Rule: New device discovered (one-shot) ----
      if (tenantSettings.rule_new_device && dev.auto_discovered === 1) {
        const createdAt = new Date(dev.created_at + 'Z').getTime();
        const ageMin = (Date.now() - createdAt) / (1000 * 60);
        if (ageMin < 60) {
          // Only "new" if < 1h old
          shouldFire.set(`${dev.id}:new_device`, {
            device_id: dev.id,
            rule_key: 'new_device',
            severity: 'info',
            title: 'Neues Geraet entdeckt',
            message: `Ein neuer Agent hat sich registriert: ${dev.hostname}`,
            value: dev.hostname,
          });
        }
      }
    }

    // Get current open alerts for this tenant
    const openAlerts = await env.DB.prepare(`
      SELECT id, device_id, rule_key, severity, status, notified FROM alerts
      WHERE tenant_id = ? AND status IN ('open','acknowledged')
    `).bind(tenantId).all<any>();

    const openMap = new Map<string, any>();
    for (const a of openAlerts.results || []) {
      openMap.set(`${a.device_id}:${a.rule_key}`, a);
    }

    // Fire new + update existing
    for (const [key, fired] of shouldFire) {
      const existing = openMap.get(key);
      if (existing) {
        // Already open — just update last_seen
        await env.DB.prepare(`
          UPDATE alerts SET last_seen = datetime('now'), value = ? WHERE id = ?
        `).bind(fired.value || null, existing.id).run();
        openMap.delete(key);
      } else {
        // New alert
        const r = await env.DB.prepare(`
          INSERT INTO alerts (tenant_id, device_id, rule_key, severity, title, message, value, status, notified)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'open', 0)
          ON CONFLICT(tenant_id, device_id, rule_key) DO UPDATE SET
            last_seen = datetime('now'),
            value = excluded.value,
            status = CASE WHEN status='resolved' THEN 'open' ELSE status END,
            resolved_at = CASE WHEN status='resolved' THEN NULL ELSE resolved_at END,
            notified = CASE WHEN status='resolved' THEN 0 ELSE notified END
        `).bind(
          tenantId, fired.device_id, fired.rule_key, fired.severity,
          fired.title, fired.message, fired.value || null
        ).run();

        const alertId = r.meta.last_row_id;
        firedCount++;

        // History entry
        await env.DB.prepare(`
          INSERT INTO alert_history (tenant_id, alert_id, device_id, rule_key, severity, event)
          VALUES (?, ?, ?, ?, ?, 'fired')
        `).bind(tenantId, alertId, fired.device_id, fired.rule_key, fired.severity).run();

        // Telegram notification (if enabled + not yet notified)
        if (tenantSettings.telegram_enabled && tenantSettings.telegram_bot_token && tenantSettings.telegram_chat_id) {
          const hostname = fired.device_id ? deviceHostnames.get(fired.device_id) || null : null;
          const msg = formatTelegramMessage(fired, hostname, tenantName);
          const ok = await sendTelegram(tenantSettings.telegram_bot_token, tenantSettings.telegram_chat_id, msg);
          if (ok) {
            await env.DB.prepare(`UPDATE alerts SET notified = 1 WHERE tenant_id = ? AND device_id = ? AND rule_key = ?`)
              .bind(tenantId, fired.device_id, fired.rule_key).run();
            await env.DB.prepare(`
              INSERT INTO alert_history (tenant_id, alert_id, device_id, rule_key, severity, event)
              VALUES (?, ?, ?, ?, ?, 'notified')
            `).bind(tenantId, alertId, fired.device_id, fired.rule_key, fired.severity).run();
            notifiedCount++;
          }
        }
      }
    }

    // Auto-resolve: anything still in openMap was not "shouldFire" anymore → resolve
    for (const [key, alert] of openMap) {
      await env.DB.prepare(`
        UPDATE alerts SET status='resolved', resolved_at=datetime('now') WHERE id = ?
      `).bind(alert.id).run();
      await env.DB.prepare(`
        INSERT INTO alert_history (tenant_id, alert_id, device_id, rule_key, severity, event)
        VALUES (?, ?, ?, ?, ?, 'resolved')
      `).bind(tenantId, alert.id, alert.device_id, alert.rule_key, alert.severity).run();
      resolvedCount++;

      // Telegram resolve notification (optional, brief)
      if (tenantSettings.telegram_enabled && tenantSettings.telegram_bot_token && tenantSettings.telegram_chat_id && alert.severity === 'critical') {
        const hostname = alert.device_id ? deviceHostnames.get(alert.device_id) || null : null;
        const ruleLabel = ({
          disk_critical: 'Disk fast voll',
          av_disabled: 'Antivirus deaktiviert',
          bitlocker_off: 'BitLocker deaktiviert',
          agent_offline_critical: 'Agent offline (lang)',
        } as any)[alert.rule_key] || alert.rule_key;
        const msg = `✅ <b>Behoben:</b> ${ruleLabel}\n💻 ${hostname || '—'}\n\nDie Bedingung trifft nicht mehr zu.`;
        await sendTelegram(tenantSettings.telegram_bot_token, tenantSettings.telegram_chat_id, msg);
      }
    }
  }

  return { tenants: settings.results.length, fired: firedCount, resolved: resolvedCount, notified: notifiedCount };
}

// ---------- Test message (for "test telegram" button) ----------

export async function sendTestTelegram(env: AlertEnv, tenantId: number): Promise<{ ok: boolean; error?: string }> {
  const s = await env.DB.prepare(`SELECT telegram_bot_token, telegram_chat_id FROM alert_settings WHERE tenant_id = ?`).bind(tenantId).first<any>();
  if (!s || !s.telegram_bot_token || !s.telegram_chat_id) {
    return { ok: false, error: 'Bot token oder Chat-ID fehlen' };
  }
  const t = await env.DB.prepare(`SELECT name FROM tenants WHERE id = ?`).bind(tenantId).first<any>();
  const msg = `✅ <b>Hasi IT-Cockpit — Test</b>\n\nDie Telegram-Verbindung funktioniert für <b>${t?.name || 'Tenant'}</b>.\n\nAb jetzt erhältst du Alerts auf diesem Chat.`;
  const ok = await sendTelegram(s.telegram_bot_token, s.telegram_chat_id, msg);
  return { ok, error: ok ? undefined : 'Telegram API-Aufruf fehlgeschlagen (Token/Chat-ID prüfen)' };
}
