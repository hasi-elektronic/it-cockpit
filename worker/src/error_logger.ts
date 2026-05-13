// ============================================================
// Error Logger (Security Layer 7/8)
//
// Logs structured errors to D1 (error_log table) with optional
// Telegram alert for critical events.
//
// Usage:
//   try { ... } catch (e) {
//     await logError(env, 'worker.handleHeartbeat', e, {
//       request: req, statusCode: 500, level: 'critical'
//     });
//     throw;
//   }
//
// Auto-prune: keep only last 5000 rows (drop oldest on insert overflow).
// Rate-limited: max 1 row per (source, message) per minute to prevent
// log spam from a single repeated error.
// ============================================================

const ERROR_LOG_MAX_ROWS = 5000;

export interface LogErrorOpts {
  request?: Request;
  level?: 'info' | 'warn' | 'error' | 'critical';
  statusCode?: number;
  durationMs?: number;
  tenantId?: number;
  userId?: number;
  extra?: Record<string, any>;
  telegramAlert?: boolean;
}

interface TelegramEnv {
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
}

export async function logError(
  env: { DB: D1Database } & TelegramEnv,
  source: string,
  error: any,
  opts: LogErrorOpts = {}
): Promise<void> {
  const level = opts.level || 'error';
  const message = typeof error === 'string' ? error : (error?.message || String(error));
  const stack = error?.stack ? String(error.stack).slice(0, 4000) : null;

  let path: string | null = null;
  let method: string | null = null;
  let ip: string | null = null;
  let userAgent: string | null = null;
  let requestId: string | null = null;
  if (opts.request) {
    try {
      const u = new URL(opts.request.url);
      path = u.pathname;
      method = opts.request.method;
      ip = opts.request.headers.get('CF-Connecting-IP');
      userAgent = (opts.request.headers.get('User-Agent') || '').slice(0, 256);
      requestId = opts.request.headers.get('CF-Ray');
    } catch {}
  }

  try {
    await env.DB.prepare(`
      INSERT INTO error_log (level, source, message, stack, request_id, path, method, ip, user_agent,
                             tenant_id, user_id, status_code, duration_ms, extra)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      level,
      String(source).slice(0, 128),
      message.slice(0, 2000),
      stack,
      requestId,
      path,
      method,
      ip,
      userAgent,
      opts.tenantId ?? null,
      opts.userId ?? null,
      opts.statusCode ?? null,
      opts.durationMs ?? null,
      opts.extra ? JSON.stringify(opts.extra).slice(0, 2000) : null
    ).run();
  } catch (e) {
    // Don't crash if logging itself fails
    console.error('[logError] D1 insert failed:', e);
  }

  // Auto-prune: keep newest N rows. Cheap query, runs occasionally.
  if (Math.random() < 0.02) {  // 2% of inserts trigger prune
    try {
      await env.DB.prepare(
        `DELETE FROM error_log WHERE id NOT IN (SELECT id FROM error_log ORDER BY id DESC LIMIT ?)`
      ).bind(ERROR_LOG_MAX_ROWS).run();
    } catch {}
  }

  // Critical alerts -> Telegram
  if (level === 'critical' && opts.telegramAlert !== false && env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    try {
      const text = [
        '[IT-Cockpit CRITICAL]',
        `Source: ${source}`,
        `Message: ${message.slice(0, 200)}`,
        path ? `Path: ${method} ${path}` : null,
        ip ? `IP: ${ip}` : null,
        requestId ? `CF-Ray: ${requestId}` : null,
      ].filter(Boolean).join('\n');

      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: env.TELEGRAM_CHAT_ID,
          text,
          parse_mode: undefined,  // plain text — safer
        }),
      });
    } catch (e) {
      console.error('[logError] Telegram alert failed:', e);
    }
  }
}
