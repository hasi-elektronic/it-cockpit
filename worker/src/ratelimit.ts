// ============================================================
// Rate Limiter — KV-backed sliding window
//
// Usage:
//   const rl = await checkRateLimit(env.RATELIMIT, 'bulk-enroll', clientIp, {
//     limit: 30, windowSeconds: 3600
//   });
//   if (!rl.allowed) return rateLimitError(rl);
//
// Implementation: each (bucket, key) holds an array of timestamps (ms).
// On every call we:
//   1. Read current array from KV
//   2. Drop timestamps older than (now - windowSeconds*1000)
//   3. If length < limit -> push now, write back, allow
//   4. Else -> deny, return retry-after
//
// Storage cost: 1 KV read + 1 KV write per request to that endpoint.
// CF free tier: 100K reads/day + 1K writes/day per namespace.
// At 30 PC * 96 heartbeats/day = 2880 writes/day per tenant.
// 5 tenants ~= 14K writes/day — still in paid tier ($0.50/Mo per mio).
// Strategy: heartbeat uses lower-overhead path (no KV, just D1).
//   KV-based limit ONLY for unauthenticated endpoints:
//     /api/agent/bulk-enroll, /api/agent/register, /api/install/*
// ============================================================

export interface RateLimitConfig {
  limit: number;            // max requests
  windowSeconds: number;    // sliding window size
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;          // unix ms timestamp when next slot frees
  retryAfter: number;       // seconds until next request allowed
}

const PRESETS: Record<string, RateLimitConfig> = {
  // Anonymous endpoint, hostname-based enrollment — moderate
  'bulk-enroll':   { limit: 30,  windowSeconds: 3600 },     // 30 / hour per IP
  // Legacy enroll-token register — strict (single-use tokens)
  'register':      { limit: 20,  windowSeconds: 3600 },     // 20 / hour per IP
  // Installer download (.exe, .bat, .ps1)
  'install':       { limit: 60,  windowSeconds: 3600 },     // 60 / hour per IP
  // Public install script generation (text/plain)
  'install-script':{ limit: 30,  windowSeconds: 3600 },     // 30 / hour per IP
  // Login endpoint (brute force protection)
  'login':         { limit: 10,  windowSeconds: 600 },      // 10 / 10 min per IP
};

export async function checkRateLimit(
  kv: KVNamespace,
  bucket: keyof typeof PRESETS,
  key: string,
  customConfig?: RateLimitConfig
): Promise<RateLimitResult> {
  const cfg = customConfig || PRESETS[bucket];
  if (!cfg) {
    // Unknown bucket — fail open (log warning would be nice)
    return { allowed: true, remaining: 999, resetAt: 0, retryAfter: 0 };
  }

  const now = Date.now();
  const windowMs = cfg.windowSeconds * 1000;
  const kvKey = `rl:${bucket}:${key}`;

  // Read current timestamps
  let timestamps: number[] = [];
  try {
    const raw = await kv.get(kvKey, { type: 'json' });
    if (Array.isArray(raw)) {
      timestamps = raw.filter((t: any) => typeof t === 'number' && t > now - windowMs);
    }
  } catch {
    // KV read failure — fail open (don't block legitimate traffic)
    return { allowed: true, remaining: 999, resetAt: 0, retryAfter: 0 };
  }

  if (timestamps.length >= cfg.limit) {
    const oldest = Math.min(...timestamps);
    const resetAt = oldest + windowMs;
    return {
      allowed: false,
      remaining: 0,
      resetAt,
      retryAfter: Math.max(1, Math.ceil((resetAt - now) / 1000)),
    };
  }

  // Allowed — record this request
  timestamps.push(now);
  // KV TTL = window + 60s buffer (auto-cleanup)
  await kv.put(kvKey, JSON.stringify(timestamps), {
    expirationTtl: cfg.windowSeconds + 60,
  });

  return {
    allowed: true,
    remaining: cfg.limit - timestamps.length,
    resetAt: now + windowMs,
    retryAfter: 0,
  };
}

export function rateLimitResponse(result: RateLimitResult): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      retry_after: result.retryAfter,
      reset_at: new Date(result.resetAt).toISOString(),
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(result.retryAfter),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.floor(result.resetAt / 1000)),
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}

// Helper to extract IP for rate-limit key
export function getClientIp(req: Request): string {
  return (
    req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}
