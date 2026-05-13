// ============================================================
// Rate Limiter — Hybrid (native binding + KV sliding window)
//
// Why both?
//   - Native Workers Rate Limit binding: per-CF-location, ~0ms,
//     free. First line of defense against IP-based flood/DDoS.
//   - KV sliding window: global count, per-token granularity,
//     custom presets. Catches a single client distributed across
//     CF locations and protects against a misbehaving authenticated
//     agent (heartbeat loop bug, etc).
//
// Order of checks in endpoints:
//   1. rlCheck(env.RL_*, ipKey)          — edge, cheap
//   2. kvCheck(env.RATELIMIT, bucket, k)  — global, accurate
//   Either failing returns HTTP 429.
//
// Cost profile:
//   - Native binding: free, no usage billing
//   - KV: 100K reads/day + 1K writes/day free
//   - Heartbeat is the hot path (~96/day/device); at 100 tenants *
//     30 PC = 288K writes/day = ~$0.50/Mo on workers paid plan.
//     For pilot (Sickinger), well within free tier.
// ============================================================

// ============== Native Workers Rate Limit binding ============

export interface RateLimitBinding {
  limit(opts: { key: string }): Promise<{ success: boolean }>;
}

/**
 * Check rate limit using a native Workers Rate Limit binding.
 * Returns true if request is allowed, false if rate-limited.
 * Fails open on errors (don't block legitimate traffic on infra issues).
 */
export async function rlCheck(binding: RateLimitBinding | undefined, key: string): Promise<boolean> {
  if (!binding) return true;
  try {
    const r = await binding.limit({ key });
    return r.success;
  } catch {
    return true;
  }
}

// ============== KV-backed sliding window =====================

export interface KvLimitConfig {
  limit: number;
  windowSeconds: number;
}

export interface KvLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter: number;
}

const KV_PRESETS: Record<string, KvLimitConfig> = {
  // Anonymous endpoints — IP-keyed
  'bulk-enroll':    { limit: 60,   windowSeconds: 3600 },  // 60 / hour per IP (global)
  'register':       { limit: 40,   windowSeconds: 3600 },  // 40 / hour per IP
  'install':        { limit: 120,  windowSeconds: 3600 },  // 120 / hour per IP
  'install-script': { limit: 60,   windowSeconds: 3600 },  // 60 / hour per IP
  'login':          { limit: 20,   windowSeconds: 600  },  // 20 / 10min per IP
  // Authenticated endpoints — token-keyed
  'heartbeat':      { limit: 360,  windowSeconds: 3600 },  // 360 / hour per token = ~1/10s avg
};

export async function kvCheck(
  kv: KVNamespace | undefined,
  bucket: keyof typeof KV_PRESETS,
  key: string,
  customConfig?: KvLimitConfig
): Promise<KvLimitResult> {
  if (!kv) return { allowed: true, remaining: 999, resetAt: 0, retryAfter: 0 };

  const cfg = customConfig || KV_PRESETS[bucket];
  if (!cfg) return { allowed: true, remaining: 999, resetAt: 0, retryAfter: 0 };

  const now = Date.now();
  const windowMs = cfg.windowSeconds * 1000;
  const kvKey = `rl:${bucket}:${key}`;

  let timestamps: number[] = [];
  try {
    const raw = await kv.get(kvKey, { type: 'json' });
    if (Array.isArray(raw)) {
      timestamps = raw.filter((t: any) => typeof t === 'number' && t > now - windowMs);
    }
  } catch {
    // KV read failure — fail open
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

  timestamps.push(now);
  try {
    await kv.put(kvKey, JSON.stringify(timestamps), {
      expirationTtl: cfg.windowSeconds + 60,
    });
  } catch {
    // KV write failure — still allow (we already returned the decision)
  }

  return {
    allowed: true,
    remaining: cfg.limit - timestamps.length,
    resetAt: now + windowMs,
    retryAfter: 0,
  };
}

// ============== Response helpers =============================

export function rateLimitResponse(retryAfter: number = 60, layer: 'edge' | 'global' = 'edge'): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      message: 'Bitte spaeter erneut versuchen.',
      layer,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
        'X-RateLimit-Layer': layer,
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}

export function getClientIp(req: Request): string {
  return (
    req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}
