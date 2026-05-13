// ============================================================
// Rate Limiter — Workers Rate Limit binding (native, edge, 0ms)
//
// Replaces the v0.6.0 KV-backed approach with Cloudflare's native
// Workers Rate Limit binding (declared in wrangler.toml [unsafe.bindings]).
//
// Characteristics:
//   - Per-Cloudflare-location count (eventually consistent globally)
//   - Cached on Worker isolate, ~0ms latency
//   - Free plan, no KV reads/writes billed
//   - Configuration in wrangler.toml (declarative), not code
//
// Each endpoint uses a separate binding so counters don't share state:
//   RL_LOGIN, RL_REGISTER, RL_BULK_ENROLL, RL_INSTALL, RL_HEARTBEAT
//
// Limit function signature:
//   await binding.limit({ key: string })  =>  { success: boolean }
//
// Key strategy:
//   - IP-based endpoints (anonymous):    getClientIp(req)
//   - Token-based endpoints (agent):     `tok:${agentToken}` or `dev:${deviceId}`
// ============================================================

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

/** HTTP 429 response with helpful headers. */
export function rateLimitResponse(): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      message: 'Bitte spaeter erneut versuchen.',
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': '60',
        'X-RateLimit-Policy': 'per-cloudflare-location',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}

/** Extract client IP from request (CF-aware). */
export function getClientIp(req: Request): string {
  return (
    req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}
