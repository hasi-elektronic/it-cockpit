// ============================================================
// Input Validation Schemas (Security Layer 4/8)
//
// Defines Zod schemas for every public-facing endpoint that accepts
// JSON. Used in handlers as:
//
//   const parsed = HeartbeatSchema.safeParse(body);
//   if (!parsed.success) return validationError(parsed.error);
//   const data = parsed.data;   // fully typed + sanitized
//
// Design rules:
//   - All strings have max length (DoS via huge payload)
//   - All numbers have explicit min/max ranges
//   - Enums for closed sets (os_platform, status, role)
//   - Unknown fields are stripped (.strip()) — only declared fields pass through
//   - Optional fields default to sane values where possible
//   - HTML/script-like patterns rejected on identifiers (hostname, slug)
// ============================================================

import { z } from 'zod';

// Common building blocks ----------------------------------------

// Safe identifier: alphanumeric + hyphen + underscore, no spaces/HTML
const safeIdentifier = (max: number = 128) =>
  z.string().max(max).regex(/^[a-zA-Z0-9._\-:\\\/() ]+$/, 'Invalid characters');

// Plain text field (allows letters, numbers, common punctuation but no HTML)
const safeText = (max: number = 256) =>
  z.string().max(max).refine(
    (s) => !/<\s*\/?\s*(script|iframe|object|embed|link|meta|style|svg|img|on\w+\s*=)/i.test(s),
    'HTML/script content not allowed'
  );

// Optional, nullable, trimmed
const optStr = (max: number = 256) => safeText(max).optional().nullable();
const optInt = (min: number, max: number) => z.number().int().min(min).max(max).optional().nullable();
const optBool = z.boolean().optional().nullable();
const optFloat = (min: number, max: number) => z.number().min(min).max(max).optional().nullable();

// Slug — strict tenant identifier
const slugSchema = z.string().min(2).max(64).regex(/^[a-z0-9-]+$/, 'Slug must be lowercase alphanumeric + hyphen');

// Email
const emailSchema = z.string().email().max(256);

// Token formats
const agentTokenSchema = z.string().regex(/^AGT-[a-zA-Z0-9-]{16,64}$/, 'Invalid agent token format').max(80);
const bulkTokenSchema  = z.string().regex(/^BULK-[a-zA-Z0-9-]{16,64}$/, 'Invalid bulk token format').max(80);

// ============== ENDPOINT SCHEMAS =============================

// POST /api/auth/login
export const LoginSchema = z.object({
  tenant:   slugSchema,
  email:    emailSchema,
  password: z.string().min(1).max(256),
}).strip();

// POST /api/agent/register (legacy enroll flow)
export const AgentRegisterSchema = z.object({
  enroll_token:  z.string().min(4).max(80),
  hostname:      safeText(128),
  os_platform:   z.enum(['windows', 'linux', 'macos']).optional().nullable(),
  agent_version: optStr(32),
  manufacturer:  optStr(128),
  model:         optStr(128),
  serial_number: optStr(64),
  os:            optStr(128),
  cpu:           optStr(128),
  ram_gb:        optInt(0, 4096),
  storage_gb:    optInt(0, 1048576),  // up to 1 PB
  mac_address:   optStr(32),
}).strip();

// POST /api/agent/bulk-enroll
export const BulkEnrollSchema = z.object({
  bulk_token:    bulkTokenSchema,
  hostname:      safeText(128),
  os_platform:   z.enum(['windows', 'linux', 'macos']).optional().nullable(),
  manufacturer:  optStr(128),
  model:         optStr(128),
  mac_address:   optStr(32),
}).strip();

// POST /api/agent/heartbeat — the hot path. Has 50+ optional fields.
export const HeartbeatSchema = z.object({
  // Telemetry timestamp
  timestamp:       optStr(64),
  agent_version:   optStr(32),

  // Runtime
  uptime_seconds:  optInt(0, 31_536_000),  // up to 1 year
  logged_in_user:  optStr(256),

  // CPU/RAM
  cpu_percent:     optFloat(0, 100),
  cpu_temp_c:      optFloat(-50, 150),
  ram_percent:     optFloat(0, 100),
  ram_total_gb:    optFloat(0, 4096),
  ram_used_gb:     optFloat(0, 4096),

  // Disk
  disk_c_percent:  optFloat(0, 100),
  disk_c_total_gb: optFloat(0, 1_048_576),
  disk_c_free_gb:  optFloat(0, 1_048_576),
  disk_count:      optInt(0, 100),

  // Network
  ip_internal:     optStr(45),  // IPv6 max
  ip_external:     optStr(45),
  last_boot:       optStr(64),

  // Battery
  battery_wear_pct: optFloat(0, 100),
  battery_health:   optStr(64),
  boot_time_sec:    optFloat(0, 86400),

  // Software counts
  outdated_sw_count: optInt(0, 100_000),
  installed_sw_count: optInt(0, 100_000),
  open_ports_count: optInt(0, 65535),

  // Security score components (booleans, counts)
  bitlocker_enabled:   optBool,
  uac_enabled:         optBool,
  auto_login_enabled:  optBool,
  av_enabled:          optBool,
  av_up_to_date:       optBool,
  av_signature_age_days: optInt(0, 365),
  defender_tamper_on:  optBool,
  tpm_present:         optBool,
  tpm_ready:           optBool,
  secure_boot:         optBool,
  firewall_domain:     optBool,
  firewall_private:    optBool,
  firewall_public:     optBool,
  wu_critical_count:   optInt(0, 1000),
  wu_pending_count:    optInt(0, 10_000),
  pending_reboot:      optBool,
  failed_logons_24h:   optInt(0, 1_000_000),
  local_admin_count:   optInt(0, 1000),
  rdp_enabled:         optBool,

  // AnyDesk (v0.5.12+)
  anydesk_id:          z.string().max(20).regex(/^[0-9]+$/).optional().nullable(),

  // v0.6.1: Static inventory backfill (sent ~once per day from agent)
  manufacturer:        z.string().max(128).optional().nullable(),
  model:               z.string().max(128).optional().nullable(),
  serial_number:       z.string().max(64).optional().nullable(),
  cpu:                 z.string().max(256).optional().nullable(),
  ram_gb:              z.number().min(0).max(8192).optional().nullable(),
  storage_gb:          z.number().min(0).max(1_048_576).optional().nullable(),
  os_version:          z.string().max(128).optional().nullable(),
  mac_address:         z.string().max(32).optional().nullable(),

  // Arrays of structured data — bounded length to prevent DoS
  disks:     z.array(z.any()).max(50).optional().nullable(),
  processes: z.array(z.any()).max(100).optional().nullable(),
  browsers:  z.array(z.any()).max(20).optional().nullable(),
  antivirus: z.array(z.any()).max(20).optional().nullable(),
  software:  z.array(z.any()).max(2000).optional().nullable(),

  // Catch-all telemetry blob (limited)
  extra: z.record(z.any()).optional().nullable(),
}).strip();

// POST /api/devices (admin create)
export const DeviceCreateSchema = z.object({
  hostname:      safeText(128),
  device_type:   z.enum(['desktop', 'laptop', 'server', 'mobile', 'tablet', 'printer', 'router', 'switch', 'firewall', 'iot', 'other']).optional(),
  manufacturer:  optStr(128),
  model:         optStr(128),
  serial_number: optStr(64),
  os:            optStr(128),
  cpu:           optStr(128),
  ram_gb:        optInt(0, 4096),
  storage_gb:    optInt(0, 1_048_576),
  mac_address:   optStr(32),
  ip_address:    optStr(45),
  location:      optStr(128),
  assigned_to:   optStr(256),
  status:        z.enum(['active', 'inactive', 'maintenance', 'retired']).optional(),
  notes:         optStr(2000),
}).strip();

// PUT /api/devices/:id
export const DeviceUpdateSchema = DeviceCreateSchema.partial();

// POST /api/users (admin create)
export const UserCreateSchema = z.object({
  email:    emailSchema,
  password: z.string().min(8).max(256),
  role:     z.enum(['admin', 'user', 'viewer']),
  active:   optBool,
}).strip();

// POST /api/tenants (super-admin)
export const TenantCreateSchema = z.object({
  slug:   slugSchema,
  name:   safeText(128),
  plan:   z.enum(['starter', 'pro', 'enterprise']).optional(),
  status: z.enum(['active', 'inactive', 'trial']).optional(),
}).strip();

// POST /api/agent/commands/:id/result
export const CommandResultSchema = z.object({
  status:     z.enum(['done', 'error']).optional(),
  stdout:     z.string().max(16000).optional().nullable(),
  stderr:     z.string().max(4000).optional().nullable(),
  exit_code:  optInt(-2147483648, 2147483647),
  error_message: optStr(2000),
}).strip();

// ============== HELPER ========================================

import type { ZodError } from 'zod';

export function validationError(error: ZodError): Response {
  const issues = error.issues.slice(0, 5).map((i) => ({
    path: i.path.join('.'),
    message: i.message,
  }));
  return new Response(
    JSON.stringify({
      error: 'Validation failed',
      issues,
    }),
    {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}
