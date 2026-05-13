// ============================================================
// Token Hashing (Security Layer 2/8)
//
// All authentication tokens (agent_token, install_token, enroll_token)
// are stored hashed in D1. Plaintext is never persisted at rest.
//
// Algorithm: SHA-256 over UTF-8 bytes of the raw token.
// No salt needed — tokens are already 32-byte random (UUID v4 or randomToken).
//
// Dual-mode lookup (30-day transition window until 2026-06-13):
//   1. Hash the incoming token
//   2. Try matching against *_token_hash column first
//   3. Fall back to plaintext *_token column (legacy)
//   4. On legacy match: lazily populate the hash column (auto-migration)
// ============================================================

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// Lookup helpers — return the row if found, null otherwise.
// They handle dual-mode (hash + plaintext) and auto-migrate on legacy hit.

export async function findAgentByToken(
  db: D1Database,
  agentToken: string
): Promise<any | null> {
  const hash = await sha256Hex(agentToken);

  // Try hash match first (preferred path)
  let row = await db.prepare(
    `SELECT id, tenant_id, device_id, status, agent_token, agent_token_hash
     FROM agents WHERE agent_token_hash = ?`
  ).bind(hash).first<any>();
  if (row) return row;

  // Legacy fallback — plaintext match
  row = await db.prepare(
    `SELECT id, tenant_id, device_id, status, agent_token, agent_token_hash
     FROM agents WHERE agent_token = ?`
  ).bind(agentToken).first<any>();
  if (!row) return null;

  // Lazy migration: populate hash so next request takes the fast path
  if (!row.agent_token_hash) {
    await db.prepare(
      `UPDATE agents SET agent_token_hash = ?, token_hashed_at = datetime('now') WHERE id = ?`
    ).bind(hash, row.id).run();
    row.agent_token_hash = hash;
  }
  return row;
}

export async function findTenantByInstallToken(
  db: D1Database,
  installToken: string
): Promise<any | null> {
  const hash = await sha256Hex(installToken);

  let row = await db.prepare(
    `SELECT id, slug, name, plan, status, install_enabled, install_token, install_token_hash
     FROM tenants WHERE install_token_hash = ?`
  ).bind(hash).first<any>();
  if (row) return row;

  row = await db.prepare(
    `SELECT id, slug, name, plan, status, install_enabled, install_token, install_token_hash
     FROM tenants WHERE install_token = ?`
  ).bind(installToken).first<any>();
  if (!row) return null;

  if (!row.install_token_hash) {
    await db.prepare(
      `UPDATE tenants SET install_token_hash = ?, install_token_hashed_at = datetime('now') WHERE id = ?`
    ).bind(hash, row.id).run();
    row.install_token_hash = hash;
  }
  return row;
}

export async function findAgentByEnrollToken(
  db: D1Database,
  enrollToken: string
): Promise<any | null> {
  const hash = await sha256Hex(enrollToken);

  let row = await db.prepare(
    `SELECT id, tenant_id, device_id, status, enroll_token, enroll_token_hash
     FROM agents WHERE enroll_token_hash = ?`
  ).bind(hash).first<any>();
  if (row) return row;

  row = await db.prepare(
    `SELECT id, tenant_id, device_id, status, enroll_token, enroll_token_hash
     FROM agents WHERE enroll_token = ?`
  ).bind(enrollToken).first<any>();
  if (!row) return null;

  if (!row.enroll_token_hash) {
    await db.prepare(
      `UPDATE agents SET enroll_token_hash = ? WHERE id = ?`
    ).bind(hash, row.id).run();
    row.enroll_token_hash = hash;
  }
  return row;
}
