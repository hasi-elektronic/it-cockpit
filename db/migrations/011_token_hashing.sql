-- ============================================================
-- Migration 011: Token Hashing (Security Layer 2/8)
--
-- Adds SHA-256 hash columns alongside existing plaintext tokens.
-- Worker reads/writes hash; plaintext kept for 30-day transition.
-- Future migration 012 (after 2026-06-13): DROP plaintext columns.
-- ============================================================

-- Agent token (per device) — used in /api/agent/heartbeat, /commands
ALTER TABLE agents ADD COLUMN agent_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(agent_token_hash);

-- Bulk install token (per tenant) — used in /api/agent/bulk-enroll, /api/install/*
ALTER TABLE tenants ADD COLUMN install_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_tenants_install_token_hash ON tenants(install_token_hash);

-- Enroll token (per pending device, single-use) — used in /api/agent/register
ALTER TABLE agents ADD COLUMN enroll_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_agents_enroll_token_hash ON agents(enroll_token_hash);

-- Audit: track when hash was first set (so we know transition progress)
ALTER TABLE agents ADD COLUMN token_hashed_at TEXT;
ALTER TABLE tenants ADD COLUMN install_token_hashed_at TEXT;
