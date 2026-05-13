-- ============================================================
-- Migration 012: Token Rotation audit (Security Layer 5/8)
-- ============================================================

-- Tenant install_token rotation tracking
ALTER TABLE tenants ADD COLUMN install_token_rotated_at TEXT;
ALTER TABLE tenants ADD COLUMN install_token_rotated_by TEXT;
ALTER TABLE tenants ADD COLUMN install_token_rotation_count INTEGER DEFAULT 0;
