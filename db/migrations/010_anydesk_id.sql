-- ===========================================
-- v0.5.12 — AnyDesk ID storage
-- ===========================================

-- Agent reports AnyDesk-ID from registry; admin can override and lock
ALTER TABLE devices ADD COLUMN anydesk_id TEXT;
ALTER TABLE devices ADD COLUMN anydesk_id_locked INTEGER DEFAULT 0;
