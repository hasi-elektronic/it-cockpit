-- ============================================================
-- Migration 013: Error logging (Security Layer 7/8)
-- ============================================================

CREATE TABLE IF NOT EXISTS error_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  level        TEXT NOT NULL DEFAULT 'error',  -- info | warn | error | critical
  source       TEXT NOT NULL,                  -- e.g. 'worker.handleHeartbeat', 'cron.backup'
  message      TEXT NOT NULL,
  stack        TEXT,
  request_id   TEXT,                            -- cf-ray header
  path         TEXT,
  method       TEXT,
  ip           TEXT,
  user_agent   TEXT,
  tenant_id    INTEGER,
  user_id      INTEGER,
  status_code  INTEGER,
  duration_ms  INTEGER,
  extra        TEXT                              -- JSON blob for context
);

CREATE INDEX IF NOT EXISTS idx_error_log_created ON error_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_log_level   ON error_log(level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_log_tenant  ON error_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_log_source  ON error_log(source, created_at DESC);
