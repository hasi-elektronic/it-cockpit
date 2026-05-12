-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.3 (Alert System)
-- 2026-05-12
-- =====================================================================

-- 1. Tenant-level alert settings (Telegram token, email, enabled rules)
CREATE TABLE IF NOT EXISTS alert_settings (
  tenant_id           INTEGER PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  telegram_enabled    INTEGER DEFAULT 0,
  telegram_bot_token  TEXT,
  telegram_chat_id    TEXT,
  email_enabled       INTEGER DEFAULT 0,
  email_recipient     TEXT,
  -- Rule toggles (1 = enabled, 0 = disabled)
  rule_disk_critical    INTEGER DEFAULT 1,
  rule_disk_warning     INTEGER DEFAULT 1,
  rule_av_disabled      INTEGER DEFAULT 1,
  rule_av_outdated      INTEGER DEFAULT 1,
  rule_bitlocker_off    INTEGER DEFAULT 1,
  rule_agent_offline    INTEGER DEFAULT 1,
  rule_wu_critical      INTEGER DEFAULT 1,
  rule_new_device       INTEGER DEFAULT 1,
  -- Thresholds
  disk_critical_pct     INTEGER DEFAULT 95,
  disk_warning_pct      INTEGER DEFAULT 85,
  av_signature_days     INTEGER DEFAULT 14,
  agent_offline_warn_h  INTEGER DEFAULT 2,
  agent_offline_crit_h  INTEGER DEFAULT 24,
  wu_critical_count     INTEGER DEFAULT 5,
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. Active alerts (open issues)
CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id       INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  rule_key        TEXT NOT NULL,                  -- e.g. "disk_critical", "av_disabled"
  severity        TEXT NOT NULL,                  -- "critical" | "warning" | "info"
  title           TEXT NOT NULL,
  message         TEXT,
  value           TEXT,                           -- e.g. "97.3%" or "BitLocker off"
  status          TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | resolved
  notified        INTEGER DEFAULT 0,              -- 1 if telegram sent
  first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at     TEXT,
  acknowledged_at TEXT,
  acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE(tenant_id, device_id, rule_key)
);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);

-- 3. Alert history (for audit/trends — every fire/resolve event)
CREATE TABLE IF NOT EXISTS alert_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_id    INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
  device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  rule_key    TEXT NOT NULL,
  severity    TEXT NOT NULL,
  event       TEXT NOT NULL,                      -- fired | resolved | acknowledged | notified
  details     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_hist_tenant ON alert_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alert_hist_created ON alert_history(created_at);

-- Seed alert settings for existing tenants
INSERT OR IGNORE INTO alert_settings (tenant_id) SELECT id FROM tenants;
