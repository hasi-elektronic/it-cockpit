-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.5 (Extended Telemetry)
-- 2026-05-12
-- =====================================================================

-- security_status: yeni kolonlar
ALTER TABLE security_status ADD COLUMN defender_tamper_on INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN uac_enabled INTEGER DEFAULT 1;
ALTER TABLE security_status ADD COLUMN rdp_enabled INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN auto_login_enabled INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN pending_reboot INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN pending_reboot_reason TEXT;
ALTER TABLE security_status ADD COLUMN failed_logons_24h INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN local_admin_count INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN open_ports_count INTEGER DEFAULT 0;
ALTER TABLE security_status ADD COLUMN open_ports_list TEXT;

-- device_telemetry: yeni kolonlar
ALTER TABLE device_telemetry ADD COLUMN cpu_temp_c REAL;
ALTER TABLE device_telemetry ADD COLUMN battery_wear_pct REAL;
ALTER TABLE device_telemetry ADD COLUMN battery_health TEXT;
ALTER TABLE device_telemetry ADD COLUMN boot_time_sec INTEGER;
ALTER TABLE device_telemetry ADD COLUMN outdated_sw_count INTEGER DEFAULT 0;

-- Multi-disk: ayrı tablo (bir cihazın birden fazla diski olabilir)
CREATE TABLE IF NOT EXISTS device_disks (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  mount         TEXT NOT NULL,        -- C:, D:, ...
  label         TEXT,
  filesystem    TEXT,
  total_gb      REAL,
  free_gb       REAL,
  percent       REAL,
  smart_health  TEXT,                 -- Healthy | Warning | Unhealthy | Unknown
  disk_type     TEXT,                 -- SSD | HDD | NVMe | USB | Local
  last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, mount)
);

CREATE INDEX IF NOT EXISTS idx_disks_device ON device_disks(device_id);

-- Top processes: snapshot tablosu (her heartbeat'te güncellenir)
CREATE TABLE IF NOT EXISTS device_processes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  pid           INTEGER,
  ram_mb        REAL,
  cpu_pct       REAL,
  rank          INTEGER NOT NULL,     -- 1 to 10 (top 10 listesi)
  captured_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_procs_device ON device_processes(device_id);

-- Browser versions
CREATE TABLE IF NOT EXISTS device_browsers (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  browser_name TEXT NOT NULL,
  version      TEXT,
  outdated     INTEGER DEFAULT 0,
  last_seen    TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, browser_name)
);

CREATE INDEX IF NOT EXISTS idx_browsers_device ON device_browsers(device_id);

-- Alert settings için yeni kurallar
ALTER TABLE alert_settings ADD COLUMN rule_pending_reboot INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_uptime_long INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_smart_warning INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_failed_logon_spike INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_browser_outdated INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_patch_high INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_battery_wear INTEGER DEFAULT 1;
ALTER TABLE alert_settings ADD COLUMN rule_defender_tamper_off INTEGER DEFAULT 1;

ALTER TABLE alert_settings ADD COLUMN pending_reboot_days INTEGER DEFAULT 7;
ALTER TABLE alert_settings ADD COLUMN uptime_max_days INTEGER DEFAULT 60;
ALTER TABLE alert_settings ADD COLUMN failed_logon_threshold INTEGER DEFAULT 20;
ALTER TABLE alert_settings ADD COLUMN patch_high_threshold INTEGER DEFAULT 20;
ALTER TABLE alert_settings ADD COLUMN battery_wear_threshold INTEGER DEFAULT 30;
