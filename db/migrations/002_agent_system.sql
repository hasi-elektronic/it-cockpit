-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.2 (Agent System)
-- 2026-05-11
-- =====================================================================

-- 1. Agents — her bir kurulu agent için
CREATE TABLE IF NOT EXISTS agents (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id         INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id         INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  enroll_token      TEXT NOT NULL UNIQUE,        -- Müşteri PC'sine konulan token
  agent_token       TEXT UNIQUE,                  -- Register sonrası agent kullanır
  agent_version     TEXT,                         -- 0.2.0 vb.
  os_platform       TEXT,                         -- windows / linux / darwin
  hostname_reported TEXT,                         -- Agent'ın bildirdiği hostname
  status            TEXT NOT NULL DEFAULT 'pending', -- pending|active|inactive|revoked
  last_seen         TEXT,                         -- ISO timestamp
  last_ip           TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_device ON agents(device_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

-- 2. Device telemetry — heartbeat geçmişi (timeseries, 90 gün retention)
CREATE TABLE IF NOT EXISTS device_telemetry (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  agent_id        INTEGER REFERENCES agents(id) ON DELETE SET NULL,
  recorded_at     TEXT NOT NULL DEFAULT (datetime('now')),
  -- System
  uptime_seconds  INTEGER,
  logged_in_user  TEXT,
  cpu_percent     REAL,
  ram_percent     REAL,
  ram_total_gb    REAL,
  ram_used_gb     REAL,
  disk_c_percent  REAL,
  disk_c_total_gb REAL,
  disk_c_free_gb  REAL,
  ip_internal     TEXT,
  ip_external     TEXT,
  -- Network
  last_boot       TEXT
);

CREATE INDEX IF NOT EXISTS idx_telemetry_device ON device_telemetry(device_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_recorded ON device_telemetry(recorded_at);

-- 3. Security status — son durumu agent gönderir, üzerine yazılır (current state)
CREATE TABLE IF NOT EXISTS security_status (
  device_id              INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  tenant_id              INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- BitLocker
  bitlocker_enabled      INTEGER,                -- 0/1
  bitlocker_status_text  TEXT,                   -- "FullyEncrypted" / "Decrypted" / ...
  -- Antivirus
  av_product             TEXT,                   -- "Windows Defender", "Kaspersky"
  av_enabled             INTEGER,
  av_up_to_date          INTEGER,
  av_signature_age_days  INTEGER,
  -- Windows Update
  wu_last_search         TEXT,
  wu_last_install        TEXT,
  wu_pending_count       INTEGER,
  wu_critical_count      INTEGER,
  -- TPM / Boot
  tpm_present            INTEGER,
  tpm_ready              INTEGER,
  secure_boot            INTEGER,
  -- Firewall
  firewall_domain        INTEGER,
  firewall_private       INTEGER,
  firewall_public        INTEGER,
  -- Computed score (0-100)
  security_score         INTEGER,
  updated_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_security_tenant ON security_status(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_score ON security_status(security_score);

-- 4. Installed software (son snapshot her heartbeat update edilir)
CREATE TABLE IF NOT EXISTS installed_software (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  version         TEXT,
  publisher       TEXT,
  install_date    TEXT,
  first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_software_device ON installed_software(device_id);
CREATE INDEX IF NOT EXISTS idx_software_name ON installed_software(name);

-- 5. Add agent-related columns to devices (extend mevcut tablo)
-- Bunlar eklenecek (eğer henüz yoksa, hata yutulacak)
-- SQLite, ALTER TABLE ADD COLUMN ı sadece bir kerede destekler, IF NOT EXISTS yok
-- Migration runner try/catch ile sarmalanacak
