-- =========================================================
-- Hasi IT-Cockpit — D1 Schema v0.1
-- Multi-tenant SaaS for SMB IT management
-- =========================================================

-- 1. Tenants (Kunden)
CREATE TABLE IF NOT EXISTS tenants (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  slug          TEXT NOT NULL UNIQUE,            -- 'sickinger'
  name          TEXT NOT NULL,                   -- 'Manfred Sickinger GmbH'
  plan          TEXT NOT NULL DEFAULT 'pilot',   -- pilot|starter|pro|enterprise
  device_quota  INTEGER NOT NULL DEFAULT 50,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  status        TEXT NOT NULL DEFAULT 'active'
);

-- 2. Users (Mitarbeiter + Admin pro Tenant)
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email         TEXT NOT NULL,
  full_name     TEXT,
  department    TEXT,
  role          TEXT NOT NULL DEFAULT 'user',    -- super_admin|admin|user|viewer
  pw_hash       TEXT,                            -- PBKDF2 (null wenn nur Mitarbeiter ohne Login)
  pw_salt       TEXT,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_login    TEXT,
  UNIQUE(tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 3. Devices (Hardware-Inventar)
CREATE TABLE IF NOT EXISTS devices (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  hostname        TEXT NOT NULL,                  -- SICK-PC-042
  device_type     TEXT NOT NULL DEFAULT 'desktop',-- desktop|laptop|server|phone|tablet|printer|other
  manufacturer    TEXT,                           -- Dell, HP, Lenovo
  model           TEXT,                           -- OptiPlex 7080
  serial_number   TEXT,
  os              TEXT,                           -- Windows 11 Pro 23H2
  cpu             TEXT,
  ram_gb          INTEGER,
  storage_gb      INTEGER,
  mac_address     TEXT,
  ip_address      TEXT,
  location        TEXT,                           -- Buero, Werkstatt, Lager
  assigned_to     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  purchase_date   TEXT,
  warranty_until  TEXT,
  status          TEXT NOT NULL DEFAULT 'active', -- active|repair|retired|lost
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(tenant_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_devices_assigned ON devices(assigned_to);
CREATE INDEX IF NOT EXISTS idx_devices_warranty ON devices(warranty_until);

-- 4. Licenses (Software-Lizenzen)
CREATE TABLE IF NOT EXISTS licenses (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  software_name   TEXT NOT NULL,                  -- Microsoft 365 Business Standard
  vendor          TEXT,                           -- Microsoft
  license_type    TEXT NOT NULL DEFAULT 'subscription', -- perpetual|subscription|oem|volume
  license_key     TEXT,                           -- verschluesselt im Worker
  seats_total     INTEGER NOT NULL DEFAULT 1,
  seats_used      INTEGER NOT NULL DEFAULT 0,
  cost_per_year   REAL,
  currency        TEXT DEFAULT 'EUR',
  purchase_date   TEXT,
  expires_at      TEXT,
  renewal_auto    INTEGER NOT NULL DEFAULT 0,
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at);

-- 5. Assignments (Welche License auf welchem Device / User)
CREATE TABLE IF NOT EXISTS assignments (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  license_id    INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  device_id     INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
  assigned_at   TEXT NOT NULL DEFAULT (datetime('now')),
  unassigned_at TEXT,
  notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_assignments_tenant ON assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assignments_license ON assignments(license_id);

-- 6. Audit Log (DSGVO-konforme Aktion-Historie)
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action        TEXT NOT NULL,                    -- create|update|delete|login|export|import
  entity_type   TEXT NOT NULL,                    -- device|license|user|assignment
  entity_id     INTEGER,
  details       TEXT,                             -- JSON: vor/nach State
  ip_address    TEXT,
  user_agent    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- =========================================================
-- Seed: Sickinger tenant + Hamdi als super_admin
-- =========================================================
INSERT OR IGNORE INTO tenants (slug, name, plan, device_quota)
VALUES ('sickinger', 'Manfred Sickinger GmbH', 'pilot', 50);

INSERT OR IGNORE INTO tenants (slug, name, plan, device_quota)
VALUES ('hasi', 'Hasi Elektronic (System)', 'enterprise', 100);
