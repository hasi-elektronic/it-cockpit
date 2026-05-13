-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.5.2 (Multi-AV support)
-- 2026-05-13
-- =====================================================================
-- Tüm AV ürünlerini ayrı tablo olarak sakla (1 cihaz, N AV)
-- security_status.av_product hala 'primary' (best-of) olarak kalır - backward compat

CREATE TABLE IF NOT EXISTS device_antivirus (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,        -- "G DATA Security Client", "Malwarebytes", ...
  enabled       INTEGER DEFAULT 0,    -- real-time aktif mi
  up_to_date    INTEGER DEFAULT 0,    -- signature aktuell mi
  is_defender   INTEGER DEFAULT 0,
  product_state INTEGER,              -- raw bitfield (debugging için)
  last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(device_id, name)
);

CREATE INDEX IF NOT EXISTS idx_antivirus_device ON device_antivirus(device_id);
CREATE INDEX IF NOT EXISTS idx_antivirus_tenant ON device_antivirus(tenant_id);
