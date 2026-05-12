-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.5 (Super-Admin tenant management)
-- 2026-05-12
-- =====================================================================

-- 1. Erweitere tenants um Kontakt-/Vertragsdaten
ALTER TABLE tenants ADD COLUMN contact_name TEXT;
ALTER TABLE tenants ADD COLUMN contact_email TEXT;
ALTER TABLE tenants ADD COLUMN contact_phone TEXT;
ALTER TABLE tenants ADD COLUMN address TEXT;
ALTER TABLE tenants ADD COLUMN city TEXT;
ALTER TABLE tenants ADD COLUMN industry TEXT;
ALTER TABLE tenants ADD COLUMN monthly_fee REAL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN notes TEXT;
ALTER TABLE tenants ADD COLUMN updated_at TEXT;

-- 2. Hamdi's user wechselt zu Hasi-System-Tenant + super_admin Rolle
UPDATE users SET tenant_id = 2 WHERE email = 'h.guencavdi@hasi-elektronic.de';

-- 3. Sickinger Daten erganzen (Pilot)
UPDATE tenants SET
  contact_name = 'Manfred Sickinger',
  city = 'Vaihingen an der Enz',
  industry = 'Maschinenbau / Druckteile',
  monthly_fee = 450.00,
  notes = 'Pilotkunde - 30 PCs. Vertragsstart Mai 2026.',
  updated_at = datetime('now')
WHERE slug = 'sickinger';

-- 4. Hasi-Tenant Daten erganzen
UPDATE tenants SET
  contact_name = 'Hamdi Güncavdi',
  contact_email = 'h.guencavdi@hasi-elektronic.de',
  city = 'Vaihingen an der Enz',
  industry = 'IT-Dienstleistung (System)',
  notes = 'Master-Account - hier verwaltest du alle Kunden',
  updated_at = datetime('now')
WHERE slug = 'hasi';
