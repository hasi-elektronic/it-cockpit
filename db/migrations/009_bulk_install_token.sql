-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.5.5 (Bulk install per tenant)
-- 2026-05-13
-- =====================================================================

-- Tenant bazında bulk install token (Hamdi Sickinger'a gidip her PC'de aynı URL kullanacak)
ALTER TABLE tenants ADD COLUMN install_token TEXT;
ALTER TABLE tenants ADD COLUMN install_enabled INTEGER DEFAULT 1;

-- Yeni enroll endpoint sırasında self-register edilmiş cihazlar için flag
ALTER TABLE devices ADD COLUMN bulk_enrolled INTEGER DEFAULT 0;
