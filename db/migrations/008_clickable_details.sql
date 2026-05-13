-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.5.3 (Tıklanabilir detay)
-- 2026-05-13
-- =====================================================================

-- security_status'a 2 yeni text alan (JSON)
ALTER TABLE security_status ADD COLUMN open_ports_detail TEXT;   -- JSON array
ALTER TABLE security_status ADD COLUMN local_admins_list TEXT;   -- JSON array
