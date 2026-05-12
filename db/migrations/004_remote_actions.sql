-- =====================================================================
-- Hasi IT-Cockpit — Migration v0.4 (Remote Actions / Command Queue)
-- 2026-05-12
-- =====================================================================

-- Command queue: pending commands per device + execution results
CREATE TABLE IF NOT EXISTS commands (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  agent_id        INTEGER REFERENCES agents(id) ON DELETE SET NULL,
  command_type    TEXT NOT NULL,           -- 'reboot' | 'lock' | 'msg' | 'ping' | 'ps' | 'cmd'
  command_args    TEXT,                    -- JSON: type-specific args (e.g. {"script":"Get-Process"})
  status          TEXT NOT NULL DEFAULT 'queued',   -- queued | sent | running | done | error | timeout | cancelled
  created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  picked_at       TEXT,                    -- agent has picked it up
  completed_at    TEXT,
  result_stdout   TEXT,                    -- truncated to 16KB
  result_stderr   TEXT,                    -- truncated to 4KB
  result_exit     INTEGER,                 -- exit code
  error_message   TEXT,
  timeout_seconds INTEGER DEFAULT 120,
  notes           TEXT                     -- admin's note why the command was issued
);

CREATE INDEX IF NOT EXISTS idx_commands_device_status ON commands(device_id, status);
CREATE INDEX IF NOT EXISTS idx_commands_tenant ON commands(tenant_id, created_at);

-- Command type whitelist (used by Worker to validate)
-- This is informational — actual enforcement happens in Worker code.
CREATE TABLE IF NOT EXISTS command_types (
  type            TEXT PRIMARY KEY,
  label           TEXT NOT NULL,
  category        TEXT NOT NULL,           -- 'safe' | 'caution' | 'dangerous'
  description     TEXT,
  requires_admin  INTEGER DEFAULT 1
);

INSERT OR IGNORE INTO command_types (type, label, category, description, requires_admin) VALUES
  ('ping',   'Ping',                'safe',      'Test, ob der Agent erreichbar ist',       0),
  ('msg',    'Nachricht anzeigen',  'safe',      'Popup-Nachricht beim Benutzer anzeigen',  1),
  ('lock',   'Bildschirm sperren',  'caution',   'Sperrt sofort den Bildschirm',            1),
  ('reboot', 'Neustart',            'dangerous', 'Startet den PC neu (60s Vorlaufzeit)',    1),
  ('ps',     'PowerShell Skript',   'dangerous', 'Fuehrt PowerShell-Befehl als SYSTEM aus', 1),
  ('cmd',    'CMD Befehl',          'dangerous', 'Fuehrt CMD-Befehl aus',                   1);
