-- ============================================================
-- Migration 014: Agent versioning + self-update (Security Layer 8/8)
-- ============================================================

-- Central version registry — controls what version agents should run.
-- Worker reads from here on every heartbeat to tell agent whether to upgrade.
CREATE TABLE IF NOT EXISTS agent_versions (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  version         TEXT NOT NULL UNIQUE,          -- e.g. '0.5.5'
  platform        TEXT NOT NULL DEFAULT 'windows',  -- windows | linux | macos
  r2_key          TEXT NOT NULL,                  -- e.g. 'v0.5.5/hasi-agent-windows-amd64.exe'
  sha256          TEXT,                            -- hex digest for integrity
  size_bytes      INTEGER,
  released_at     TEXT DEFAULT (datetime('now')),
  is_latest       INTEGER NOT NULL DEFAULT 0,     -- only ONE row per platform should have this = 1
  is_required     INTEGER NOT NULL DEFAULT 0,     -- if 1, agents MUST upgrade (security fix)
  release_notes   TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_versions_latest ON agent_versions(platform, is_latest);
CREATE INDEX IF NOT EXISTS idx_agent_versions_version ON agent_versions(version);

-- Audit: which agents upgraded when (for rollout monitoring)
CREATE TABLE IF NOT EXISTS agent_upgrade_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id        INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  from_version    TEXT,
  to_version      TEXT,
  triggered_at    TEXT NOT NULL DEFAULT (datetime('now')),
  succeeded       INTEGER,                          -- 1 = ack received, 0 = no ack
  succeeded_at    TEXT,
  error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_upgrade_log_agent ON agent_upgrade_log(agent_id, triggered_at DESC);

-- Seed: register v0.5.5 as the current latest (agents already on this)
INSERT OR IGNORE INTO agent_versions (version, platform, r2_key, is_latest, release_notes)
VALUES ('0.5.5', 'windows', 'latest/hasi-agent-windows-amd64.exe', 1,
        'AnyDesk ID auto-detection + 30 telemetry fields');
