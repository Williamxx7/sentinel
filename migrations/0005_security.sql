-- Session hardening and agent name uniqueness.

-- Idle timeout support: the raw session id is no longer stored.
ALTER TABLE sessions ADD COLUMN last_used_at TEXT;

-- Older code allowed duplicate agent names. Resolve those before the
-- unique index, otherwise the migration would fail.
UPDATE agents
SET name = name || '-' || substr(id, 1, 8)
WHERE rowid NOT IN (SELECT MIN(rowid) FROM agents GROUP BY name);

-- Agent names are identities (devices.agent, dedupe keys), so they must be unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_name ON agents(name);
