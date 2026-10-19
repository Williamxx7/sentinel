-- Agent-based network monitoring (SIEM-lite).
-- Apply locally:  npx wrangler d1 migrations apply DB --local
-- Apply remotely: npx wrangler d1 migrations apply DB --remote

-- Register deployed local agents. Only the SHA-256 hash of the token is
-- stored, never the token itself.
CREATE TABLE IF NOT EXISTS agents (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	last_seen_at TEXT
);

-- Devices discovered on the local network by the agents.
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	mac TEXT NOT NULL UNIQUE,
	ip TEXT,
	hostname TEXT,
	status TEXT NOT NULL DEFAULT 'unknown', -- unknown | known | ignored
	open_ports TEXT NOT NULL DEFAULT '[]',
	agent TEXT,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	notes TEXT NOT NULL DEFAULT ''
);

-- Alerts are deduplicated per key so the same fact doesn't spam the log.
ALTER TABLE incidents ADD COLUMN dedupe_key TEXT;
CREATE INDEX IF NOT EXISTS idx_incidents_dedupe ON incidents(dedupe_key);
