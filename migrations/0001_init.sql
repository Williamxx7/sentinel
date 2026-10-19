-- Sentinel schema (Cloudflare D1 / SQLite).
-- Apply locally:  npx wrangler d1 migrations apply DB --local
-- Apply remotely: npx wrangler d1 migrations apply DB --remote

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS assets (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	identifier TEXT NOT NULL,
	notes TEXT NOT NULL DEFAULT '',
	expires_at TEXT,
	tags TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_expires ON assets(expires_at);

CREATE TABLE IF NOT EXISTS monitors (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	url TEXT NOT NULL,
	method TEXT NOT NULL DEFAULT 'GET',
	expected_status INTEGER NOT NULL DEFAULT 200,
	interval_sec INTEGER NOT NULL DEFAULT 300,
	last_status TEXT NOT NULL DEFAULT 'unknown',
	last_checked_at TEXT,
	last_latency_ms INTEGER,
	last_error TEXT,
	history TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	title TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT 'medium',
	status TEXT NOT NULL DEFAULT 'open',
	source TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS notes (
	id TEXT PRIMARY KEY,
	title TEXT NOT NULL,
	ciphertext TEXT NOT NULL,
	iv TEXT NOT NULL,
	salt TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
