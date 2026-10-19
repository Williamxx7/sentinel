-- Notifications, durable rate limiting and service data.

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- Login throttling that works across Worker isolates (unlike memory).
CREATE TABLE IF NOT EXISTS rate_limits (
	key TEXT PRIMARY KEY,
	count INTEGER NOT NULL,
	reset_at TEXT NOT NULL
);

-- Service/version info reported by nmap -sV: [{port,name,product,version}]
ALTER TABLE devices ADD COLUMN services TEXT NOT NULL DEFAULT '[]';
