-- Security findings and accepted-risk baselines.

-- Per-device accepted ports/services baseline (JSON). When the current
-- state matches, port/service alerts are suppressed for that device.
ALTER TABLE devices ADD COLUMN accepted_baseline TEXT;

-- Findings reported by the weekly nmap vulnerability scan.
CREATE TABLE IF NOT EXISTS vulnerabilities (
	id TEXT PRIMARY KEY,
	mac TEXT NOT NULL,
	ip TEXT,
	script TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT 'medium',
	status TEXT NOT NULL DEFAULT 'open', -- open | accepted | resolved
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	UNIQUE(mac, script, title)
);
CREATE INDEX IF NOT EXISTS idx_vulns_mac ON vulnerabilities(mac);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
