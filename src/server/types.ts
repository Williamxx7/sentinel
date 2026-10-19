// Shared domain types for the Sentinel control room.
// These are storage-agnostic so the local JSON store can later be
// swapped for Cloudflare D1 without touching the pages.

export type AssetType = 'domain' | 'api' | 'key' | 'certificate' | 'other';

export interface Asset {
	id: string;
	name: string;
	type: AssetType;
	identifier: string;
	notes: string;
	expiresAt: string | null;
	tags: string[];
	createdAt: string;
}

export type MonitorStatus = 'up' | 'down' | 'degraded' | 'unknown';

export interface Ping {
	at: string;
	status: MonitorStatus;
	latencyMs: number | null;
	code: number | null;
}

export interface Monitor {
	id: string;
	name: string;
	url: string;
	method: string;
	expectedStatus: number;
	intervalSec: number;
	lastStatus: MonitorStatus;
	lastCheckedAt: string | null;
	lastLatencyMs: number | null;
	lastError: string | null;
	history: Ping[];
	createdAt: string;
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'mitigated' | 'resolved';

export interface Incident {
	id: string;
	title: string;
	description: string;
	severity: Severity;
	status: IncidentStatus;
	source: string;
	tags: string[];
	createdAt: string;
	updatedAt: string;
	resolvedAt: string | null;
}

// Notes are encrypted in the browser (AES-GCM). The server only ever
// stores ciphertext, never the plaintext or the passphrase.
export interface Note {
	id: string;
	title: string;
	ciphertext: string;
	iv: string;
	salt: string;
	createdAt: string;
	updatedAt: string;
}

export interface User {
	id: string;
	username: string;
	passwordHash: string;
	createdAt: string;
}

/** Safe subset of User that may live in request locals / be rendered. */
export interface SessionUser {
	id: string;
	username: string;
}

export interface Session {
	id: string;
	userId: string;
	createdAt: string;
	expiresAt: string;
}

export type DeviceStatus = 'unknown' | 'known' | 'ignored';

export type VulnStatus = 'open' | 'accepted' | 'resolved';

export interface Vulnerability {
	id: string;
	mac: string;
	ip: string | null;
	script: string;
	title: string;
	detail: string;
	severity: Severity;
	status: VulnStatus;
	firstSeen: string;
	lastSeen: string;
}

export interface ServiceInfo {
	port: number;
	name?: string | null;
	product?: string | null;
	version?: string | null;
}

export interface Device {
	id: string;
	mac: string;
	ip: string | null;
	hostname: string | null;
	vendor: string | null;
	status: DeviceStatus;
	openPorts: number[];
	services: ServiceInfo[];
	acceptedBaseline: boolean;
	agent: string | null;
	firstSeen: string;
	lastSeen: string;
	notes: string;
}

export interface Agent {
	id: string;
	name: string;
	createdAt: string;
	lastSeenAt: string | null;
}
