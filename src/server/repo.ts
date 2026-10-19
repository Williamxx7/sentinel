// Data access + domain logic for the Sentinel modules, backed by D1.

import { env } from 'cloudflare:workers';
import { getDB, newId, nowISO, parseJSON, randomToken, sha256Hex } from './store';
import { notifyIncident } from './notify';
import { getSetting } from './settings';
import type {
	Agent,
	Asset,
	AssetType,
	Device,
	DeviceStatus,
	Incident,
	IncidentStatus,
	Monitor,
	MonitorStatus,
	Note,
	Ping,
	ServiceInfo,
	Severity,
	Vulnerability,
	VulnStatus,
} from './types';

/* ------------------------------------------------------------------ */
/* Assets                                                              */
/* ------------------------------------------------------------------ */

const ASSET_TYPES: AssetType[] = ['domain', 'api', 'key', 'certificate', 'other'];

interface AssetRow {
	id: string;
	name: string;
	type: string;
	identifier: string;
	notes: string;
	expires_at: string | null;
	tags: string;
	created_at: string;
}

function toAsset(row: AssetRow): Asset {
	return {
		id: row.id,
		name: row.name,
		type: (ASSET_TYPES.includes(row.type as AssetType) ? row.type : 'other') as AssetType,
		identifier: row.identifier,
		notes: row.notes,
		expiresAt: row.expires_at,
		tags: parseJSON<string[]>(row.tags, []),
		createdAt: row.created_at,
	};
}

export interface AssetInput {
	name: string;
	type: string;
	identifier: string;
	notes: string;
	expiresAt: string | null;
	tags: string[];
}

export async function listAssets(): Promise<Asset[]> {
	// NULL expiry last, then soonest first.
	const { results } = await getDB()
		.prepare('SELECT * FROM assets ORDER BY expires_at IS NULL, expires_at ASC')
		.all<AssetRow>();
	return results.map(toAsset);
}

export async function createAsset(input: AssetInput): Promise<Asset> {
	const type = ASSET_TYPES.includes(input.type as AssetType) ? (input.type as AssetType) : 'other';
	const asset: Asset = {
		id: newId(),
		name: input.name,
		type,
		identifier: input.identifier,
		notes: input.notes,
		expiresAt: input.expiresAt,
		tags: input.tags,
		createdAt: nowISO(),
	};
	await getDB()
		.prepare(
			`INSERT INTO assets (id, name, type, identifier, notes, expires_at, tags, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
		)
		.bind(
			asset.id,
			asset.name,
			asset.type,
			asset.identifier,
			asset.notes,
			asset.expiresAt,
			JSON.stringify(asset.tags),
			asset.createdAt,
		)
		.run();
	return asset;
}

export async function deleteAsset(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM assets WHERE id = ?1').bind(id).run();
}

export async function updateAsset(id: string, input: AssetInput): Promise<void> {
	const type = ASSET_TYPES.includes(input.type as AssetType) ? (input.type as AssetType) : 'other';
	await getDB()
		.prepare(
			`UPDATE assets
       SET name = ?1, type = ?2, identifier = ?3, notes = ?4, expires_at = ?5, tags = ?6
       WHERE id = ?7`,
		)
		.bind(
			input.name,
			type,
			input.identifier,
			input.notes,
			input.expiresAt,
			JSON.stringify(input.tags),
			id,
		)
		.run();
}

/** Days until expiry, or null when no date is set. Negative = expired. */
export function daysUntil(date: string | null): number | null {
	if (!date) return null;
	const ms = new Date(date).getTime() - Date.now();
	if (Number.isNaN(ms)) return null;
	return Math.ceil(ms / 86_400_000);
}

/* ------------------------------------------------------------------ */
/* Monitors / uptime                                                   */
/* ------------------------------------------------------------------ */

const MAX_HISTORY = 50;
const CHECK_TIMEOUT_MS = 8_000;

// Set ALLOW_PRIVATE_TARGETS=true to let uptime monitors point at hosts on
// the local network. Off by default. Note that Cloudflare Workers cannot
// reach private/link-local addresses anyway; this is defence in depth.
const ALLOW_PRIVATE_TARGETS = env.ALLOW_PRIVATE_TARGETS === 'true';

const PRIVATE_HOST_RE = /^(localhost|.+\.localhost|.+\.local|.+\.internal)$/i;

function isPrivateIPv4(ip: string): boolean {
	const p = ip.split('.').map(Number);
	if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
	const [a, b] = p;
	if (a === 0 || a === 10 || a === 127) return true;
	if (a === 169 && b === 254) return true;
	if (a === 172 && b! >= 16 && b! <= 31) return true;
	if (a === 192 && b === 168) return true;
	if (a === 100 && b! >= 64 && b! <= 127) return true;
	if (a === 198 && (b === 18 || b === 19)) return true;
	if (a! >= 224) return true; // multicast / reserved
	return false;
}

/**
 * Reject URLs that clearly point at loopback, link-local or private
 * ranges. On Workers we cannot resolve DNS, so this is a syntactic check
 * (which mirrors what the platform blocks anyway).
 */
export function validateTarget(rawUrl: string): {
	ok: boolean;
	reason?: 'url' | 'private';
} {
	let url: URL;
	try {
		url = new URL(rawUrl);
	} catch {
		return { ok: false, reason: 'url' };
	}
	if (url.protocol !== 'http:' && url.protocol !== 'https:') return { ok: false, reason: 'url' };
	if (ALLOW_PRIVATE_TARGETS) return { ok: true };

	const host = url.hostname.toLowerCase();
	if (PRIVATE_HOST_RE.test(host)) return { ok: false, reason: 'private' };
	if (host.startsWith('[')) return { ok: false, reason: 'private' }; // IPv6 literal
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && isPrivateIPv4(host)) {
		return { ok: false, reason: 'private' };
	}
	return { ok: true };
}

interface MonitorRow {
	id: string;
	name: string;
	url: string;
	method: string;
	expected_status: number;
	interval_sec: number;
	last_status: string;
	last_checked_at: string | null;
	last_latency_ms: number | null;
	last_error: string | null;
	history: string;
	created_at: string;
}

function toMonitor(row: MonitorRow): Monitor {
	return {
		id: row.id,
		name: row.name,
		url: row.url,
		method: row.method,
		expectedStatus: row.expected_status,
		intervalSec: row.interval_sec,
		lastStatus: row.last_status as MonitorStatus,
		lastCheckedAt: row.last_checked_at,
		lastLatencyMs: row.last_latency_ms,
		lastError: row.last_error,
		history: parseJSON<Ping[]>(row.history, []),
		createdAt: row.created_at,
	};
}

export interface MonitorInput {
	name: string;
	url: string;
	method: string;
	expectedStatus: number;
	intervalSec: number;
}

export async function listMonitors(): Promise<Monitor[]> {
	const { results } = await getDB()
		.prepare('SELECT * FROM monitors ORDER BY name ASC')
		.all<MonitorRow>();
	return results.map(toMonitor);
}

export async function createMonitor(input: MonitorInput): Promise<Monitor> {
	const monitor: Monitor = {
		id: newId(),
		name: input.name,
		url: input.url,
		method: input.method,
		expectedStatus: input.expectedStatus,
		intervalSec: input.intervalSec,
		lastStatus: 'unknown',
		lastCheckedAt: null,
		lastLatencyMs: null,
		lastError: null,
		history: [],
		createdAt: nowISO(),
	};
	await getDB()
		.prepare(
			`INSERT INTO monitors
         (id, name, url, method, expected_status, interval_sec, last_status, last_checked_at, last_latency_ms, last_error, history, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
		)
		.bind(
			monitor.id,
			monitor.name,
			monitor.url,
			monitor.method,
			monitor.expectedStatus,
			monitor.intervalSec,
			monitor.lastStatus,
			monitor.lastCheckedAt,
			monitor.lastLatencyMs,
			monitor.lastError,
			JSON.stringify(monitor.history),
			monitor.createdAt,
		)
		.run();
	return monitor;
}

export async function deleteMonitor(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM monitors WHERE id = ?1').bind(id).run();
}

export async function updateMonitor(id: string, input: MonitorInput): Promise<void> {
	// Status and history are left untouched; only the configuration changes.
	await getDB()
		.prepare(
			`UPDATE monitors
       SET name = ?1, url = ?2, method = ?3, expected_status = ?4, interval_sec = ?5
       WHERE id = ?6`,
		)
		.bind(input.name, input.url, input.method, input.expectedStatus, input.intervalSec, id)
		.run();
}

async function probe(monitor: Monitor): Promise<Ping> {
	const started = Date.now();
	if (!validateTarget(monitor.url).ok) {
		return { at: nowISO(), status: 'down', latencyMs: null, code: null };
	}
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);
	try {
		const res = await fetch(monitor.url, {
			method: monitor.method,
			redirect: 'manual',
			signal: controller.signal,
			headers: { 'user-agent': 'Sentinel-Uptime/1.0' },
		});
		const latencyMs = Date.now() - started;
		const status: MonitorStatus = res.status === monitor.expectedStatus ? 'up' : 'degraded';
		return { at: nowISO(), status, latencyMs, code: res.status };
	} catch {
		return { at: nowISO(), status: 'down', latencyMs: null, code: null };
	} finally {
		clearTimeout(timer);
	}
}

/** Check one monitor (or all due monitors) and persist the pings. */
export async function runChecks(id?: string): Promise<Monitor[]> {
	const monitors = await listMonitors();
	const now = Date.now();
	// Without an explicit id (the cron), only run monitors whose interval
	// has elapsed. Manual checks always run.
	const targets = monitors.filter((m) => {
		if (id) return m.id === id;
		if (!m.lastCheckedAt) return true;
		return now >= new Date(m.lastCheckedAt).getTime() + m.intervalSec * 1000;
	});
	if (targets.length === 0) return monitors;

	const pings = new Map<string, Ping>();
	await Promise.all(
		targets.map(async (m) => {
			pings.set(m.id, await probe(m));
		}),
	);

	const db = getDB();
	const statements = targets
		.filter((m) => pings.has(m.id))
		.map((m) => {
			const ping = pings.get(m.id)!;
			const history = [ping, ...m.history].slice(0, MAX_HISTORY);
			return db
				.prepare(
					`UPDATE monitors
             SET last_status = ?1, last_checked_at = ?2, last_latency_ms = ?3, last_error = ?4, history = ?5
             WHERE id = ?6`,
				)
				.bind(
					ping.status,
					ping.at,
					ping.latencyMs,
					ping.status === 'down' ? 'Ingen respons' : null,
					JSON.stringify(history),
					m.id,
				);
		});
	if (statements.length > 0) await db.batch(statements);

	// Uptime failures become incidents (and therefore notifications), and
	// are resolved automatically when the service comes back.
	for (const m of targets) {
		const ping = pings.get(m.id);
		if (!ping) continue;
		if (ping.status === 'down') {
			await raiseAlert(
				{
					title: `Tjeneste nede: ${m.name}`,
					description: `${m.url} svarede ikke som forventet.`,
					severity: 'high',
					source: 'uptime',
					tags: ['uptime', 'nede'],
				},
				`monitor-down:${m.id}`,
			);
		} else {
			await resolveAlert(`monitor-down:${m.id}`);
		}
	}

	return listMonitors();
}

/* ------------------------------------------------------------------ */
/* Incidents                                                           */
/* ------------------------------------------------------------------ */

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];
const INCIDENT_STATUSES: IncidentStatus[] = ['open', 'investigating', 'mitigated', 'resolved'];

interface IncidentRow {
	id: string;
	title: string;
	description: string;
	severity: string;
	status: string;
	source: string;
	tags: string;
	created_at: string;
	updated_at: string;
	resolved_at: string | null;
}

function toIncident(row: IncidentRow): Incident {
	return {
		id: row.id,
		title: row.title,
		description: row.description,
		severity: row.severity as Severity,
		status: row.status as IncidentStatus,
		source: row.source,
		tags: parseJSON<string[]>(row.tags, []),
		createdAt: row.created_at,
		updatedAt: row.updated_at,
		resolvedAt: row.resolved_at,
	};
}

export interface IncidentInput {
	title: string;
	description: string;
	severity: string;
	source: string;
	tags: string[];
}

export async function listIncidents(): Promise<Incident[]> {
	const { results } = await getDB()
		.prepare('SELECT * FROM incidents ORDER BY created_at DESC')
		.all<IncidentRow>();
	return results.map(toIncident);
}

export async function createIncident(input: IncidentInput, dedupeKey?: string): Promise<Incident> {
	const severity = SEVERITIES.includes(input.severity as Severity)
		? (input.severity as Severity)
		: 'medium';
	const now = nowISO();
	const incident: Incident = {
		id: newId(),
		title: input.title,
		description: input.description,
		severity,
		status: 'open',
		source: input.source,
		tags: input.tags,
		createdAt: now,
		updatedAt: now,
		resolvedAt: null,
	};
	await getDB()
		.prepare(
			`INSERT INTO incidents
         (id, title, description, severity, status, source, tags, created_at, updated_at, resolved_at, dedupe_key)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
		)
		.bind(
			incident.id,
			incident.title,
			incident.description,
			incident.severity,
			incident.status,
			incident.source,
			JSON.stringify(incident.tags),
			incident.createdAt,
			incident.updatedAt,
			incident.resolvedAt,
			dedupeKey ?? null,
		)
		.run();
	await notifyIncident(incident);
	return incident;
}

/**
 * Create an alert unless an open incident with the same dedupe key already
 * exists. Returns true when a new incident was created.
 */
export async function raiseAlert(input: IncidentInput, dedupeKey: string): Promise<boolean> {
	const existing = await getDB()
		.prepare("SELECT id FROM incidents WHERE dedupe_key = ?1 AND status <> 'resolved' LIMIT 1")
		.bind(dedupeKey)
		.first<{ id: string }>();
	if (existing) return false;
	await createIncident(input, dedupeKey);
	return true;
}

/** Mark the open incident with this dedupe key as resolved (if any). */
export async function resolveAlert(dedupeKey: string): Promise<void> {
	const now = nowISO();
	await getDB()
		.prepare(
			"UPDATE incidents SET status = 'resolved', resolved_at = ?1, updated_at = ?1 WHERE dedupe_key = ?2 AND status <> 'resolved'",
		)
		.bind(now, dedupeKey)
		.run();
}

export async function setIncidentStatus(id: string, status: string): Promise<void> {
	const next = INCIDENT_STATUSES.includes(status as IncidentStatus)
		? (status as IncidentStatus)
		: 'open';
	const now = nowISO();
	await getDB()
		.prepare('UPDATE incidents SET status = ?1, updated_at = ?2, resolved_at = ?3 WHERE id = ?4')
		.bind(next, now, next === 'resolved' ? now : null, id)
		.run();
}

export async function deleteIncident(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM incidents WHERE id = ?1').bind(id).run();
}

export async function updateIncident(id: string, input: IncidentInput): Promise<void> {
	const severity = SEVERITIES.includes(input.severity as Severity)
		? (input.severity as Severity)
		: 'medium';
	await getDB()
		.prepare(
			`UPDATE incidents
       SET title = ?1, description = ?2, severity = ?3, source = ?4, tags = ?5, updated_at = ?6
       WHERE id = ?7`,
		)
		.bind(
			input.title,
			input.description,
			severity,
			input.source,
			JSON.stringify(input.tags),
			nowISO(),
			id,
		)
		.run();
}

/* ------------------------------------------------------------------ */
/* Notes (ciphertext only)                                             */
/* ------------------------------------------------------------------ */

interface NoteRow {
	id: string;
	title: string;
	ciphertext: string;
	iv: string;
	salt: string;
	created_at: string;
	updated_at: string;
}

function toNote(row: NoteRow): Note {
	return {
		id: row.id,
		title: row.title,
		ciphertext: row.ciphertext,
		iv: row.iv,
		salt: row.salt,
		createdAt: row.created_at,
		updatedAt: row.updated_at,
	};
}

export async function listNotes(): Promise<Note[]> {
	const { results } = await getDB()
		.prepare('SELECT * FROM notes ORDER BY updated_at DESC')
		.all<NoteRow>();
	return results.map(toNote);
}

export interface NoteInput {
	id?: string;
	title: string;
	ciphertext: string;
	iv: string;
	salt: string;
}

export async function upsertNote(input: NoteInput): Promise<Note> {
	const db = getDB();
	const now = nowISO();
	if (input.id) {
		const existing = await db
			.prepare('SELECT * FROM notes WHERE id = ?1')
			.bind(input.id)
			.first<NoteRow>();
		if (existing) {
			await db
				.prepare(
					'UPDATE notes SET title = ?1, ciphertext = ?2, iv = ?3, salt = ?4, updated_at = ?5 WHERE id = ?6',
				)
				.bind(input.title, input.ciphertext, input.iv, input.salt, now, input.id)
				.run();
			return { ...toNote(existing), ...input, updatedAt: now } as Note;
		}
	}
	const note: Note = {
		id: newId(),
		title: input.title,
		ciphertext: input.ciphertext,
		iv: input.iv,
		salt: input.salt,
		createdAt: now,
		updatedAt: now,
	};
	await db
		.prepare(
			`INSERT INTO notes (id, title, ciphertext, iv, salt, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
		)
		.bind(note.id, note.title, note.ciphertext, note.iv, note.salt, note.createdAt, note.updatedAt)
		.run();
	return note;
}

export async function deleteNote(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM notes WHERE id = ?1').bind(id).run();
}

/* ------------------------------------------------------------------ */
/* Agents (local scanners)                                             */
/* ------------------------------------------------------------------ */

interface AgentRow {
	id: string;
	name: string;
	token_hash: string;
	created_at: string;
	last_seen_at: string | null;
}

function toAgent(row: AgentRow): Agent {
	return {
		id: row.id,
		name: row.name,
		createdAt: row.created_at,
		lastSeenAt: row.last_seen_at,
	};
}

export async function listAgents(): Promise<Agent[]> {
	const { results } = await getDB()
		.prepare('SELECT * FROM agents ORDER BY created_at ASC')
		.all<AgentRow>();
	return results.map(toAgent);
}

/** Create an agent and return its token once. Only the hash is stored. */
export async function createAgent(name: string): Promise<{ agent: Agent; token: string }> {
	const db = getDB();
	const base = (name || 'agent').slice(0, 60);
	let finalName = base;
	let suffix = 2;
	// Agent names are identities in devices.agent and dedupe keys, so keep
	// them unique instead of silently colliding.
	while (await db.prepare('SELECT 1 FROM agents WHERE name = ?1').bind(finalName).first()) {
		finalName = `${base.slice(0, 55)}-${suffix++}`;
		if (suffix > 100) break;
	}

	const token = randomToken(32);
	const tokenHash = await sha256Hex(token);
	const agent: Agent = {
		id: newId(),
		name: finalName,
		createdAt: nowISO(),
		lastSeenAt: null,
	};

	// The unique index can still race with a concurrent create. Retry with a
	// random suffix instead of returning a 500 to the UI.
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			await db
				.prepare(
					'INSERT INTO agents (id, name, token_hash, created_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5)',
				)
				.bind(agent.id, agent.name, tokenHash, agent.createdAt, null)
				.run();
			return { agent, token };
		} catch {
			agent.name = `${base.slice(0, 50)}-${randomToken(3)}`;
		}
	}
	throw new Error('Kunne ikke oprette agent');
}

export async function deleteAgent(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM agents WHERE id = ?1').bind(id).run();
}

/** Resolve a bearer token to an agent, or null. */
export async function agentByToken(token: string): Promise<Agent | null> {
	if (!token) return null;
	const row = await getDB()
		.prepare('SELECT * FROM agents WHERE token_hash = ?1')
		.bind(await sha256Hex(token))
		.first<AgentRow>();
	return row ? toAgent(row) : null;
}

export async function touchAgent(id: string): Promise<void> {
	await getDB().prepare('UPDATE agents SET last_seen_at = ?1 WHERE id = ?2').bind(nowISO(), id).run();
}

/* ------------------------------------------------------------------ */
/* Devices discovered on the network                                   */
/* ------------------------------------------------------------------ */

interface DeviceRow {
	id: string;
	mac: string;
	ip: string | null;
	hostname: string | null;
	vendor: string | null;
	status: string;
	open_ports: string;
	services: string;
	accepted_baseline: string | null;
	agent: string | null;
	first_seen: string;
	last_seen: string;
	notes: string;
}

function toDevice(row: DeviceRow): Device {
	return {
		id: row.id,
		mac: row.mac,
		ip: row.ip,
		hostname: row.hostname,
		vendor: row.vendor,
		status: row.status as DeviceStatus,
		openPorts: parseJSON<number[]>(row.open_ports, []),
		services: parseJSON<ServiceInfo[]>(row.services, []),
		acceptedBaseline: Boolean(row.accepted_baseline),
		agent: row.agent,
		firstSeen: row.first_seen,
		lastSeen: row.last_seen,
		notes: row.notes,
	};
}

export async function listDevices(): Promise<Device[]> {
	// Unknown first, then most recently seen.
	const { results } = await getDB()
		.prepare("SELECT * FROM devices ORDER BY (status = 'unknown') DESC, last_seen DESC")
		.all<DeviceRow>();
	return results.map(toDevice);
}

export async function setDeviceStatus(id: string, status: string): Promise<void> {
	const next: DeviceStatus = (['unknown', 'known', 'ignored'] as DeviceStatus[]).includes(
		status as DeviceStatus,
	)
		? (status as DeviceStatus)
		: 'unknown';
	const db = getDB();
	const row = await db.prepare('SELECT mac FROM devices WHERE id = ?1').bind(id).first<{ mac: string }>();
	await db.prepare('UPDATE devices SET status = ?1 WHERE id = ?2').bind(next, id).run();
	// Approving a device closes the "new device" alert.
	if (next === 'known' && row) await resolveAlert(`device-new:${row.mac}`);
}

export async function deleteDevice(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM devices WHERE id = ?1').bind(id).run();
}

export interface IngestDevice {
	mac: string;
	ip?: string | null;
	hostname?: string | null;
	vendor?: string | null;
	openPorts?: number[];
	services?: ServiceInfo[];
}

export interface IngestResult {
	devices: number;
	newDevices: number;
	alerts: number;
}

function cleanPorts(ports: unknown): number[] {
	if (!Array.isArray(ports)) return [];
	return [...new Set(ports.filter((p) => Number.isInteger(p) && p > 0 && p < 65536))]
		.sort((a, b) => a - b)
		.slice(0, 256);
}

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const IP_ID_RE = /^ip:(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+)$/i;

function isValidIdentity(value: string): boolean {
	return MAC_RE.test(value) || IP_ID_RE.test(value);
}

function cleanIp(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	const v = value.trim().slice(0, 64);
	if (!v) return null;
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
		return v.split('.').every((o) => Number(o) <= 255) ? v : null;
	}
	if (/^[0-9a-f:]+$/i.test(v) && v.includes(':')) return v;
	return null;
}

function cleanText(value: unknown, max: number): string | null {
	if (typeof value !== 'string') return null;
	const v = value
		.replace(/[\u0000-\u001f\u007f]/g, '')
		.trim()
		.slice(0, max);
	return v || null;
}

function cleanServices(services: unknown): ServiceInfo[] {
	if (!Array.isArray(services)) return [];
	const byPort = new Map<number, ServiceInfo>();
	for (const s of services) {
		if (!s || typeof s !== 'object') continue;
		const item = s as ServiceInfo;
		const port = Number(item.port);
		if (!Number.isInteger(port) || port <= 0 || port >= 65536) continue;
		byPort.set(port, {
			port,
			name: item.name ? String(item.name).slice(0, 64) : null,
			product: item.product ? String(item.product).slice(0, 128) : null,
			version: item.version ? String(item.version).slice(0, 64) : null,
		});
	}
	return [...byPort.values()].sort((a, b) => a.port - b.port).slice(0, 256);
}

function serviceSignature(services: ServiceInfo[]): string {
	return services.map((s) => `${s.port}:${s.name ?? ''}:${s.product ?? ''}:${s.version ?? ''}`).join('|');
}

/**
 * Merge a new (possibly less detailed) scan into the known services.
 * A quick scan without -sV reports no product/version; keep the last known
 * values for the same port so we don't flip-flop between alerts.
 */
function mergeServices(oldServices: ServiceInfo[], incoming: ServiceInfo[]): ServiceInfo[] {
	const oldByPort = new Map(oldServices.map((s) => [s.port, s]));
	return incoming.map((s) => {
		if (s.product || s.version) return s;
		const prev = oldByPort.get(s.port);
		if (!prev) return s;
		return {
			port: s.port,
			name: s.name ?? prev.name,
			product: prev.product,
			version: prev.version,
		};
	});
}

function serviceLabel(s: ServiceInfo): string {
	const bits = [s.name, s.product, s.version].filter(Boolean).join(' ');
	return `${s.port}${s.name ? `/${s.name}` : ''}${bits ? ` (${bits})` : ''}`;
}

/** Human-readable differences between two service lists. */
function diffServices(oldServices: ServiceInfo[], newServices: ServiceInfo[]): string[] {
	const oldByPort = new Map(oldServices.map((s) => [s.port, s]));
	const newByPort = new Map(newServices.map((s) => [s.port, s]));
	const out: string[] = [];

	for (const [port, service] of newByPort) {
		const prev = oldByPort.get(port);
		if (!prev) {
			out.push(`Ny: ${serviceLabel(service)}`);
			continue;
		}
		if (serviceSignature([prev]) !== serviceSignature([service])) {
			const label = (s: ServiceInfo) =>
				[s.product, s.version].filter(Boolean).join(' ') || s.name || 'ukendt';
			out.push(
				`Ændret: port ${port}${service.name ? `/${service.name}` : ''} ${label(prev)} → ${label(service)}`,
			);
		}
	}
	for (const [port, service] of oldByPort) {
		if (!newByPort.has(port)) out.push(`Fjernet: ${serviceLabel(service)}`);
	}
	return out.slice(0, 10);
}

// A known device not seen for this long is reported as "missing".
// Configurable via Settings (device_missing_hours), default 48.
async function getMissingHours(): Promise<number> {
	const raw = await getSetting('device_missing_hours');
	const n = Number(raw);
	return Number.isFinite(n) && n > 0 ? n : 48;
}

// Cap the number of incidents a single ingest run can create, so a bad or
// malicious agent payload cannot flood the log or the notification budget.
const MAX_ALERTS_PER_RUN = 20;

/**
 * Store a scan result and raise deduplicated incidents for:
 *   - a device never seen before (device-new)
 *   - a known IP whose MAC changed (mac-change)
 *   - new open ports (ports)
 *   - changed services/versions (service-change)
 *   - known devices that stopped appearing (device-missing)
 */
export async function ingestDevices(
	agentName: string,
	devices: IngestDevice[],
): Promise<IngestResult> {
	const db = getDB();
	let newDevices = 0;
	let alerts = 0;
	const seenMacs = new Set<string>();
	const missingHours = await getMissingHours();

	for (const input of devices) {
		if (!input || typeof input !== 'object') continue;
		const mac = typeof input.mac === 'string' ? input.mac.toLowerCase().trim().slice(0, 64) : '';
		if (!isValidIdentity(mac)) continue;
		const ip = cleanIp(input.ip);
		const hostname = cleanText(input.hostname, 253);
		const vendor = cleanText(input.vendor, 128);
		const ports = cleanPorts(input.openPorts);
		let services = cleanServices(input.services);
		const existing = await db
			.prepare('SELECT * FROM devices WHERE mac = ?1')
			.bind(mac)
			.first<DeviceRow>();

		// One agent may not overwrite another agent's device.
		if (existing && existing.agent && existing.agent !== agentName) continue;

		// Only count devices this agent is actually allowed to report, so it
		// cannot close another agent's "missing" alert.
		seenMacs.add(mac);

		// If we previously identified this device by IP only (e.g. before
		// nmap could read ARP), adopt that record instead of creating a
		// duplicate and a false "new device" / "MAC changed" alert.
		if (!existing && ip) {
			const placeholder = await db
				.prepare('SELECT * FROM devices WHERE mac = ?1')
				.bind(`ip:${ip}`)
				.first<DeviceRow>();
			if (placeholder) {
				if (placeholder.agent && placeholder.agent !== agentName) continue;
				services = mergeServices(parseJSON<ServiceInfo[]>(placeholder.services, []), services);
				await db
					.prepare(
						'UPDATE devices SET mac = ?1, ip = ?2, hostname = ?3, vendor = ?4, last_seen = ?5, open_ports = ?6, services = ?7, agent = ?8 WHERE id = ?9',
					)
					.bind(
						mac,
						ip,
						hostname ?? placeholder.hostname,
						vendor ?? placeholder.vendor,
						nowISO(),
						JSON.stringify(ports),
						JSON.stringify(services),
						agentName,
						placeholder.id,
					)
					.run();
				await resolveAlert(`mac-change:${ip}:${mac}`);
				continue;
			}
		}

		if (!existing) {
			// Same IP as a known device but a different MAC: classic sign of
			// a spoofed/randomised address or a replaced device.
			if (ip && alerts < MAX_ALERTS_PER_RUN) {
				const sameIp = await db
					.prepare('SELECT mac FROM devices WHERE ip = ?1 AND mac <> ?2 LIMIT 1')
					.bind(ip, mac)
					.first<{ mac: string }>();
				if (sameIp) {
					const created = await raiseAlert(
						{
							title: `MAC-adresse ændret for ${ip}`,
							description: `Enheden på ${ip} havde MAC ${sameIp.mac}, nu ${mac}.`,
							severity: 'high',
							source: agentName,
							tags: ['netværk', 'mac'],
						},
						`mac-change:${ip}:${mac}`,
					);
					if (created) alerts++;
				}
			}

			const device: Device = {
				id: newId(),
				mac,
				ip,
				hostname,
				vendor,
				status: 'unknown',
				openPorts: ports,
				services,
				agent: agentName,
				firstSeen: nowISO(),
				lastSeen: nowISO(),
				notes: '',
			};
			await db
				.prepare(
					`INSERT INTO devices (id, mac, ip, hostname, vendor, status, open_ports, services, agent, first_seen, last_seen, notes)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
           ON CONFLICT(mac) DO UPDATE SET
             ip = excluded.ip,
             hostname = excluded.hostname,
             vendor = excluded.vendor,
             last_seen = excluded.last_seen,
             open_ports = excluded.open_ports,
             services = excluded.services,
             agent = excluded.agent`,
				)
				.bind(
					device.id,
					device.mac,
					device.ip,
					device.hostname,
					device.vendor,
					device.status,
					JSON.stringify(device.openPorts),
					JSON.stringify(device.services),
					device.agent,
					device.firstSeen,
					device.lastSeen,
					device.notes,
				)
				.run();
			newDevices++;

			if (alerts < MAX_ALERTS_PER_RUN) {
				const created = await raiseAlert(
					{
						title: `Ny enhed på netværket: ${ip ?? mac}`,
						description:
							`MAC ${mac}` +
							(hostname ? `, navn ${hostname}` : '') +
							(vendor ? `, producent ${vendor}` : '') +
							'.' +
							(ports.length ? ` Åbne porte: ${ports.join(', ')}.` : ''),
						severity: 'medium',
						source: agentName,
						tags: ['netværk', 'ny-enhed'],
					},
					`device-new:${mac}`,
				);
				if (created) alerts++;
			}
			continue;
		}

		const oldPorts = parseJSON<number[]>(existing.open_ports, []);
		const oldServices = parseJSON<ServiceInfo[]>(existing.services, []);
		services = mergeServices(oldServices, services);
		const portsChanged = JSON.stringify(oldPorts) !== JSON.stringify(ports);
		const servicesChanged = serviceSignature(oldServices) !== serviceSignature(services);

		// Accepted-risk baseline: if the current ports/services match what the
		// user accepted for this device, don't re-alert on them.
		const baseline = parseJSON<{ ports?: number[]; services?: string }>(
			existing.accepted_baseline,
			{},
		);
		const baselineMatch =
			Array.isArray(baseline.ports) &&
			JSON.stringify(baseline.ports) === JSON.stringify(ports) &&
			baseline.services === serviceSignature(services);

		await db
			.prepare(
				'UPDATE devices SET ip = ?1, hostname = ?2, vendor = ?3, last_seen = ?4, open_ports = ?5, services = ?6, agent = ?7 WHERE mac = ?8',
			)
			.bind(
				ip ?? existing.ip,
				hostname ?? existing.hostname,
				vendor ?? existing.vendor,
				nowISO(),
				JSON.stringify(ports),
				JSON.stringify(services),
				agentName,
				mac,
			)
			.run();

		const label = hostname || existing.hostname || ip || mac;
		const active = existing.status !== 'ignored' && !baselineMatch;

		if (portsChanged && active && alerts < MAX_ALERTS_PER_RUN) {
			const added = ports.filter((p) => !oldPorts.includes(p));
			if (added.length > 0) {
				const created = await raiseAlert(
					{
						title: `Nye åbne porte på ${label}`,
						description: `Nye porte: ${added.join(', ')}.`,
						severity: 'high',
						source: agentName,
						tags: ['netværk', 'port'],
					},
					`ports:${mac}:${added.join(',')}`,
				);
				if (created) alerts++;
			}
		}

		// Only report service changes when the port set is unchanged, so we
		// don't double-report a newly opened port.
		if (servicesChanged && !portsChanged && active && services.length > 0 && alerts < MAX_ALERTS_PER_RUN) {
			const hash = (await sha256Hex(serviceSignature(services))).slice(0, 16);
			const diff = diffServices(oldServices, services);
			const created = await raiseAlert(
				{
					title: `Tjeneste ændret på ${label}`,
					description: diff.length ? diff.join('\n') : 'Tjenester/versioner er ændret.',
					severity: 'medium',
					source: agentName,
					tags: ['netværk', 'tjeneste'],
				},
				`service-change:${mac}:${hash}`,
			);
			if (created) alerts++;
		}
	}

	// Known devices for this agent that have not been seen for a while.
	const cutoff = new Date(Date.now() - missingHours * 3_600_000).toISOString();
	const known = await db
		.prepare(
			"SELECT mac, ip, hostname, last_seen FROM devices WHERE agent = ?1 AND status = 'known'",
		)
		.bind(agentName)
		.all<{ mac: string; ip: string | null; hostname: string | null; last_seen: string }>();

	for (const row of known.results) {
		if (seenMacs.has(row.mac) || row.last_seen > cutoff || alerts >= MAX_ALERTS_PER_RUN) continue;
		const label = row.hostname || row.ip || row.mac;
		const created = await raiseAlert(
			{
				title: `Enhed forsvundet: ${label}`,
				description: `Enheden er ikke set i over ${missingHours} timer.`,
				severity: 'medium',
				source: agentName,
				tags: ['netværk', 'forsvundet'],
			},
			`device-missing:${row.mac}`,
		);
		if (created) alerts++;
	}

	// Devices that are back again close their "missing" incident (batched to
	// keep the number of D1 queries low).
	const keys = [...seenMacs].map((m) => `device-missing:${m}`);
	for (let i = 0; i < keys.length; i += 50) {
		const chunk = keys.slice(i, i + 50);
		const placeholders = chunk.map((_, n) => `?${n + 1}`).join(', ');
		const nowPlaceholder = `?${chunk.length + 1}`;
		await db
			.prepare(
				`UPDATE incidents SET status = 'resolved', resolved_at = ${nowPlaceholder}, updated_at = ${nowPlaceholder}
         WHERE dedupe_key IN (${placeholders}) AND status <> 'resolved'`,
			)
			.bind(...chunk, nowISO())
			.run();
	}

	return { devices: devices.length, newDevices, alerts };
}

/* ------------------------------------------------------------------ */
/* Accepted-risk baselines                                             */
/* ------------------------------------------------------------------ */

export async function acceptBaseline(id: string): Promise<void> {
	const db = getDB();
	const row = await db
		.prepare('SELECT open_ports, services FROM devices WHERE id = ?1')
		.bind(id)
		.first<{ open_ports: string; services: string }>();
	if (!row) return;
	const ports = parseJSON<number[]>(row.open_ports, []);
	const services = parseJSON<ServiceInfo[]>(row.services, []);
	await db
		.prepare('UPDATE devices SET accepted_baseline = ?1 WHERE id = ?2')
		.bind(JSON.stringify({ ports, services: serviceSignature(services) }), id)
		.run();
}

export async function clearBaseline(id: string): Promise<void> {
	await getDB().prepare('UPDATE devices SET accepted_baseline = NULL WHERE id = ?1').bind(id).run();
}

/* ------------------------------------------------------------------ */
/* Vulnerabilities                                                     */
/* ------------------------------------------------------------------ */

interface VulnRow {
	id: string;
	mac: string;
	ip: string | null;
	script: string;
	title: string;
	detail: string;
	severity: string;
	status: string;
	first_seen: string;
	last_seen: string;
}

function toVuln(row: VulnRow): Vulnerability {
	return {
		id: row.id,
		mac: row.mac,
		ip: row.ip,
		script: row.script,
		title: row.title,
		detail: row.detail,
		severity: row.severity as Severity,
		status: row.status as VulnStatus,
		firstSeen: row.first_seen,
		lastSeen: row.last_seen,
	};
}

export async function listVulnerabilities(): Promise<Vulnerability[]> {
	const { results } = await getDB()
		.prepare(
			`SELECT * FROM vulnerabilities
       ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'accepted' THEN 1 ELSE 2 END,
                CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                last_seen DESC`,
		)
		.all<VulnRow>();
	return results.map(toVuln);
}

export interface IngestFinding {
	mac: string;
	ip?: string | null;
	script: string;
	title?: string;
	detail?: string;
	severity?: string;
}

function vulnDedupeKey(mac: string, script: string, title: string, hash: string): string {
	return `vuln:${mac}:${script}:${hash}`;
}

export async function ingestFindings(
	agentName: string,
	findings: IngestFinding[],
): Promise<{ findings: number; newFindings: number; alerts: number }> {
	const db = getDB();
	let newFindings = 0;
	let alerts = 0;

	for (const f of findings.slice(0, 500)) {
		if (!f || typeof f !== 'object') continue;
		const mac = typeof f.mac === 'string' ? f.mac.toLowerCase().trim().slice(0, 64) : '';
		if (!isValidIdentity(mac)) continue;
		const script = cleanText(f.script, 120) ?? 'unknown';
		const title = cleanText(f.title, 200) ?? script;
		const detail = cleanText(f.detail, 2000) ?? '';
		const severity = (['low', 'medium', 'high', 'critical'] as Severity[]).includes(
			f.severity as Severity,
		)
			? (f.severity as Severity)
			: 'medium';
		const ip = cleanIp(f.ip);

		const existing = await db
			.prepare('SELECT * FROM vulnerabilities WHERE mac = ?1 AND script = ?2 AND title = ?3')
			.bind(mac, script, title)
			.first<VulnRow>();
		const now = nowISO();

		if (!existing) {
			await db
				.prepare(
					`INSERT INTO vulnerabilities (id, mac, ip, script, title, detail, severity, status, first_seen, last_seen)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
				)
				.bind(newId(), mac, ip, script, title, detail, severity, 'open', now, now)
				.run();
			newFindings++;

			if (alerts < MAX_ALERTS_PER_RUN) {
				const hash = (await sha256Hex(title)).slice(0, 16);
				const created = await raiseAlert(
					{
						title: `Sårbarhed: ${title}`,
						description: `${script}${ip ? ` på ${ip}` : ''}${detail ? `\n${detail}` : ''}`,
						severity,
						source: agentName,
						tags: ['sårbarhed', script],
					},
					vulnDedupeKey(mac, script, title, hash),
				);
				if (created) alerts++;
			}
		} else {
			await db
				.prepare(
					'UPDATE vulnerabilities SET last_seen = ?1, ip = ?2, detail = ?3, severity = ?4 WHERE id = ?5',
				)
				.bind(now, ip ?? existing.ip, detail || existing.detail, severity, existing.id)
				.run();
		}
	}

	return { findings: findings.length, newFindings, alerts };
}

export async function setVulnerabilityStatus(id: string, status: string): Promise<void> {
	const next: VulnStatus = (['open', 'accepted', 'resolved'] as VulnStatus[]).includes(
		status as VulnStatus,
	)
		? (status as VulnStatus)
		: 'open';
	const db = getDB();
	const row = await db
		.prepare('SELECT mac, script, title FROM vulnerabilities WHERE id = ?1')
		.bind(id)
		.first<{ mac: string; script: string; title: string }>();
	await db.prepare('UPDATE vulnerabilities SET status = ?1 WHERE id = ?2').bind(next, id).run();
	if (row && next !== 'open') {
		const hash = (await sha256Hex(row.title)).slice(0, 16);
		await resolveAlert(vulnDedupeKey(row.mac, row.script, row.title, hash));
	}
}

export async function deleteVulnerability(id: string): Promise<void> {
	await getDB().prepare('DELETE FROM vulnerabilities WHERE id = ?1').bind(id).run();
}

/* ------------------------------------------------------------------ */
/* Retention / cleanup                                                 */
/* ------------------------------------------------------------------ */

/** Delete expired sessions, old counters and stale data. Runs in cron. */
export async function cleanupExpired(): Promise<void> {
	const db = getDB();
	const now = nowISO();
	const oldDevices = new Date(Date.now() - 180 * 86_400_000).toISOString();
	const oldIncidents = new Date(Date.now() - 365 * 86_400_000).toISOString();
	const oldLimits = new Date(Date.now() - 86_400_000).toISOString();

	await db.batch([
		db.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(now),
		db.prepare('DELETE FROM rate_limits WHERE reset_at < ?1').bind(oldLimits),
		db.prepare('DELETE FROM devices WHERE last_seen < ?1').bind(oldDevices),
		db
			.prepare(
				"DELETE FROM incidents WHERE status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at < ?1",
			)
			.bind(oldIncidents),
	]);
}

/* ------------------------------------------------------------------ */
/* Dashboard summary                                                   */
/* ------------------------------------------------------------------ */

export interface Summary {
	assetCount: number;
	assetsExpiringSoon: number;
	monitorsUp: number;
	monitorsDown: number;
	monitorsTotal: number;
	openIncidents: number;
	criticalIncidents: number;
	noteCount: number;
	devicesUnknown: number;
}

export async function summary(): Promise<Summary> {
	const db = getDB();
	const soonCutoff = new Date(Date.now() + 30 * 86_400_000).toISOString();
	const [assets, soon, up, down, total, open, critical, notes, unknownDevices] = await db.batch([
		db.prepare('SELECT COUNT(*) AS n FROM assets'),
		db.prepare('SELECT COUNT(*) AS n FROM assets WHERE expires_at IS NOT NULL AND expires_at <= ?1').bind(soonCutoff),
		db.prepare("SELECT COUNT(*) AS n FROM monitors WHERE last_status = 'up'"),
		db.prepare("SELECT COUNT(*) AS n FROM monitors WHERE last_status = 'down'"),
		db.prepare('SELECT COUNT(*) AS n FROM monitors'),
		db.prepare("SELECT COUNT(*) AS n FROM incidents WHERE status <> 'resolved'"),
		db.prepare("SELECT COUNT(*) AS n FROM incidents WHERE severity = 'critical' AND status <> 'resolved'"),
		db.prepare('SELECT COUNT(*) AS n FROM notes'),
		db.prepare("SELECT COUNT(*) AS n FROM devices WHERE status = 'unknown'"),
	]);

	const n = (r: D1Result): number => (r.results?.[0] as { n?: number } | undefined)?.n ?? 0;
	return {
		assetCount: n(assets!),
		assetsExpiringSoon: n(soon!),
		monitorsUp: n(up!),
		monitorsDown: n(down!),
		monitorsTotal: n(total!),
		openIncidents: n(open!),
		criticalIncidents: n(critical!),
		noteCount: n(notes!),
		devicesUnknown: n(unknownDevices!),
	};
}
