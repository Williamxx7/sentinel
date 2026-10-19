#!/usr/bin/env node
// Sentinel network agent
//
// Runs on a machine inside the network you own (e.g. a Proxmox host or a
// container) and reports what it sees to your Sentinel instance. It is
// designed to be run every 5 minutes by cron or a systemd timer, then exits.
//
// What it does:
//   1. Pings every host in the given subnets (to populate the ARP table).
//   2. Reads the neighbour (ARP) table to find MAC/IP pairs.
//   3. Optionally opens a TCP connection to a small list of ports per host.
//   4. Uploads the result to <SENTINEL_URL>/api/ingest with a bearer token.
//
// Only scan networks you own. This tool is for your own LAN.
//
// Configuration (environment variables):
//   SENTINEL_URL       Base URL, e.g. https://sentinel.example.workers.dev
//   SENTINEL_TOKEN     Agent token from the Sentinel Settings page
//   SCAN_SUBNETS       Comma-separated CIDRs, e.g. 192.168.1.0/24,10.0.0.0/24
//                      (default: auto-detect from local interfaces, /24 each)
//   ENABLE_PORT_SCAN   "true" to also check open ports
//   PORTS              Comma-separated ports (default: 22,23,53,80,443,445,3389,8080,8443,5900)
//   PING_TIMEOUT_MS    Per-host ping timeout (default 800)
//   PORT_TIMEOUT_MS    Per-port connect timeout (default 500)
//
// Usage:
//   SENTINEL_URL=... SENTINEL_TOKEN=... node sentinel-agent.mjs
//   node sentinel-agent.mjs --dry-run        # print, do not upload

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import { promisify } from 'node:util';
import dns from 'node:dns/promises';
import { parseNmapScripts, parseNmapXml } from './nmap-xml.mjs';

const execFileAsync = promisify(execFile);
const DRY_RUN = process.argv.includes('--dry-run');

const DEFAULT_PORTS = [22, 23, 53, 80, 443, 445, 3389, 8080, 8443, 5900];
const MAX_HOSTS = 1024;

/* --------------------------- small helpers --------------------------- */

function ipToInt(ip) {
	return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}
function intToIp(n) {
	return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseCidr(cidr) {
	const [addr, bitsRaw] = cidr.split('/');
	const bits = Number(bitsRaw ?? 24);
	if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr) || bits < 0 || bits > 32) return [];
	const base = ipToInt(addr) & (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
	const size = 2 ** (32 - bits);
	const hosts = [];
	// Skip network + broadcast on prefixes of /31 or larger.
	for (let i = bits >= 31 ? 0 : 1; i < size - (bits >= 31 ? 0 : 1); i++) {
		hosts.push(intToIp((base + i) >>> 0));
		if (hosts.length >= MAX_HOSTS) break;
	}
	return hosts;
}

async function mapLimit(items, limit, fn) {
	const results = [];
	let index = 0;
	async function worker() {
		while (index < items.length) {
			const i = index++;
			results[i] = await fn(items[i], i);
		}
	}
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
	return results;
}

/* ------------------------------ discovery ---------------------------- */

function detectSubnets() {
	const addrs = [];
	for (const list of Object.values(os.networkInterfaces())) {
		for (const ni of list ?? []) {
			if (ni.family !== 'IPv4' || ni.internal) continue;
			// Use the /24 that contains this address.
			const ip = ni.address;
			const cidr = `${ip.split('.').slice(0, 3).join('.')}.0/24`;
			addrs.push(cidr);
		}
	}
	return [...new Set(addrs)];
}

async function ping(ip, timeoutMs) {
	try {
		const args =
			process.platform === 'darwin'
				? ['-c', '1', '-t', String(Math.ceil(timeoutMs / 1000)), ip]
				: ['-c', '1', '-W', String(Math.ceil(timeoutMs / 1000)), ip];
		await execFileAsync('ping', args, { timeout: timeoutMs + 1000 });
	} catch {
		/* unreachable hosts throw; that is fine */
	}
}

async function readNeighbors() {
	const map = new Map();
	try {
		const { stdout } = await execFileAsync('ip', ['neigh', 'show'], { timeout: 5000 });
		for (const line of stdout.split('\n')) {
			const m = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]{17})/i);
			if (m) map.set(m[1], m[2].toLowerCase());
		}
	} catch {
		// Fallback for systems without `ip` (e.g. macOS).
		try {
			const { stdout } = await execFileAsync('arp', ['-an'], { timeout: 5000 });
			for (const line of stdout.split('\n')) {
				const m = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)/i);
				if (m && m[2] !== 'incomplete') map.set(m[1], m[2].toLowerCase());
			}
		} catch {
			/* give up; empty result */
		}
	}
	return map;
}

function scanPort(ip, port, timeoutMs) {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		let done = false;
		const finish = (open) => {
			if (done) return;
			done = true;
			socket.destroy();
			resolve(open);
		};
		socket.setTimeout(timeoutMs);
		socket.once('connect', () => finish(true));
		socket.once('timeout', () => finish(false));
		socket.once('error', () => finish(false));
		socket.connect(port, ip);
	});
}

async function scanPorts(ip, ports, timeoutMs) {
	const open = [];
	await mapLimit(ports, 8, async (p) => {
		if (await scanPort(ip, p, timeoutMs)) open.push(p);
	});
	return open.sort((a, b) => a - b);
}

async function reverseDns(ip) {
	try {
		const names = await Promise.race([
			dns.reverse(ip),
			new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1000)),
		]);
		return names[0] ?? null;
	} catch {
		return null;
	}
}

function inSubnets(ip, subnets) {	const value = ipToInt(ip);
	return subnets.some((cidr) => {
		const [addr, bitsRaw] = cidr.split('/');
		const bits = Number(bitsRaw ?? 24);
		const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
		return (value & mask) === (ipToInt(addr) & mask);
	});
}

/* ---------------------------- DHCP leases ---------------------------- */

/**
 * Read DHCP leases so sleeping wireless clients still show up.
 * Supports dnsmasq's leases file and a JSON array (custom scripts/APIs).
 * `source` may be a local path or an http(s) URL.
 */
async function readDhcpLeases(source) {
	const map = new Map();
	if (!source) return map;

	let text;
	try {
		if (/^https?:\/\//i.test(source)) {
			const res = await fetch(source);
			if (!res.ok) throw new Error(String(res.status));
			text = await res.text();
		} else {
			text = await readFile(source, 'utf8');
		}
	} catch (err) {
		console.error(`[agent] kunne ikke læse DHCP-leases (${source}): ${err.message}`);
		return map;
	}

	const trimmed = text.trim();

	// JSON: [{ mac, ip, hostname }] or { leases: [...] }
	if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
		try {
			const parsed = JSON.parse(trimmed);
			const list = Array.isArray(parsed) ? parsed : (parsed.leases ?? []);
			for (const l of list) {
				const mac = String(l.mac ?? l.hwaddr ?? l.macaddr ?? '').toLowerCase();
				if (!mac) continue;
				map.set(mac, {
					mac,
					ip: l.ip ?? l.address ?? null,
					hostname: l.hostname ?? l.name ?? null,
				});
			}
			return map;
		} catch {
			/* fall through to dnsmasq */
		}
	}

	// dnsmasq: <expiry> <mac> <ip> <hostname> <clientid>
	const now = Math.floor(Date.now() / 1000);
	for (const line of trimmed.split('\n')) {
		const parts = line.trim().split(/\s+/);
		if (parts.length < 3) continue;
		const [expiry, mac, ip, hostname] = parts;
		if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac ?? '')) continue;
		const exp = Number(expiry);
		if (Number.isFinite(exp) && exp !== 0 && exp < now) continue;
		map.set(mac.toLowerCase(), {
			mac: mac.toLowerCase(),
			ip: ip ?? null,
			hostname: hostname && hostname !== '*' ? hostname : null,
		});
	}
	return map;
}

/* ------------------------------ scanners ----------------------------- */

/** Discovery via ping + the local ARP table (no nmap, no root). */
async function scanSimple(activeSubnets, { portScan, ports, pingTimeout, portTimeout }) {
	const hosts = [...new Set(activeSubnets.flatMap(parseCidr))];
	console.error(`[agent] pinging ${hosts.length} hosts ...`);
	await mapLimit(hosts, 64, (ip) => ping(ip, pingTimeout));

	const neighbors = await readNeighbors();
	const devices = [];
	for (const [ip, mac] of neighbors) {
		if (!inSubnets(ip, activeSubnets)) continue;
		const openPorts = portScan ? await scanPorts(ip, ports, portTimeout) : [];
		const hostname = await reverseDns(ip);
		devices.push({ mac, ip, hostname, vendor: null, openPorts, services: [] });
	}
	return devices;
}

/** Discovery (and optionally ports) via nmap, parsed from its XML output. */
async function scanWithNmap(activeSubnets, { portScan, ports, serviceDetection, extra }) {
	try {
		await execFileAsync('nmap', ['--version'], { timeout: 5000 });
	} catch {
		throw new Error('nmap er ikke installeret. Kør: apt install nmap');
	}

	const args = ['-oX', '-', '-T4'];
	if (portScan) {
		args.push('-sT', '-p', ports.join(','), '--open');
		if (serviceDetection) args.push('-sV');
	} else {
		args.push('-sn');
	}
	args.push(...extra, ...activeSubnets);

	console.error(`[agent] nmap ${args.join(' ')}`);
	const { stdout } = await execFileAsync('nmap', args, {
		timeout: 10 * 60 * 1000,
		maxBuffer: 32 * 1024 * 1024,
	});

	return parseNmapXml(stdout).map((h) => ({
		mac: h.mac,
		ip: h.ip,
		hostname: h.hostname,
		vendor: h.vendor,
		openPorts: h.openPorts,
		services: h.services ?? [],
	}));
}

/** Deep vulnerability scan (weekly). Requires nmap. */
async function scanVulns(activeSubnets, { extra }) {
	try {
		await execFileAsync('nmap', ['--version'], { timeout: 5000 });
	} catch {
		throw new Error('nmap er ikke installeret. Kør: apt install nmap');
	}
	const args = ['-oX', '-', '-T4', '-sV', '--script', 'vuln', ...extra, ...activeSubnets];
	console.error(`[agent] nmap ${args.join(' ')}`);
	const { stdout } = await execFileAsync('nmap', args, {
		timeout: 30 * 60 * 1000,
		maxBuffer: 32 * 1024 * 1024,
	});
	return { devices: parseNmapXml(stdout), findings: parseNmapScripts(stdout) };
}

/* -------------------------------- main ------------------------------- */

async function main() {
	const url = (process.env.SENTINEL_URL ?? '').replace(/\/$/, '');
	const token = process.env.SENTINEL_TOKEN ?? '';
	if (!DRY_RUN && (!url || !token)) {
		console.error('SENTINEL_URL og SENTINEL_TOKEN skal være sat (eller brug --dry-run).');
		process.exit(1);
	}

	const subnets = (process.env.SCAN_SUBNETS ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	const activeSubnets = subnets.length > 0 ? subnets : detectSubnets();
	const portScan = process.env.ENABLE_PORT_SCAN === 'true';
	const ports = (process.env.PORTS ?? '')
		.split(',')
		.map((p) => Number(p.trim()))
		.filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
	const portList = ports.length > 0 ? ports : DEFAULT_PORTS;
	const pingTimeout = Number(process.env.PING_TIMEOUT_MS ?? 800);
	const portTimeout = Number(process.env.PORT_TIMEOUT_MS ?? 500);
	const scanner = (process.env.SCANNER ?? 'simple').toLowerCase();
	const serviceDetection = process.env.SERVICE_DETECTION === 'true';
	const nmapExtra = (process.env.NMAP_EXTRA ?? '').split(/\s+/).filter(Boolean);

	if (scanner !== 'simple' && scanner !== 'nmap') {
		console.error(`Ukendt SCANNER "${scanner}". Brug "simple" eller "nmap".`);
		process.exit(1);
	}

	console.error(
		`[agent] subnets: ${activeSubnets.join(', ')} | scanner: ${scanner} | port scan: ${portScan}`,
	);

	// Weekly/deep vulnerability scan (nmap --script vuln). Separate mode so
	// it does not run on every regular interval.
	const vulnMode =
		process.argv.includes('--vuln') || (process.env.MODE ?? '').toLowerCase() === 'vuln';
	if (vulnMode) {
		const { devices: vulnDevices, findings } = await scanVulns(activeSubnets, { extra: nmapExtra });
		console.error(`[agent] found ${vulnDevices.length} devices, ${findings.length} findings`);
		if (DRY_RUN) {
			console.log(JSON.stringify({ devices: vulnDevices, findings }, null, 2));
			return;
		}
		const res = await fetch(`${url}/api/ingest`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
			body: JSON.stringify({ devices: vulnDevices, findings }),
		});
		const text = await res.text();
		if (!res.ok) {
			console.error(`[agent] upload failed (${res.status}): ${text}`);
			process.exit(1);
		}
		console.error(`[agent] upload ok: ${text}`);
		return;
	}

	let devices;
	if (scanner === 'nmap') {
		devices = await scanWithNmap(activeSubnets, { portScan, ports: portList, serviceDetection, extra: nmapExtra });
	} else {
		devices = await scanSimple(activeSubnets, { portScan, ports: portList, pingTimeout, portTimeout });
	}

	console.error(`[agent] found ${devices.length} devices`);

	// Merge DHCP leases so sleeping wireless clients are included too.
	const leases = await readDhcpLeases(process.env.DHCP_LEASES ?? '');
	if (leases.size > 0) {
		const byMac = new Map(devices.map((d) => [d.mac, d]));
		for (const lease of leases.values()) {
			const existing = byMac.get(lease.mac);
			if (existing) {
				if (!existing.hostname && lease.hostname) existing.hostname = lease.hostname;
				if (!existing.ip && lease.ip) existing.ip = lease.ip;
			} else {
				devices.push({
					mac: lease.mac,
					ip: lease.ip,
					hostname: lease.hostname,
					vendor: null,
					openPorts: [],
					services: [],
				});
			}
		}
		console.error(`[agent] merged ${leases.size} DHCP leases`);
	}

	if (DRY_RUN) {
		console.log(JSON.stringify({ devices }, null, 2));
		return;
	}

	const res = await fetch(`${url}/api/ingest`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
		body: JSON.stringify({ devices }),
	});
	const text = await res.text();
	if (!res.ok) {
		console.error(`[agent] upload failed (${res.status}): ${text}`);
		process.exit(1);
	}
	console.error(`[agent] upload ok: ${text}`);
}

main().catch((err) => {
	console.error('[agent] fatal:', err);
	process.exit(1);
});
