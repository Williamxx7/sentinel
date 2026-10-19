// Minimal parser for `nmap -oX -` XML output.
//
// We only need the fields Sentinel stores: address, MAC (+ vendor),
// hostname and open ports. nmap's XML is well-formed and predictable, so a
// small focused parser avoids pulling in an XML dependency.

function attr(tag, name) {
	const m = tag.match(new RegExp(`${name}="([^"]*)"`));
	return m ? m[1] : null;
}

function decodeEntities(value) {
	return value
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&amp;/g, '&')
		.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

function severityForScript(id) {
	const s = id.toLowerCase();
	if (/cve|vuln|ms17|shellshock|heartbleed|bluekeep/.test(s)) return 'high';
	if (/ssl|tls|weak|enum|brute|disclosure/.test(s)) return 'medium';
	return 'low';
}

/**
 * @param {string} xml
 * @returns {{ ip: string|null, mac: string, vendor: string|null, hostname: string|null, openPorts: number[] }[]}
 */
export function parseNmapXml(xml) {
	const hosts = [];
	const hostRe = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
	let match;

	while ((match = hostRe.exec(xml)) !== null) {
		const body = match[1];

		const status = body.match(/<status[^>]*state="([^"]+)"/);
		if (status && status[1] !== 'up') continue;

		let ip = null;
		let mac = null;
		let vendor = null;

		const addrRe = /<address\s+([^>]*?)\/?>/g;
		let addr;
		while ((addr = addrRe.exec(body)) !== null) {
			const tag = addr[1];
			const addrtype = attr(tag, 'addrtype');
			const value = attr(tag, 'addr');
			if (!value) continue;
			if (addrtype === 'ipv4' || addrtype === 'ipv6') {
				if (!ip) ip = value;
			} else if (addrtype === 'mac') {
				mac = value.toLowerCase();
				vendor = attr(tag, 'vendor');
			}
		}

		const hostname = body.match(/<hostname[^>]*name="([^"]+)"/);

		const services = [];
		const openPorts = [];
		const portRe = /<port\b[^>]*portid="(\d+)"[^>]*>([\s\S]*?)<\/port>/g;
		let port;
		while ((port = portRe.exec(body)) !== null) {
			const portBody = port[2];
			const state = portBody.match(/<state[^>]*state="([^"]+)"/);
			if (!state || state[1] !== 'open') continue;
			const portId = Number(port[1]);
			openPorts.push(portId);
			const svc = portBody.match(/<service\b([^>]*?)\/?>/);
			if (svc) {
				services.push({
					port: portId,
					name: attr(svc[1], 'name'),
					product: attr(svc[1], 'product'),
					version: attr(svc[1], 'version'),
				});
			}
		}

		// Identity for Sentinel: prefer the MAC, fall back to the IP.
		const identity = mac ?? (ip ? `ip:${ip}` : null);
		if (!identity) continue;

		hosts.push({
			ip,
			mac: identity,
			vendor,
			hostname: hostname ? hostname[1] : null,
			openPorts: openPorts.sort((a, b) => a - b),
			services: services.sort((a, b) => a.port - b.port),
		});
	}

	return hosts;
}

/**
 * Parse nmap script output (from `--script vuln`) into findings.
 * @param {string} xml
 * @returns {{ ip: string|null, mac: string, script: string, title: string, detail: string, severity: string }[]}
 */
export function parseNmapScripts(xml) {
	const findings = [];
	const hostRe = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
	let match;

	while ((match = hostRe.exec(xml)) !== null) {
		const body = match[1];

		const status = body.match(/<status[^>]*state="([^"]+)"/);
		if (status && status[1] !== 'up') continue;

		let ip = null;
		let mac = null;
		const addrRe = /<address\s+([^>]*?)\/?>/g;
		let addr;
		while ((addr = addrRe.exec(body)) !== null) {
			const tag = addr[1];
			const addrtype = attr(tag, 'addrtype');
			const value = attr(tag, 'addr');
			if (!value) continue;
			if (addrtype === 'ipv4' || addrtype === 'ipv6') {
				if (!ip) ip = value;
			} else if (addrtype === 'mac') {
				mac = value.toLowerCase();
			}
		}

		const identity = mac ?? (ip ? `ip:${ip}` : null);
		if (!identity) continue;

		const scriptRe = /<script\b([^>]*)>/g;
		let script;
		while ((script = scriptRe.exec(body)) !== null) {
			const tag = script[1];
			const id = attr(tag, 'id');
			if (!id) continue;
			const output = attr(tag, 'output');
			const detail = output ? decodeEntities(output).trim() : '';
			findings.push({
				ip,
				mac: identity,
				script: id,
				title: id,
				detail: detail.slice(0, 1500),
				severity: severityForScript(id),
			});
		}
	}

	return findings;
}
