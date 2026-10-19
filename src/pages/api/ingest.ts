import type { APIRoute } from 'astro';
import {
	agentByToken,
	ingestDevices,
	ingestFindings,
	touchAgent,
	type IngestDevice,
	type IngestFinding,
} from '../../server/repo';

export const prerender = false;

// Called by the local agent (not the browser). Authenticated with a bearer
// token that the agent got from the Settings page. This route is public in
// middleware and does its own token check.
export const POST: APIRoute = async ({ request }) => {
	const auth = request.headers.get('authorization') ?? '';
	const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
	const agent = await agentByToken(token);
	if (!agent) {
		return Response.json({ error: 'unauthorized' }, { status: 401 });
	}

	// Reject oversized bodies before parsing.
	const length = Number(request.headers.get('content-length') ?? 0);
	if (length > 2_000_000) {
		return Response.json({ error: 'too large' }, { status: 413 });
	}

	const body = (await request.json().catch(() => null)) as {
		devices?: IngestDevice[];
		findings?: IngestFinding[];
	} | null;
	if (!body || (!Array.isArray(body.devices) && !Array.isArray(body.findings))) {
		return Response.json({ error: 'bad request' }, { status: 400 });
	}

	const devices = Array.isArray(body.devices) ? body.devices : [];
	const findings = Array.isArray(body.findings) ? body.findings : [];
	if (devices.length > 200) {
		return Response.json({ error: 'too many devices' }, { status: 413 });
	}
	if (findings.length > 500) {
		return Response.json({ error: 'too many findings' }, { status: 413 });
	}

	try {
		const deviceResult = devices.length
			? await ingestDevices(agent.name, devices)
			: { devices: 0, newDevices: 0, alerts: 0 };
		const findingResult = findings.length
			? await ingestFindings(agent.name, findings)
			: { findings: 0, newFindings: 0, alerts: 0 };
		await touchAgent(agent.id);
		return Response.json({
			ok: true,
			agent: agent.name,
			devices: deviceResult.devices,
			newDevices: deviceResult.newDevices,
			findings: findingResult.findings,
			newFindings: findingResult.newFindings,
			alerts: deviceResult.alerts + findingResult.alerts,
		});
	} catch {
		// Never leak a stack trace to the agent; log a short marker instead.
		console.error('[ingest] failed');
		return Response.json({ error: 'ingest failed' }, { status: 500 });
	}
};
