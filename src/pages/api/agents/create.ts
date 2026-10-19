import type { APIRoute } from 'astro';
import { createAgent } from '../../../server/repo';

export const prerender = false;

// Returns the agent token exactly once. Only its hash is stored.
export const POST: APIRoute = async ({ request }) => {
	const body = (await request.json().catch(() => null)) as { name?: string } | null;
	const name = (body?.name ?? '').trim().slice(0, 60) || 'agent';
	const { agent, token } = await createAgent(name);
	return Response.json({ ok: true, id: agent.id, name: agent.name, token });
};
