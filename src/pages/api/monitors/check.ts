import type { APIRoute } from 'astro';
import { runChecks } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	// The body is optional: with no id we check every monitor.
	const form = await request.formData().catch(() => null);
	const id = String(form?.get('id') ?? '') || undefined;
	await runChecks(id);
	return redirect('/uptime');
};
