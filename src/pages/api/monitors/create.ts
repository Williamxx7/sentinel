import type { APIRoute } from 'astro';
import { createMonitor, validateTarget } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const name = String(form.get('name') ?? '').trim();
	const url = String(form.get('url') ?? '').trim();
	if (!name || !url) return redirect('/uptime?error=missing');

	const target = await validateTarget(url);
	if (!target.ok) return redirect(`/uptime?error=${target.reason}`);

	await createMonitor({
		name,
		url,
		method: 'GET',
		expectedStatus: Number(form.get('expectedStatus') ?? 200) || 200,
		intervalSec: Math.max(60, Number(form.get('intervalSec') ?? 300) || 300),
	});

	return redirect('/uptime');
};
