import type { APIRoute } from 'astro';
import { updateMonitor, validateTarget } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const name = String(form.get('name') ?? '').trim();
	const url = String(form.get('url') ?? '').trim();
	if (!id || !name || !url) return redirect('/uptime?error=missing');

	const target = validateTarget(url);
	if (!target.ok) return redirect(`/uptime?error=${target.reason}`);

	await updateMonitor(id, {
		name,
		url,
		method: 'GET',
		expectedStatus: Number(form.get('expectedStatus') ?? 200) || 200,
		intervalSec: Math.max(60, Number(form.get('intervalSec') ?? 300) || 300),
	});

	return redirect('/uptime');
};
