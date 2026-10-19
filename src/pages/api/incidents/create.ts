import type { APIRoute } from 'astro';
import { createIncident } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const title = String(form.get('title') ?? '').trim();
	if (!title) return redirect('/incidents?error=missing');

	await createIncident({
		title,
		description: String(form.get('description') ?? '').trim(),
		severity: String(form.get('severity') ?? 'medium'),
		source: String(form.get('source') ?? '').trim(),
		tags: String(form.get('tags') ?? '')
			.split(',')
			.map((t) => t.trim())
			.filter(Boolean),
	});

	return redirect('/incidents');
};
