import type { APIRoute } from 'astro';
import { updateIncident } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const title = String(form.get('title') ?? '').trim();
	if (!id || !title) return redirect('/incidents?error=missing');

	await updateIncident(id, {
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
