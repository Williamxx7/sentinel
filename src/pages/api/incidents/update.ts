import type { APIRoute } from 'astro';
import { setIncidentStatus } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const status = String(form.get('status') ?? 'open');
	if (id) await setIncidentStatus(id, status);
	return redirect('/incidents');
};
