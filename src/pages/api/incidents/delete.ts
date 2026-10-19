import type { APIRoute } from 'astro';
import { deleteIncident } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	if (id) await deleteIncident(id);
	return redirect('/incidents');
};
