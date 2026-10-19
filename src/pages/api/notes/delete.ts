import type { APIRoute } from 'astro';
import { deleteNote } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	if (id) await deleteNote(id);
	return redirect('/notes');
};
