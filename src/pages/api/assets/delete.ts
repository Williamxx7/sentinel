import type { APIRoute } from 'astro';
import { deleteAsset } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	if (id) await deleteAsset(id);
	return redirect('/assets');
};
