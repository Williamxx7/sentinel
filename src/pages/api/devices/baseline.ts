import type { APIRoute } from 'astro';
import { acceptBaseline, clearBaseline } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const mode = String(form.get('mode') ?? 'accept');
	if (id) {
		if (mode === 'clear') await clearBaseline(id);
		else await acceptBaseline(id);
	}
	return redirect('/devices');
};
