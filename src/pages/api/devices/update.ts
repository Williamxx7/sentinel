import type { APIRoute } from 'astro';
import { setDeviceStatus } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const status = String(form.get('status') ?? 'unknown');
	if (id) await setDeviceStatus(id, status);
	return redirect('/devices');
};
