import type { APIRoute } from 'astro';
import { setSetting } from '../../../server/settings';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const hours = Number(form.get('device_missing_hours') ?? 48);
	const value = Number.isFinite(hours) && hours > 0 ? Math.min(8760, Math.round(hours)) : 48;
	await setSetting('device_missing_hours', String(value));
	return redirect('/settings?saved=1');
};
