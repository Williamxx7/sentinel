import type { APIRoute } from 'astro';
import { setVulnerabilityStatus } from '../../../server/repo';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const status = String(form.get('status') ?? 'open');
	if (id) await setVulnerabilityStatus(id, status);
	return redirect('/vulnerabilities');
};
