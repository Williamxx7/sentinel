import type { APIRoute } from 'astro';
import { updateAsset } from '../../../server/repo';

export const prerender = false;

function parseTags(raw: FormDataEntryValue | null): string[] {
	return String(raw ?? '')
		.split(',')
		.map((t) => t.trim())
		.filter(Boolean);
}

export const POST: APIRoute = async ({ request, redirect }) => {
	const form = await request.formData();
	const id = String(form.get('id') ?? '');
	const name = String(form.get('name') ?? '').trim();
	const identifier = String(form.get('identifier') ?? '').trim();
	if (!id || !name || !identifier) return redirect('/assets?error=missing');

	const expiresRaw = String(form.get('expiresAt') ?? '').trim();
	let expiresAt: string | null = null;
	if (expiresRaw) {
		const parsed = new Date(expiresRaw);
		if (Number.isNaN(parsed.getTime())) return redirect('/assets?error=date');
		expiresAt = parsed.toISOString();
	}

	await updateAsset(id, {
		name,
		type: String(form.get('type') ?? 'other'),
		identifier,
		notes: String(form.get('notes') ?? '').trim(),
		expiresAt,
		tags: parseTags(form.get('tags')),
	});

	return redirect('/assets');
};
