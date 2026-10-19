import type { APIRoute } from 'astro';
import { upsertNote } from '../../../server/repo';

export const prerender = false;

// The client encrypts the note body before sending it here.
// We only ever store ciphertext, the iv and the salt.
export const POST: APIRoute = async ({ request }) => {
	const body = (await request.json().catch(() => null)) as {
		id?: string;
		title?: string;
		ciphertext?: string;
		iv?: string;
		salt?: string;
	} | null;

	if (!body?.title || !body.ciphertext || !body.iv || !body.salt) {
		return new Response(JSON.stringify({ error: 'missing' }), { status: 400 });
	}

	// Bound the payload so a single note cannot bloat the local store.
	const b64 = /^[A-Za-z0-9+/=]+$/;
	if (body.title.length > 200) {
		return new Response(JSON.stringify({ error: 'title' }), { status: 400 });
	}
	if (body.ciphertext.length > 512 * 1024) {
		return new Response(JSON.stringify({ error: 'size' }), { status: 413 });
	}
	if (!b64.test(body.iv) || body.iv.length > 64 || !b64.test(body.salt) || body.salt.length > 64) {
		return new Response(JSON.stringify({ error: 'iv' }), { status: 400 });
	}
	if (body.id && !/^[0-9a-f-]{36}$/.test(body.id)) {
		return new Response(JSON.stringify({ error: 'id' }), { status: 400 });
	}

	const note = await upsertNote({
		id: body.id,
		title: body.title,
		ciphertext: body.ciphertext,
		iv: body.iv,
		salt: body.salt,
	});

	return new Response(JSON.stringify({ ok: true, id: note.id }), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
};
