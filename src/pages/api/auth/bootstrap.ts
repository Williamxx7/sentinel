import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { createFirstUser, createSession, SESSION_COOKIE } from '../../../server/auth';
import { consume } from '../../../server/ratelimit';

export const prerender = false;

export const POST: APIRoute = async ({ request, cookies, clientAddress, redirect }) => {
	const length = Number(request.headers.get('content-length') ?? 0);
	if (length > 4096) return new Response('Payload too large', { status: 413 });

	if (!(await consume(`bootstrap:${clientAddress}`, 15 * 60 * 1000, 10))) {
		return redirect('/?error=locked');
	}

	// Account creation is opt-in. With ALLOW_BOOTSTRAP=false the site is
	// locked to existing users and no new login can ever be created.
	if (env.ALLOW_BOOTSTRAP !== 'true') return redirect('/?error=closed');

	const form = await request.formData();
	const username = String(form.get('username') ?? '').trim().slice(0, 64);
	const password = String(form.get('password') ?? '').slice(0, 1024);

	if (!username || !password) return redirect('/?error=missing');
	if (password.length < 10) return redirect('/?error=weak');

	// Atomic check-and-create: if two requests race, only one wins.
	const user = await createFirstUser(username, password);
	if (!user) return redirect('/?error=exists');

	const { session, token } = await createSession(user.id);
	cookies.set(SESSION_COOKIE, token, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: import.meta.env.PROD,
		expires: new Date(session.expiresAt),
	});

	return redirect('/dashboard');
};
