import type { APIRoute } from 'astro';
import {
	createSession,
	findUser,
	SESSION_COOKIE,
	verifyAgainstDummy,
	verifyPassword,
} from '../../../server/auth';
import { clearFailures, consume, isLockedOut, recordFailure } from '../../../server/ratelimit';

export const prerender = false;

const WINDOW_MS = 15 * 60 * 1000;

export const POST: APIRoute = async ({ request, cookies, clientAddress, redirect }) => {
	// Reject oversized bodies before parsing (unauthenticated endpoint).
	const length = Number(request.headers.get('content-length') ?? 0);
	if (length > 4096) return new Response('Payload too large', { status: 413 });

	const form = await request.formData();
	const username = String(form.get('username') ?? '').trim().slice(0, 64);
	const password = String(form.get('password') ?? '').slice(0, 1024);

	if (!username || !password) return redirect('/?error=missing');

	const userKey = `${clientAddress}:${username.toLowerCase()}`;

	// Per-account-per-IP limit (8) plus a broader per-IP limit (30), so a
	// distributed or username-spraying attack is also throttled.
	if (await isLockedOut(userKey)) return redirect('/?error=locked');
	if (!(await consume(`ip:${clientAddress}`, WINDOW_MS, 30))) {
		return redirect('/?error=locked');
	}

	const user = await findUser(username);
	// Always run a verify so response time does not reveal whether the
	// username exists.
	const ok = user
		? await verifyPassword(password, user.passwordHash)
		: (await verifyAgainstDummy(password), false);

	if (!user || !ok) {
		await recordFailure(userKey);
		return redirect('/?error=credentials');
	}

	await clearFailures(userKey);
	await clearFailures(`ip:${clientAddress}`);
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
