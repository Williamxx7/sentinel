import type { APIRoute } from 'astro';
import { destroySession, SESSION_COOKIE } from '../../../server/auth';

export const prerender = false;

export const POST: APIRoute = async ({ cookies, redirect }) => {
	const sessionId = cookies.get(SESSION_COOKIE)?.value;
	if (sessionId) await destroySession(sessionId);
	cookies.delete(SESSION_COOKIE, { path: '/' });
	return redirect('/');
};
