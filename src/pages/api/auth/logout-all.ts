import type { APIRoute } from 'astro';
import { destroyAllSessions, SESSION_COOKIE } from '../../../server/auth';

export const prerender = false;

export const POST: APIRoute = async ({ locals, cookies, redirect }) => {
	const user = locals.user;
	if (user) await destroyAllSessions(user.id);
	cookies.delete(SESSION_COOKIE, { path: '/' });
	return redirect('/');
};
