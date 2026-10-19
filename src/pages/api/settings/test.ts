import type { APIRoute } from 'astro';
import { sendTestNotification } from '../../../server/notify';

export const prerender = false;

export const POST: APIRoute = async ({ redirect }) => {
	const result = await sendTestNotification();
	if (!result.configured) return redirect('/settings?error=nourl');
	if (result.limited) return redirect('/settings?error=ratelimit');
	if (result.emailError) return redirect('/settings?error=sendfail');
	if (!result.webhookOk) return redirect('/settings?error=webhookfail');
	return redirect('/settings?tested=1');
};
