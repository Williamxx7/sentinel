import type { APIRoute } from 'astro';
import { isValidEmail } from '../../../server/email';
import { deleteSetting, setSetting } from '../../../server/settings';

export const prerender = false;

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export const POST: APIRoute = async ({ request, redirect, url }) => {
	const form = await request.formData();
	const url_ = String(form.get('webhook_url') ?? '').trim();
	const min = String(form.get('min_severity') ?? 'high');
	const emailTo = String(form.get('notify_email_to') ?? '').trim();
	const emailFrom = String(form.get('notify_email_from') ?? '').trim();
	const detail = String(form.get('notify_detail') ?? 'minimal');

	// Webhook
	if (!url_) {
		await deleteSetting('notify_webhook_url');
	} else {
		try {
			const parsed = new URL(url_);
			const isLocal = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
			if (!(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLocal))) {
				throw new Error('insecure');
			}
		} catch {
			return redirect('/settings?error=url');
		}
		await setSetting('notify_webhook_url', url_);
	}

	// E-mail
	if (emailTo) {
		const addresses = emailTo
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		if (addresses.length === 0 || addresses.length > 5 || addresses.some((a) => !isValidEmail(a))) {
			return redirect('/settings?error=email');
		}
		await setSetting('notify_email_to', addresses.join(', '));
	} else {
		await deleteSetting('notify_email_to');
	}
	if (emailFrom) {
		if (!isValidEmail(emailFrom)) return redirect('/settings?error=email');
		await setSetting('notify_email_from', emailFrom);
	} else {
		await deleteSetting('notify_email_from');
	}

	await setSetting('notify_min_severity', SEVERITIES.includes(min) ? min : 'high');
	await setSetting('notify_detail', detail === 'full' ? 'full' : 'minimal');
	await setSetting('site_url', url.origin);
	return redirect('/settings?saved=1');
};
