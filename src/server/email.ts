// E-mail notifications via Cloudflare's Email Service (send_email binding).
//
// No third-party account or API key: sending happens from your own domain
// through the Worker binding "EMAIL" declared in wrangler.jsonc, which is
// restricted to a fixed recipient and sender. Recipient and optional sender
// are stored in D1 (Settings page).

import { env } from 'cloudflare:workers';
import { getSetting } from './settings';

const DEFAULT_SENDER = 'sentinel@example.com';
const MAX_RECIPIENTS = 5;

/** Conservative validation; also rejects CR/LF (header injection). */
export function isValidEmail(value: string): boolean {
	const v = value.trim();
	if (v.length === 0 || v.length > 254) return false;
	if (/[\r\n]/.test(v)) return false;
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return false;
	return true;
}

function sanitizeHeader(value: string): string {
	return value.replace(/[\r\n]+/g, ' ').trim();
}

export async function sendEmail(
	subject: string,
	text: string,
	to?: string,
	from?: string,
): Promise<void> {
	const recipient = (to ?? (await getSetting('notify_email_to')) ?? '').trim();
	if (!recipient) return;

	const sender = sanitizeHeader(
		(from ?? (await getSetting('notify_email_from')) ?? '').trim() || DEFAULT_SENDER,
	);

	const addresses = recipient
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean)
		.filter(isValidEmail)
		.slice(0, MAX_RECIPIENTS);
	if (addresses.length === 0) return;

	await env.EMAIL.send({
		to: addresses,
		from: sender,
		subject: sanitizeHeader(subject),
		text,
	});
}
