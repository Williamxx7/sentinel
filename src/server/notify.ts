// Notifications for incidents: webhook and/or e-mail.
//
// Privacy: by default ("minimal") notifications contain only a short,
// sanitised summary plus a link to the dashboard. IP/MAC addresses and
// port details stay behind the login. Set notify_detail to "full" in
// Settings if you explicitly want those details in the notification.
//
// The webhook URL, recipient and detail level live in D1 (Settings page).
// Notifications must never break incident creation, so failures are logged
// and swallowed.

import { sendEmail } from './email';
import { consume } from './ratelimit';
import { getSetting } from './settings';

const TIMEOUT_MS = 5000;
const SEVERITY_RANK: Record<string, number> = {
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};

export interface NotifyIncident {
	title: string;
	description: string;
	severity: string;
	source: string;
	createdAt: string;
	tags?: string[];
}

/** A short label that does not contain IP/MAC/port details. */
function safeTitle(incident: NotifyIncident): string {
	const tags = incident.tags ?? [];
	if (tags.includes('ny-enhed')) return 'Ny enhed på netværket';
	if (tags.includes('port')) return 'Nye åbne porte på en enhed';
	if (tags.includes('mac')) return 'MAC-adresse ændret';
	if (tags.includes('tjeneste')) return 'Tjeneste ændret';
	if (tags.includes('forsvundet')) return 'Enhed forsvundet';
	if (tags.includes('uptime')) return incident.title; // service name only
	return incident.title;
}

function buildMessage(
	incident: NotifyIncident,
	detail: string,
	siteUrl: string,
): { subject: string; text: string } {
	const isFull = detail === 'full';
	const title = isFull ? incident.title : safeTitle(incident);
	const lines = [`[${incident.severity.toUpperCase()}] ${title}`];
	if (isFull && incident.description) lines.push(incident.description);
	lines.push(`Kilde: ${incident.source} · ${incident.createdAt}`);
	if (siteUrl) lines.push(``, `Åbn Sentinel: ${siteUrl}/incidents`);
	return { subject: `[Sentinel] ${title}`, text: lines.join('\n') };
}

async function postWebhook(
	url: string,
	payload: Record<string, unknown>,
): Promise<void> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
	try {
		await fetch(url, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(payload),
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timer);
	}
}

export async function notifyIncident(incident: NotifyIncident): Promise<void> {
	try {
		const [url, minSeverity, emailTo, detail, siteUrl] = await Promise.all([
			getSetting('notify_webhook_url'),
			getSetting('notify_min_severity'),
			getSetting('notify_email_to'),
			getSetting('notify_detail'),
			getSetting('site_url'),
		]);
		if (!url && !emailTo) return;

		const threshold = SEVERITY_RANK[minSeverity ?? 'high'] ?? SEVERITY_RANK.high!;
		const rank = SEVERITY_RANK[incident.severity] ?? 0;
		if (rank < threshold) return;

		// Global notification budget: 30 per hour. Incidents still get
		// logged; only the outbound notifications are dropped.
		if (!(await consume('notify:global', 3_600_000, 30))) return;

		const isFull = detail === 'full';
		const { subject, text } = buildMessage(incident, detail ?? 'minimal', siteUrl ?? '');

		const jobs: Promise<void>[] = [];
		if (url) {
			jobs.push(
				postWebhook(url, {
					text,
					content: text,
					title: isFull ? incident.title : safeTitle(incident),
					severity: incident.severity,
					source: incident.source,
					createdAt: incident.createdAt,
					// Only include detailed fields when explicitly requested.
					...(isFull ? { description: incident.description } : {}),
				}),
			);
		}
		if (emailTo) jobs.push(sendEmail(subject, text, emailTo));
		await Promise.allSettled(jobs);
	} catch {
		// Never let a notification failure affect the request.
		console.error('[notify] notification failed');
	}
}

/**
 * Send a test through every configured channel and report which ones
 * failed, so the Settings page can give useful feedback.
 */
export async function sendTestNotification(): Promise<{
	configured: boolean;
	emailError: string | null;
	webhookOk: boolean;
	limited: boolean;
}> {
	const [url, emailTo] = await Promise.all([
		getSetting('notify_webhook_url'),
		getSetting('notify_email_to'),
	]);
	const configured = Boolean(url || emailTo);
	if (!configured) return { configured, emailError: null, webhookOk: true, limited: false };

	// Prevent the test button from being used to send mail in a loop.
	if (!(await consume('notify:test', 3_600_000, 5))) {
		return { configured, emailError: null, webhookOk: true, limited: true };
	}

	const subject = 'Test-notifikation fra Sentinel';
	const text = 'Hvis du ser denne besked, virker notifikationerne.';

	let emailError: string | null = null;
	let webhookOk = true;

	if (url) {
		try {
			await postWebhook(url, { text, content: text, title: subject, severity: 'critical' });
		} catch {
			webhookOk = false;
		}
	}
	if (emailTo) {
		try {
			await sendEmail(subject, text, emailTo);
		} catch (err) {
			emailError = err instanceof Error ? err.message : 'unknown';
			console.error('[email] test failed');
		}
	}

	return { configured, emailError, webhookOk, limited: false };
}
