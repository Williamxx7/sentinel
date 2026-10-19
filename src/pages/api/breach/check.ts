import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';

export const prerender = false;

const TIMEOUT_MS = 8_000;

async function fetchWithTimeout(url: string, headers: Record<string, string> = {}) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
	try {
		return await fetch(url, { headers, signal: controller.signal });
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Breach lookup.
 *
 * - mode "password": the browser hashes the password (SHA-1) and sends
 *   only the first 5 hex chars (prefix) plus the remaining 35 (suffix).
 *   We ask the HIBP Pwned Passwords range API for that prefix and check
 *   whether our suffix is in the returned set. The password itself and
 *   even its full hash never reach this server.
 * - mode "email": HIBP breached-account API, which requires an API key
 *   (HIBP_API_KEY). Without one we report that it is not configured.
 */
export const POST: APIRoute = async ({ request }) => {
	const body = (await request.json().catch(() => null)) as {
		mode?: string;
		value?: string;
		prefix?: string;
		suffix?: string;
	} | null;

	if (body?.mode === 'password') {
		const prefix = (body.prefix ?? '').toUpperCase();
		const suffix = (body.suffix ?? '').toUpperCase();
		if (!/^[0-9A-F]{5}$/.test(prefix) || !/^[0-9A-F]{35}$/.test(suffix)) {
			return Response.json({ ok: false, error: 'input' }, { status: 400 });
		}
		try {
			const res = await fetchWithTimeout(
				`https://api.pwnedpasswords.com/range/${prefix}`,
				{ 'user-agent': 'Sentinel-BreachCheck/1.0' },
			);
			if (!res.ok) throw new Error('upstream');
			const text = await res.text();
			const match = text
				.split('\n')
				.map((line) => line.split(':'))
				.find(([s]) => s.trim() === suffix);
			const count = match ? Number(match[1]) : 0;
			return Response.json({ ok: true, pwned: count > 0, count });
		} catch {
			return Response.json({ ok: false, error: 'upstream' }, { status: 502 });
		}
	}

	if (body?.mode === 'email') {
		const value = body.value?.trim();
		if (!value) return Response.json({ ok: false, error: 'missing' }, { status: 400 });
		const key = env.HIBP_API_KEY;
		if (!key) {
			return Response.json({ ok: true, configured: false });
		}
		const encoded = encodeURIComponent(value);
		try {
			const res = await fetchWithTimeout(
				`https://haveibeenpwned.com/api/v3/breachedaccount/${encoded}?truncateResponse=false`,
				{ 'hibp-api-key': key, 'user-agent': 'Sentinel-BreachCheck/1.0' },
			);
			if (res.status === 404) return Response.json({ ok: true, configured: true, breaches: [] });
			if (!res.ok) throw new Error('upstream');
			const breaches = (await res.json()) as Array<{ Name: string; BreachDate: string }>;
			return Response.json({
				ok: true,
				configured: true,
				breaches: breaches.map((b) => ({ name: b.Name, date: b.BreachDate })),
			});
		} catch {
			return Response.json({ ok: false, error: 'upstream' }, { status: 502 });
		}
	}

	return Response.json({ ok: false, error: 'mode' }, { status: 400 });
};
