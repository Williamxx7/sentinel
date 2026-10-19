import { defineMiddleware } from 'astro:middleware';
import { SESSION_COOKIE, userForSession } from './server/auth';

// Routes that are reachable without a session. /api/ingest authenticates
// itself with an agent bearer token instead of the session cookie.
const PUBLIC_PATHS = new Set([
	'/',
	'/api/auth/login',
	'/api/auth/bootstrap',
	'/api/ingest',
]);

const SECURITY_HEADERS: Record<string, string> = {
	'X-Frame-Options': 'DENY',
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'no-referrer',
	'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

// The CSP is only applied in production: the Vite dev server relies on
// inline scripts and eval, which a strict policy would block.
//
// Note: script-src still needs 'unsafe-inline' because Astro inlines small
// page scripts at build time. Adopting nonces/hashes is a larger change.
const CSP = [
	"default-src 'self'",
	"script-src 'self' 'unsafe-inline'",
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
	'font-src https://fonts.gstatic.com',
	"img-src 'self' data:",
	"connect-src 'self'",
	"frame-ancestors 'none'",
	"frame-src 'none'",
	"object-src 'none'",
	"worker-src 'self'",
	"base-uri 'none'",
	"form-action 'self'",
	'upgrade-insecure-requests',
].join('; ');

function applySecurityHeaders(response: Response): Response {
	const headers = new Headers(response.headers);
	for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
	if (import.meta.env.PROD) headers.set('Content-Security-Policy', CSP);

	// Don't let authenticated pages or API responses sit in browser caches.
	const type = headers.get('content-type') ?? '';
	if (type.includes('text/html') || type.includes('application/json')) {
		headers.set('Cache-Control', 'no-store');
	}

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

/**
 * CSRF defence in depth. SameSite=Lax on the session cookie is the real
 * guard; this only rejects clearly foreign origins. Non-browser clients
 * (no Origin) and opaque origins ("null") are allowed through.
 */
function sameOrigin(request: Request, requestUrl: URL): boolean {
	const origin = request.headers.get('origin');
	if (!origin || origin === 'null') return true;

	let parsed: URL;
	try {
		parsed = new URL(origin);
	} catch {
		return true;
	}

	const host = request.headers.get('host') ?? requestUrl.host;
	if (parsed.host === host) return true;

	// In local dev, localhost / 127.0.0.1 / ::1 are the same machine.
	const loopback = new Set(['localhost', '127.0.0.1', '::1']);
	try {
		if (loopback.has(parsed.hostname) && loopback.has(new URL(`http://${host}`).hostname)) {
			return true;
		}
	} catch {
		/* fall through */
	}
	return false;
}

export const onRequest = defineMiddleware(async (context, next) => {
	const sessionId = context.cookies.get(SESSION_COOKIE)?.value;
	const user = await userForSession(sessionId);
	context.locals.user = user;

	const path = context.url.pathname;
	const isPublic = PUBLIC_PATHS.has(path);

	if (
		context.request.method === 'POST' &&
		!sameOrigin(context.request, context.url)
	) {
		return applySecurityHeaders(new Response('Cross-origin request blocked', { status: 403 }));
	}

	if (!user && !isPublic) {
		if (path.startsWith('/api/')) {
			return applySecurityHeaders(
				new Response(JSON.stringify({ error: 'unauthorized' }), {
					status: 401,
					headers: { 'content-type': 'application/json' },
				}),
			);
		}
		return applySecurityHeaders(context.redirect('/'));
	}

	if (user && path === '/') {
		return applySecurityHeaders(context.redirect('/dashboard'));
	}

	return applySecurityHeaders(await next());
});
