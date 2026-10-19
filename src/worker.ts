// Custom Cloudflare Worker entrypoint.
//
// We wrap the adapter's request handler and add a scheduled handler so
// uptime monitors are checked automatically by a Cron Trigger instead of
// only when someone opens the Uptime page.

import { handle } from '@astrojs/cloudflare/handler';
import { cleanupExpired, runChecks } from './server/repo';

export default {
	fetch(request, env, context) {
		return handle(request, env, context);
	},

	// Fired by the Cron Trigger defined in wrangler.jsonc.
	async scheduled(_controller, _env, context) {
		context.waitUntil(
			Promise.all([runChecks(), cleanupExpired()]).then(() => undefined),
		);
	},
} satisfies ExportedHandler<Env>;
