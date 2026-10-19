/// <reference types="astro/client" />
/// <reference path="../worker-configuration.d.ts" />

import type { SessionUser } from './server/types';

declare global {
	namespace App {
		interface Locals {
			user: SessionUser | null;
		}
	}

	// Secrets set out-of-band with `wrangler secret put` are not part of
	// the generated worker types, so we declare them here.
	interface Env {
		HIBP_API_KEY?: string;
	}
}

export {};
