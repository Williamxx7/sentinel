// Cloudflare D1 access.
//
// Bindings are read from the Workers runtime. The binding is declared in
// wrangler.jsonc as "DB" and must be migrated before use:
//   npx wrangler d1 migrations apply DB --local    (development)
//   npx wrangler d1 migrations apply DB --remote   (production)

import { env } from 'cloudflare:workers';

export function getDB(): D1Database {
	const db = env.DB;
	if (!db) {
		throw new Error(
			'D1-bindingen "DB" mangler. Kør `npx wrangler d1 migrations apply DB --local`.',
		);
	}
	return db;
}

export function nowISO(): string {
	return new Date().toISOString();
}

export function newId(): string {
	return crypto.randomUUID();
}

/** Lowercase hex of a random byte string (for API tokens). */
export function randomToken(bytes = 32): string {
	return [...crypto.getRandomValues(new Uint8Array(bytes))]
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** JSON.parse that never throws on malformed column data. */
export function parseJSON<T>(value: string | null | undefined, fallback: T): T {
	if (!value) return fallback;
	try {
		return JSON.parse(value) as T;
	} catch {
		return fallback;
	}
}
