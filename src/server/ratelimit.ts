// Durable rate limiting and counters, stored in D1.
//
// Works across Worker isolates and cold starts, unlike the earlier
// in-memory version. Used for login throttling and notification budgets.

import { getDB, nowISO } from './store';

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 8;

interface BucketRow {
	count: number;
	reset_at: string;
}

async function getBucket(key: string): Promise<BucketRow | null> {
	return getDB()
		.prepare('SELECT count, reset_at FROM rate_limits WHERE key = ?1')
		.bind(key)
		.first<BucketRow>();
}

async function bump(key: string, windowMs: number): Promise<void> {
	const now = Date.now();
	const nowStr = new Date(now).toISOString();
	const resetAt = new Date(now + windowMs).toISOString();
	await getDB()
		.prepare(
			`INSERT INTO rate_limits (key, count, reset_at)
       VALUES (?1, 1, ?2)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN rate_limits.reset_at <= ?3 THEN 1 ELSE rate_limits.count + 1 END,
         reset_at = CASE WHEN rate_limits.reset_at <= ?3 THEN ?2 ELSE rate_limits.reset_at END`,
		)
		.bind(key, resetAt, nowStr)
		.run();
}

export async function isLockedOut(key: string): Promise<boolean> {
	const row = await getBucket(key);
	if (!row || row.reset_at <= nowISO()) return false;
	return row.count >= MAX_ATTEMPTS;
}

/** Record a failed attempt (resetting the window if it has expired). */
export async function recordFailure(key: string): Promise<void> {
	await bump(key, WINDOW_MS);
}

/** Clear the counter after a successful login. */
export async function clearFailures(key: string): Promise<void> {
	await getDB().prepare('DELETE FROM rate_limits WHERE key = ?1').bind(key).run();
}

/**
 * Increment a counter and return true while it is within the budget.
 * `max` is inclusive: max=30 allows the first 30 in the window.
 */
export async function consume(key: string, windowMs: number, max: number): Promise<boolean> {
	await bump(key, windowMs);
	const row = await getBucket(key);
	return (row?.count ?? 0) <= max;
}

/** Remove counters whose window expired more than a day ago. */
export async function cleanupRateLimits(): Promise<void> {
	const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
	await getDB().prepare('DELETE FROM rate_limits WHERE reset_at < ?1').bind(cutoff).run();
}
