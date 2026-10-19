// Password hashing and session handling.
//
// Passwords use PBKDF2-HMAC-SHA256 through the Web Crypto API. Cloudflare
// Workers caps PBKDF2 at 100,000 iterations, so we use exactly that ceiling;
// the count is stored in the hash so it can be raised on another platform.
// The version string is also used to detect legacy hashes.
//
// Session tokens are random 256-bit values. Only their SHA-256 hash is stored
// in D1, so a database dump does not hand out live sessions. Sessions have a
// 7-day absolute lifetime and a 12-hour idle timeout.

import { getDB, newId, nowISO, randomToken, sha256Hex } from './store';
import type { Session, SessionUser, User } from './types';

export const SESSION_COOKIE = 'sentinel_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // absolute: 7 days
const IDLE_TTL_MS = 1000 * 60 * 60 * 12; // idle: 12 hours
const TOUCH_INTERVAL_MS = 1000 * 60 * 5; // update last_used at most every 5 min

const PBKDF2_ITERATIONS = 100_000;
const KEY_BYTES = 32;

const encoder = new TextEncoder();

function toB64(bytes: Uint8Array): string {
	let binary = '';
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary);
}

function fromB64(value: string): Uint8Array {
	return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
	const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
		'deriveBits',
	]);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
		base,
		KEY_BYTES * 8,
	);
	return new Uint8Array(bits);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

export async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const derived = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
	return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${toB64(salt)}$${toB64(derived)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
	const parts = stored.split('$');
	if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha256') return false;
	const iterations = Number(parts[1]);
	const salt = fromB64(parts[2]!);
	const expected = fromB64(parts[3]!);
	// Guard against a corrupted/hostile iteration count (DoS via login).
	if (!Number.isFinite(iterations) || iterations <= 0 || iterations > 1_000_000) return false;
	const derived = await pbkdf2(password, salt, iterations);
	return constantTimeEqual(expected, derived);
}

// A hash used to equalise login timing when the username does not exist.
let dummyHashPromise: Promise<string> | null = null;
function dummyHash(): Promise<string> {
	dummyHashPromise ??= hashPassword(`dummy-${randomToken(24)}`);
	return dummyHashPromise;
}

/** Always spends roughly one PBKDF2 verify worth of time. */
export async function verifyAgainstDummy(password: string): Promise<void> {
	await verifyPassword(password, await dummyHash());
}

/**
 * Create a session. Returns the raw token (to put in the cookie) and the
 * stored session, whose id is the hash of that token.
 */
export async function createSession(userId: string): Promise<{ session: Session; token: string }> {
	const db = getDB();
	const now = Date.now();
	const token = randomToken(32);
	const session: Session = {
		id: await sha256Hex(token),
		userId,
		createdAt: new Date(now).toISOString(),
		expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
	};
	await db.batch([
		db
			.prepare(
				'INSERT INTO sessions (id, user_id, created_at, expires_at, last_used_at) VALUES (?1, ?2, ?3, ?4, ?5)',
			)
			.bind(session.id, session.userId, session.createdAt, session.expiresAt, session.createdAt),
		db.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(nowISO()),
	]);
	return { session, token };
}

/** Delete the session belonging to a raw cookie token. */
export async function destroySession(rawToken: string): Promise<void> {
	const id = await sha256Hex(rawToken);
	await getDB().prepare('DELETE FROM sessions WHERE id = ?1').bind(id).run();
}

/** Log out everywhere for this user. */
export async function destroyAllSessions(userId: string): Promise<void> {
	await getDB().prepare('DELETE FROM sessions WHERE user_id = ?1').bind(userId).run();
}

interface SessionRow {
	id: string;
	created_at: string;
	expires_at: string;
	last_used_at: string | null;
	username: string;
}

/** Resolve a raw session cookie to a sanitised user (no password hash). */
export async function userForSession(rawToken: string | undefined): Promise<SessionUser | null> {
	if (!rawToken) return null;
	const id = await sha256Hex(rawToken);
	const db = getDB();
	const row = await db
		.prepare(
			`SELECT s.id AS id, s.created_at AS created_at, s.expires_at AS expires_at,
              s.last_used_at AS last_used_at, u.id AS user_id, u.username AS username
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.id = ?1`,
		)
		.bind(id)
		.first<SessionRow & { user_id: string }>();
	if (!row) return null;

	const now = Date.now();
	if (row.expires_at <= new Date(now).toISOString()) return null;

	const idleBase = row.last_used_at ?? row.created_at;
	if (new Date(idleBase).getTime() + IDLE_TTL_MS < now) {
		await db.prepare('DELETE FROM sessions WHERE id = ?1').bind(id).run();
		return null;
	}

	// Touch at most every few minutes to avoid a write per request.
	if (!row.last_used_at || now - new Date(row.last_used_at).getTime() > TOUCH_INTERVAL_MS) {
		await db.prepare('UPDATE sessions SET last_used_at = ?1 WHERE id = ?2').bind(nowISO(), id).run();
	}

	return { id: row.user_id, username: row.username };
}

interface UserRow {
	id: string;
	username: string;
	password_hash: string;
	created_at: string;
}

function toUser(row: UserRow): User {
	return {
		id: row.id,
		username: row.username,
		passwordHash: row.password_hash,
		createdAt: row.created_at,
	};
}

export async function findUser(username: string): Promise<User | null> {
	const row = await getDB()
		.prepare(
			'SELECT id, username, password_hash, created_at FROM users WHERE username = ?1 COLLATE NOCASE',
		)
		.bind(username)
		.first<UserRow>();
	return row ? toUser(row) : null;
}

export async function hasUsers(): Promise<boolean> {
	const row = await getDB().prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>();
	return (row?.n ?? 0) > 0;
}

/**
 * Create the first user atomically. Returns null if a user already exists,
 * so concurrent bootstrap requests cannot both win.
 */
export async function createFirstUser(username: string, password: string): Promise<User | null> {
	const db = getDB();
	const user: User = {
		id: newId(),
		username,
		passwordHash: await hashPassword(password),
		createdAt: nowISO(),
	};
	const result = await db
		.prepare(
			`INSERT INTO users (id, username, password_hash, created_at)
       SELECT ?1, ?2, ?3, ?4
       WHERE NOT EXISTS (SELECT 1 FROM users)`,
		)
		.bind(user.id, user.username, user.passwordHash, user.createdAt)
		.run();
	return result.meta.changes > 0 ? user : null;
}
