// Key/value settings stored in D1.

import { getDB } from './store';

export async function getSetting(key: string): Promise<string | null> {
	const row = await getDB()
		.prepare('SELECT value FROM settings WHERE key = ?1')
		.bind(key)
		.first<{ value: string }>();
	return row?.value ?? null;
}

export async function setSetting(key: string, value: string): Promise<void> {
	await getDB()
		.prepare(
			`INSERT INTO settings (key, value) VALUES (?1, ?2)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		)
		.bind(key, value)
		.run();
}

export async function deleteSetting(key: string): Promise<void> {
	await getDB().prepare('DELETE FROM settings WHERE key = ?1').bind(key).run();
}
