import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { hash, passwordHash, signingKeypair, seal, unseal } from './crypto.mjs';

export function openStore(directory) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  mkdirSync(path.join(directory, 'documents'), { recursive: true, mode: 0o700 });
  const keyPath = path.join(directory, 'master.key');
  const dbPath = path.join(directory, 'ciphertrail.sqlite');
  const existingDatabase=existsSync(dbPath);
  if (!existsSync(keyPath)) {
    if (existsSync(dbPath)) throw new Error('Existing database has no master.key. Restore its original key before starting.');
    writeFileSync(keyPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
  }
  const key = readFileSync(keyPath);
  if (key.length !== 32) throw new Error('Invalid master.key.');
  if(existingDatabase) for(const name of ['sender','device','watermark-v1']) if(!existsSync(path.join(directory,name+'.key'))) throw new Error(`Existing workspace is missing ${name}.key. Restore the complete data directory.`);
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, kem_public TEXT, sign_public TEXT, key_id TEXT);
    CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, pages INTEGER NOT NULL, digest TEXT NOT NULL, wrapped_key BLOB NOT NULL, created_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL DEFAULT 1, manifest BLOB, signature BLOB);
    CREATE TABLE IF NOT EXISTS permissions (document_id TEXT NOT NULL REFERENCES documents(id), user_id TEXT NOT NULL REFERENCES users(id), envelope TEXT NOT NULL, PRIMARY KEY(document_id,user_id));
    CREATE TABLE IF NOT EXISTS issuances (id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id), recipient_id TEXT NOT NULL REFERENCES users(id), request_id TEXT NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, epoch INTEGER NOT NULL, event BLOB NOT NULL, signature BLOB, attestation BLOB, status TEXT NOT NULL, UNIQUE(recipient_id,request_id));
    CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, artifact_hash TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
  const check = db.prepare('SELECT value FROM config WHERE key=?').get('key_check');
  const fingerprint = hash(Buffer.concat([key, Buffer.from('CipherTrail key check')]));
  if (check && check.value !== fingerprint) { db.close(); throw new Error('master.key does not match this database.'); }
  if (!check) db.prepare('INSERT INTO config VALUES (?,?)').run('key_check', fingerprint);
  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
    const accounts = [ ['admin', 'Demo Administrator', 'admin'], ['recipient.a', 'Recipient A', 'recipient'], ['recipient.b', 'Recipient B', 'recipient'] ].map(([id,name,role]) => ({id,name,role,password:randomBytes(15).toString('base64url')}));
    // Kept outside the public web root; give each participant only their own password.
    writeFileSync(path.join(directory, 'initial-accounts.json'), JSON.stringify(accounts, null, 2), { mode: 0o600, flag: 'wx' });
    transaction(db, () => {
      for (const a of accounts) db.prepare('INSERT INTO users(id,name,role,password) VALUES (?,?,?,?)').run(a.id,a.name,a.role,passwordHash(a.password));
    });
  }
  function localSecret(name, generate) {
    const file = path.join(directory, name + '.key');
    if (!existsSync(file)) writeFileSync(file, seal(generate(),key,name), {mode:0o600,flag:'wx'});
    return unseal(readFileSync(file),key,name);
  }
  const sender = JSON.parse(localSecret('sender', () => {
    const keys = signingKeypair();
    return Buffer.from(JSON.stringify({publicKey:Buffer.from(keys.publicKey).toString('base64'),secretKey:Buffer.from(keys.secretKey).toString('base64')}));
  }));
  const device = JSON.parse(localSecret('device', () => {
    const keys = signingKeypair();
    return Buffer.from(JSON.stringify({publicKey:Buffer.from(keys.publicKey).toString('base64'),secretKey:Buffer.from(keys.secretKey).toString('base64')}));
  }));
  const watermarkKey = localSecret('watermark-v1', () => randomBytes(48));
  return {db,key,directory,sender,device,watermarkKey};
}
export function transaction(db, action) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = action(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
export function appendAudit(db, actor, action, details) {
  const payload = JSON.stringify({ time: new Date().toISOString(), actor, action, details });
  const previous = db.prepare('SELECT digest FROM audit ORDER BY seq DESC LIMIT 1').get()?.digest || '0'.repeat(96);
  db.prepare('INSERT INTO audit(payload,previous,digest) VALUES (?,?,?)').run(payload,previous,hash(previous + payload,'CipherTrail/audit/v1'));
}
export function verifyAudit(db) {
  let previous = '0'.repeat(96), count = 0;
  for (const row of db.prepare('SELECT * FROM audit ORDER BY seq').iterate()) {
    if (row.previous !== previous || hash(previous + row.payload,'CipherTrail/audit/v1') !== row.digest) return { valid:false, count, brokenAt:row.seq };
    previous = row.digest; count++;
  }
  return { valid:true, count, head:previous };
}
