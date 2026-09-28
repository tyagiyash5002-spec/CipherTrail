import { randomBytes, createCipheriv, createDecipheriv, createHash, createHmac, scryptSync, timingSafeEqual, hkdfSync } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import cbor from 'cbor';

export const hash = (bytes, domain = 'CipherTrail/artifact/v1') => createHash('sha384').update(domain + '\0').update(bytes).digest('hex');
export const canonical = value => cbor.encodeCanonical(value);
export const b64 = bytes => Buffer.from(bytes).toString('base64');
export const from64 = text => Buffer.from(text, 'base64');
export const sign = (bytes, key) => Buffer.from(ml_dsa65.sign(bytes, key));
export function verify(bytes, signature, key) { try { return ml_dsa65.verify(signature, bytes, key); } catch { return false; } }
export const signingKeypair = () => ml_dsa65.keygen();
export const envelopeContext = (docId, recipientId) => `CipherTrail/envelope/v1/${docId}/${recipientId}`;
export const deriveEnvelopeKey = (secret, context) => Buffer.from(hkdfSync('sha384', secret, Buffer.alloc(0), context, 32));
export function envelope(dek, publicKey, context) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  try { return { cipherText:b64(cipherText), wrappedKey:b64(seal(dek, deriveEnvelopeKey(sharedSecret, context), context)) }; }
  finally { sharedSecret.fill(0); }
}
export function passwordHash(password, salt = randomBytes(16).toString('hex')) {
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}
export function passwordMatches(password, encoded) {
  const [salt, expected] = encoded.split(':');
  const actual = passwordHash(password, salt).split(':')[1];
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'));
}
// AAD binds each ciphertext to its purpose and document ID.
export function seal(bytes, key, context) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
}
export function unseal(bytes, key, context) {
  const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
  cipher.setAAD(Buffer.from(context));
  cipher.setAuthTag(bytes.subarray(12, 28));
  return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]);
}
export function marker(event, key) {
  const payload = `${event.id}.${event.document_id}.${event.recipient_id}`;
  return `CipherTrail-v1:${payload}.${createHmac('sha384', key).update(payload).digest().subarray(0,24).toString('hex')}`;
}
