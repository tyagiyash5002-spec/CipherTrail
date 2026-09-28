import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { encode64, decode64 } from './api';
export function generateKeys(account) {
  const kem = ml_kem768.keygen(), signing = ml_dsa65.keygen();
  return {format:'ciphertrail-private-demo-keys-v1',account,kemPublic:encode64(kem.publicKey),kemSecret:encode64(kem.secretKey),signPublic:encode64(signing.publicKey),signSecret:encode64(signing.secretKey)};
}
export function enrollment(keys) {
  const bytes = new TextEncoder().encode(`CipherTrail/enroll/v1/${keys.account}/${keys.kemPublic}`);
  return {kemPublic:keys.kemPublic,signPublic:keys.signPublic,proof:encode64(ml_dsa65.sign(bytes,decode64(keys.signSecret)))};
}
export function validateKeys(keys,user) {
  if (keys.format!=='ciphertrail-private-demo-keys-v1' || keys.account!==user.id || (user.keyId && (keys.kemPublic!==user.kemPublic || keys.signPublic!==user.signPublic))) throw new Error('This key file does not match your account and registered public keys.');
  const message = new TextEncoder().encode('CipherTrail/key-self-test/v1');
  if (!ml_dsa65.verify(ml_dsa65.sign(message,decode64(keys.signSecret)),message,decode64(keys.signPublic))) throw new Error('Signing key self-test failed.');
  const {cipherText,sharedSecret} = ml_kem768.encapsulate(decode64(keys.kemPublic));
  const recovered = ml_kem768.decapsulate(cipherText,decode64(keys.kemSecret));
  if (!sharedSecret.every((v,i)=>v===recovered[i])) throw new Error('Encryption key self-test failed.');
  sharedSecret.fill(0); recovered.fill(0); return keys;
}
export function unlockEnvelope(value,keys) {
  const secret = ml_kem768.decapsulate(decode64(value.cipherText),decode64(keys.kemSecret));
  try { return encode64(secret); } finally { secret.fill(0); }
}
export function signEvent(event,keys) { return encode64(ml_dsa65.sign(decode64(event),decode64(keys.signSecret))); }
