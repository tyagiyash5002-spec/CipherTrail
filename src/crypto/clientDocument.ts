import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { encode, decode } from 'cborg';
import { PDFDocument, PDFName, PDFHexString } from 'pdf-lib';
import { addVisualWatermark } from './visualWatermark.ts';

export const CLIENT_SUITE = 'CT-CLIENT-1/ML-KEM-768/ML-DSA-65/AES-256-GCM/HKDF-SHA-384';
const MAX_PDF = 10 * 1024 * 1024;
const utf8 = new TextEncoder();
const MARKER = PDFName.of('CipherTrailIssuance');

export interface RecipientEnvelope {
  recipientId: string;
  keyId: string;
  cipherText: string; // base64 ML-KEM-768 ciphertext (1088 bytes)
  wrappedKey: string; // base64 nonce[12] || tag[16] || encrypted DEK[32]
}
export interface PackageManifest {
  domain: 'CipherTrail/client-package/v1';
  suite: typeof CLIENT_SUITE;
  documentId: string;
  version: number;
  filename: string;
  senderKeyId: string;
  sourceDigest: string;
  ciphertextDigest: string;
  recipients: RecipientEnvelope[];
}
export interface EncryptedClientPackage {
  encryptedPayload: Uint8Array; // nonce[12] || tag[16] || ciphertext
  manifestBytes: Uint8Array; // exact canonical CBOR, never JSON to re-sign
  senderSignature: Uint8Array;
}
export interface RecipientPublicIdentity {
  recipientId: string;
  keyId: string;
  kemPublicKey: Uint8Array; // trusted/pinned outside the storage server
}
export interface ClientIdentity {
  recipientId: string;
  keyId: string;
  kemPrivateKey: Uint8Array;
}
export interface IssuanceContext {
  networkId: string;
  sessionId: string; // create once per issuance, reuse for a transport retry
  policyEpoch: number;
  createdAt: string;
}
export interface ClientIssuanceEvent {
  domain: 'CipherTrail/client-issuance/v1';
  suite: typeof CLIENT_SUITE;
  networkId: string;
  sessionId: string;
  documentId: string;
  documentVersion: number;
  recipientId: string;
  keyId: string;
  policyEpoch: number;
  createdAt: string;
  packageDigest: string;
  outputDigest: string;
  watermarkProfile: 'structural-client-v1' | 'dct-footer-v1';
}
export interface PreparedClientCopy {
  pdfBytes: Uint8Array;
  filename: string;
  event: ClientIssuanceEvent;
  eventBytes: Uint8Array;
}
export interface SignedClientEvent {
  eventBytes: Uint8Array;
  signature: Uint8Array;
}

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto requires HTTPS or localhost.');
  return globalThis.crypto.subtle;
}
function buffer(bytes: Uint8Array): ArrayBuffer {
  const result = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(result).set(bytes);
  return result;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}
export function toBase64(bytes: Uint8Array): string {
  let text = '';
  for (let at = 0; at < bytes.length; at += 8192)
    text += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return btoa(text);
}
export function fromBase64(text: string): Uint8Array {
  if (typeof text !== 'string' || text.length > 20000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('Malformed base64 envelope.');
  const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
  if (toBase64(bytes) !== text) throw new Error('Noncanonical base64 envelope.');
  return bytes;
}
export async function digest(bytes: Uint8Array, domain = 'CipherTrail/artifact/v1'): Promise<string> {
  const result = await subtle().digest('SHA-384', buffer(concat(utf8.encode(domain + '\0'), bytes)));
  return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, '0')).join('');
}
const context = (documentId: string, recipientId: string) => `CipherTrail/envelope/v1/${documentId}/${recipientId}`;
function id(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(value)) throw new Error('Invalid identity or document identifier.');
}
async function envelopeKey(sharedSecret: Uint8Array, aad: string): Promise<CryptoKey> {
  const material = await subtle().importKey('raw', buffer(sharedSecret), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-384', salt: new Uint8Array(0), info: buffer(utf8.encode(aad)) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}
async function importAes(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('Expected an AES-256 document key.');
  return subtle().importKey('raw', buffer(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(bytes: Uint8Array, key: CryptoKey, aad: string): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await subtle().encrypt(
    { name: 'AES-GCM', iv: buffer(iv), additionalData: buffer(utf8.encode(aad)), tagLength: 128 }, key, buffer(bytes),
  ));
  // Web Crypto returns ciphertext || tag. Preserve the existing Node wire layout.
  return concat(iv, encrypted.subarray(-16), encrypted.subarray(0, -16));
}
async function unseal(bytes: Uint8Array, key: CryptoKey, aad: string): Promise<Uint8Array> {
  if (bytes.length < 28) throw new Error('Truncated AES-GCM envelope.');
  return new Uint8Array(await subtle().decrypt(
    { name: 'AES-GCM', iv: buffer(bytes.subarray(0, 12)), additionalData: buffer(utf8.encode(aad)), tagLength: 128 },
    key, buffer(concat(bytes.subarray(28), bytes.subarray(12, 28))),
  ));
}
async function loadPdf(bytes: Uint8Array): Promise<PDFDocument> {
  if (bytes.length > MAX_PDF || String.fromCharCode(...bytes.subarray(0, 5)) !== '%PDF-') throw new Error('Expected a PDF no larger than 10 MiB.');
  const pdf = await PDFDocument.load(bytes, { updateMetadata: false });
  if (pdf.getPageCount() < 1 || pdf.getPageCount() > 100) throw new Error('PDF must have 1–100 pages.');
  return pdf;
}
function validateManifest(value: unknown): asserts value is PackageManifest {
  if (!value || typeof value !== 'object') throw new Error('Invalid manifest.');
  const m = value as PackageManifest;
  const names = ['domain','suite','documentId','version','filename','senderKeyId','sourceDigest','ciphertextDigest','recipients'];
  if (Object.keys(m).sort().join() !== names.sort().join() || m.domain !== 'CipherTrail/client-package/v1' || m.suite !== CLIENT_SUITE || m.version !== 1) throw new Error('Unsupported package schema or suite.');
  id(m.documentId);
  if (typeof m.filename !== 'string' || !m.filename || m.filename.length > 160) throw new Error('Invalid filename.');
  for (const hash of [m.senderKeyId,m.sourceDigest,m.ciphertextDigest]) if (!/^[0-9a-f]{96}$/.test(hash)) throw new Error('Invalid SHA-384 digest.');
  if (!Array.isArray(m.recipients) || !m.recipients.length || m.recipients.length > 20) throw new Error('Expected 1–20 recipients.');
  const seen = new Set<string>();
  for (const e of m.recipients) {
    if (!e || Object.keys(e).sort().join() !== ['recipientId','keyId','cipherText','wrappedKey'].sort().join()) throw new Error('Invalid recipient envelope.');
    id(e.recipientId); id(e.keyId);
    if (seen.has(e.recipientId)) throw new Error('Duplicate recipient identity.');
    seen.add(e.recipientId);
    if (fromBase64(e.cipherText).length !== 1088 || fromBase64(e.wrappedKey).length !== 60) throw new Error('Invalid ML-KEM/AES envelope length.');
  }
}

/** Run on the SENDER's computer. Only the returned encrypted package is uploaded. */
export async function encryptPdfForRecipients(input: {
  pdfBytes: Uint8Array;
  documentId: string;
  filename: string;
  recipients: RecipientPublicIdentity[];
  senderSigningPrivateKey: Uint8Array;
}): Promise<EncryptedClientPackage> {
  subtle(); id(input.documentId);
  await loadPdf(input.pdfBytes);
  if (input.senderSigningPrivateKey.length !== 4032) throw new Error('Expected an ML-DSA-65 signing key.');
  if (input.recipients.length < 1 || input.recipients.length > 20) throw new Error('Choose 1–20 recipients.');
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    const encryptedPayload = await seal(input.pdfBytes, await importAes(dek), 'document/' + input.documentId);
    const recipients: RecipientEnvelope[] = [];
    for (const r of input.recipients) {
      id(r.recipientId); id(r.keyId);
      if (r.kemPublicKey.length !== 1184) throw new Error('Expected an ML-KEM-768 public key.');
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(r.kemPublicKey);
      try {
        const aad = context(input.documentId, r.recipientId);
        recipients.push({ recipientId: r.recipientId, keyId: r.keyId, cipherText: toBase64(cipherText), wrappedKey: toBase64(await seal(dek, await envelopeKey(sharedSecret, aad), aad)) });
      } finally { sharedSecret.fill(0); }
    }
    const manifest: PackageManifest = {
      domain: 'CipherTrail/client-package/v1', suite: CLIENT_SUITE, documentId: input.documentId, version: 1,
      filename: input.filename, recipients: recipients.sort((a,b) => a.recipientId < b.recipientId ? -1 : 1),
      senderKeyId: await digest(ml_dsa65.getPublicKey(input.senderSigningPrivateKey), 'CipherTrail/sender-key/v1'),
      sourceDigest: await digest(input.pdfBytes),
      ciphertextDigest: await digest(encryptedPayload, 'CipherTrail/ciphertext/v1'),
    };
    validateManifest(manifest);
    const manifestBytes = encode(manifest);
    return { encryptedPayload, manifestBytes, senderSignature: ml_dsa65.sign(manifestBytes, input.senderSigningPrivateKey) };
  } finally { dek.fill(0); }
}

/** Entirely local. Does not call fetch, send a shared secret, or download unmarked bytes. */
export async function decryptAndMarkPdf(input: {
  package: EncryptedClientPackage;
  recipient: ClientIdentity;
  trustedSenderPublicKey: Uint8Array;
  issuance: IssuanceContext;
  visualWatermark?: boolean;
}): Promise<PreparedClientCopy> {
  subtle();
  const { package: pkg, recipient, issuance } = input;
  id(recipient.recipientId); id(recipient.keyId); id(issuance.sessionId); id(issuance.networkId);
  if (!Number.isSafeInteger(issuance.policyEpoch) || issuance.policyEpoch < 1 || !Number.isFinite(Date.parse(issuance.createdAt))) throw new Error('Invalid issuance context.');
  if (pkg.encryptedPayload.length > MAX_PDF + 28 || pkg.manifestBytes.length > 128 * 1024) throw new Error('Package exceeds demo size limits.');
  if (input.trustedSenderPublicKey.length !== 1952 || pkg.senderSignature.length !== 3309 || recipient.kemPrivateKey.length !== 2400) throw new Error('Incorrect PQ key/signature length.');
  if (!ml_dsa65.verify(pkg.senderSignature, pkg.manifestBytes, input.trustedSenderPublicKey)) throw new Error('Sender signature verification failed.');
  const decoded: unknown = decode(pkg.manifestBytes, { strict: true, allowIndefinite: false, allowUndefined: false, allowNaN: false, allowInfinity: false, allowBigInt: false, rejectDuplicateMapKeys: true });
  validateManifest(decoded);
  const manifest = decoded;
  if (!equal(encode(manifest), pkg.manifestBytes)) throw new Error('Manifest is not canonical CBOR.');
  if (manifest.senderKeyId !== await digest(input.trustedSenderPublicKey, 'CipherTrail/sender-key/v1')) throw new Error('Sender key binding failed.');
  if (manifest.ciphertextDigest !== await digest(pkg.encryptedPayload, 'CipherTrail/ciphertext/v1')) throw new Error('Encrypted payload digest mismatch.');
  const recipientEnvelope = manifest.recipients.find(e => e.recipientId === recipient.recipientId && e.keyId === recipient.keyId);
  if (!recipientEnvelope) throw new Error('This package has no envelope for your identity and key.');
  let sharedSecret: Uint8Array | undefined;
  let dek: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    sharedSecret = ml_kem768.decapsulate(fromBase64(recipientEnvelope.cipherText), recipient.kemPrivateKey);
    const aad = context(manifest.documentId, recipient.recipientId);
    dek = await unseal(fromBase64(recipientEnvelope.wrappedKey), await envelopeKey(sharedSecret, aad), aad);
    plaintext = await unseal(pkg.encryptedPayload, await importAes(dek), 'document/' + manifest.documentId);
    if (await digest(plaintext) !== manifest.sourceDigest) throw new Error('Source document digest mismatch.');
    const pdf = await loadPdf(plaintext);
    if (input.visualWatermark) await addVisualWatermark(pdf, issuance.networkId, issuance.sessionId);
    const mark = 'CipherTrail-client-v1:' + toBase64(encode({sessionId: issuance.sessionId, documentId: manifest.documentId, recipientId: recipient.recipientId, keyId: recipient.keyId}));
    pdf.catalog.set(MARKER, PDFHexString.fromText(mark));
    pdf.setModificationDate(new Date(issuance.createdAt));
    const pdfBytes = await pdf.save({ useObjectStreams: false });
    const check = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const extracted = check.catalog.get(MARKER);
    if (!(extracted instanceof PDFHexString) || extracted.decodeText() !== mark || check.getPageCount() !== pdf.getPageCount()) throw new Error('Local watermark self-extraction failed.');
    const event: ClientIssuanceEvent = {
      domain: 'CipherTrail/client-issuance/v1', suite: CLIENT_SUITE,
      networkId: issuance.networkId, sessionId: issuance.sessionId, policyEpoch: issuance.policyEpoch, createdAt: issuance.createdAt,
      documentId: manifest.documentId, documentVersion: manifest.version, recipientId: recipient.recipientId, keyId: recipient.keyId,
      packageDigest: await digest(pkg.manifestBytes, 'CipherTrail/package/v1'),
      outputDigest: await digest(pdfBytes), watermarkProfile: input.visualWatermark ? 'dct-footer-v1' : 'structural-client-v1',
    };
    const safeName = manifest.filename.replace(/[^A-Za-z0-9._-]/g, '_').replace(/\.pdf$/i, '');
    return { pdfBytes, filename: `${safeName}-${issuance.sessionId}.pdf`, event, eventBytes: encode(event) };
  } finally {
    sharedSecret?.fill(0); dek?.fill(0); plaintext?.fill(0);
    // JS, PDF parser and browser buffers may retain copies; no secure-memory claim.
  }
}

/** Call only after displaying the local event and obtaining the recipient's approval. */
export async function signClientIssuance(copy: PreparedClientCopy, signingPrivateKey: Uint8Array, registeredSigningPublicKey: Uint8Array): Promise<SignedClientEvent> {
  if (signingPrivateKey.length !== 4032) throw new Error('Expected an ML-DSA-65 private key.');
  if (!equal(ml_dsa65.getPublicKey(signingPrivateKey), registeredSigningPublicKey)) throw new Error('Signing key does not match the registered recipient.');
  if (!equal(encode(copy.event), copy.eventBytes) || await digest(copy.pdfBytes) !== copy.event.outputDigest) throw new Error('Prepared PDF/event changed before signing.');
  const signature = ml_dsa65.sign(copy.eventBytes, signingPrivateKey);
  if (!ml_dsa65.verify(signature, copy.eventBytes, ml_dsa65.getPublicKey(signingPrivateKey))) throw new Error('Local signature self-check failed.');
  return { eventBytes: new Uint8Array(copy.eventBytes), signature };
}

/** Download only the already marked output; call after your record/commit policy succeeds. */
export function downloadMarkedPdf(copy: PreparedClientCopy): void {
  const url = URL.createObjectURL(new Blob([buffer(copy.pdfBytes)], { type: 'application/pdf' }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = copy.filename;
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
