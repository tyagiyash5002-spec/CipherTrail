import { useRef, useState } from 'react';
import {
  decryptAndMarkPdf, signClientIssuance, downloadMarkedPdf,
  type EncryptedClientPackage, type ClientIdentity, type IssuanceContext,
  type PreparedClientCopy, type SignedClientEvent,
} from './clientDocument';

interface Props {
  encryptedPackage: EncryptedClientPackage;
  recipient: ClientIdentity;
  recipientSigningPrivateKey: Uint8Array;
  registeredSigningPublicKey: Uint8Array;
  trustedSenderPublicKey: Uint8Array;
  issuance: IssuanceContext;
  visualWatermark?: boolean;
  /** Send only event bytes/signature. Resolve only after the caller's release policy passes.
   * The Task 2 recorder currently trusts the configured RPC/API.
   * A raw RPC acknowledgment must not be described as verified finality.
   */
  recordEvent: (event: SignedClientEvent) => Promise<void>;
}

/** Drop-in React component. The backend receives neither PDF plaintext nor key material. */
export function ClientDecryptButton(props: Props) {
  const [prepared, setPrepared] = useState<PreparedClientCopy | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [complete, setComplete] = useState(false);
  const locked = useRef(false);
  // Retain the exact signed request if the response is lost; retries use the same session.
  const signed = useRef<SignedClientEvent | null>(null);

  async function prepare() {
    if (locked.current) return;
    locked.current = true; setBusy(true); setError('');
    try {
      setPrepared(await decryptAndMarkPdf({
        package: props.encryptedPackage,
        recipient: props.recipient,
        trustedSenderPublicKey: props.trustedSenderPublicKey,
        issuance: props.issuance,
        visualWatermark: props.visualWatermark,
      }));
    } catch (e) { setError(e instanceof Error ? e.message : 'Local decryption failed.'); }
    finally { locked.current = false; setBusy(false); }
  }

  async function approve() {
    if (!prepared || locked.current) return;
    locked.current = true; setBusy(true); setError('');
    try {
      signed.current ??= await signClientIssuance(prepared, props.recipientSigningPrivateKey, props.registeredSigningPublicKey);
      await props.recordEvent({ eventBytes: signed.current.eventBytes.slice(), signature: signed.current.signature.slice() });
      downloadMarkedPdf(prepared);
      prepared.pdfBytes.fill(0); signed.current = null;
      setPrepared(null); setComplete(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Recording failed. No download was triggered.');
    } finally { locked.current = false; setBusy(false); }
  }

  function decline() {
    if (busy) return;
    prepared?.pdfBytes.fill(0); setPrepared(null); signed.current = null; setError('');
  }

  return <section aria-label="Local document decryption">
    {!prepared && !complete && <button type="button" onClick={prepare} disabled={busy}>
      {busy ? 'Decrypting and marking locally…' : 'Prepare my copy on this computer'}
    </button>}
    {prepared && <div>
      <h3>Approve this issuance</h3>
      <dl>
        <dt>Document</dt><dd>{prepared.event.documentId}</dd>
        <dt>Recipient</dt><dd>{prepared.event.recipientId}</dd>
        <dt>Session</dt><dd>{prepared.event.sessionId}</dd>
        <dt>Marked output SHA-384</dt><dd style={{ overflowWrap: 'anywhere' }}>{prepared.event.outputDigest}</dd>
      </dl>
      <button type="button" onClick={approve} disabled={busy}>{busy ? 'Signing and recording…' : 'Sign, record and download'}</button>
      <button type="button" onClick={decline} disabled={busy}>Decline</button>
    </div>}
    {complete && <p role="status">Your locally decrypted and marked PDF was offered for download.</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
