# Task 1 browser cryptography implementation

The new TypeScript modules implement sender-side encryption and recipient-side decryption/marking. They are staged integration code: the existing `src/live/App.jsx` screen and its `/prepare` and `/release` routes still use the original server-side flow. No existing stored documents or server keys were silently migrated or deleted.

Files:

- `src/crypto/clientDocument.ts`: browser-only package encryption, sender verification, local ML-KEM decapsulation, AES-GCM decryption, PDF marking, canonical CBOR events, recipient signing, and marked-only download.
- `src/crypto/ClientDecryptButton.tsx`: React approval flow. It accepts an encrypted package and caller-provided signed-event recorder. It never sends the PDF, DEK, shared secret, or private keys to that recorder.
- `tests/client-crypto.test.mjs`: real PDF/crypto interoperability and rejection tests.

## Sender

```ts
import { encryptPdfForRecipients } from './crypto/clientDocument';

const encryptedPackage = await encryptPdfForRecipients({
  pdfBytes: new Uint8Array(await selectedFile.arrayBuffer()),
  documentId: crypto.randomUUID(),
  filename: selectedFile.name,
  recipients: trustedRecipients, // recipientId, keyId, pinned kemPublicKey
  senderSigningPrivateKey: localSenderSigningKey,
});

// Upload only these three byte arrays to the storage server:
// encryptedPackage.encryptedPayload
// encryptedPackage.manifestBytes
// encryptedPackage.senderSignature
// Do not upload selectedFile, source bytes, a DEK, or a recovery-wrapped DEK.
```

The sender must obtain recipient public keys through a trusted registration mechanism. Blindly trusting keys supplied by an untrusted storage server would permit key substitution. Likewise, pin the sender's signing public key on recipient devices separately from the package response.

## Recipient

```tsx
import { ClientDecryptButton } from './crypto/ClientDecryptButton';

<ClientDecryptButton
  key={issuance.sessionId}
  encryptedPackage={encryptedPackage}
  recipient={{ recipientId, keyId, kemPrivateKey: localKemPrivateKey }}
  recipientSigningPrivateKey={localSigningPrivateKey}
  registeredSigningPublicKey={registeredSigningPublicKey}
  trustedSenderPublicKey={pinnedSenderPublicKey}
  issuance={issuance}
  recordEvent={recordSignedEvent}
/>
```

Create the issuance context once per fresh request; retain it on retry:

```ts
const issuance = {
  networkId: 'ciphertrail-demo',
  sessionId: crypto.randomUUID(),
  policyEpoch: 1,
  createdAt: new Date().toISOString(),
};
```

`recordSignedEvent` receives only `{eventBytes, signature}` and returns `Promise<void>`. It must resolve only after the release policy is satisfied. Task 2 supplies the real ledger adapter and commit-proof verification. No mock acknowledgment or fabricated BFT success is built into Task 1. A rejection leaves the marked copy local and triggers no download; retry preserves the session and signed bytes.

## API integration contract

Replace the legacy plaintext upload and server-decrypt workflow; do not call `unlockEnvelope()` from `src/live/keys.js`, because that legacy helper returns a shared secret for transmission to the server.

1. The authenticated sender uploads a binary encrypted payload, exact canonical CBOR manifest, and sender signature. The server verifies the signature against the registered sender public key and stores only those objects.
2. An authorized recipient downloads those same encrypted objects. Server authorization must still check the live recipient policy before delivery.
3. The recipient runs `decryptAndMarkPdf()` locally. It does not call fetch or return the raw source PDF or any key material. The returned PDF is already marked.
4. After explicit approval, `signClientIssuance()` signs the exact event bytes. The application transmits only the event and signature to its recorder.
5. The recorder checks the identity/key binding, document/package digest, policy, session uniqueness, and signature. After the application's verified release policy passes, `downloadMarkedPdf()` creates a local Blob URL for the marked copy.

Existing server-generated packages use a different manifest schema. They need explicit migration rather than silent acceptance. Compatibility tests establish the same AES serialization, ML-KEM parameter set, HKDF context and SHA-384 framing; the new manifest profile is deliberately versioned.

## Binary profile

- Payload and DEK envelope: `nonce[12] || GCM tag[16] || ciphertext`.
- Payload AAD: UTF-8 `document/{documentId}`.
- Envelope AAD and HKDF info: UTF-8 `CipherTrail/envelope/v1/{documentId}/{recipientId}`.
- HKDF: SHA-384, empty salt, 32-byte AES key. Shared secret: ML-KEM-768.
- ML-DSA-65 signatures cover exact canonical CBOR bytes. JSON is never substituted.
- SHA-384 digests retain the existing `domain + NUL + bytes` framing.
- The metadata marker has a new `structural-client-v1` profile. Its contents identify the session/document/recipient/key. The signed event binds its exact marked PDF digest. This marker does not use the legacy server-held watermark HMAC key and is not presented as that profile.
- The server sees metadata in the manifest/event, including document names, identities, session IDs and digests; document content is encrypted.

Use HTTPS or localhost: Web Crypto is unavailable on ordinary HTTP LAN origins. A trusted packaged Electron client would additionally need a restrictive renderer/preload configuration; this module alone does not configure Electron.

The crypto functions best-effort overwrite their temporary byte arrays. JavaScript/PDF parser/browser memory copies cannot be reliably erased. Recipient-controlled software can bypass its own marking/download flow. These properties do not prevent offline verification of a retained original marked file, but must not be confused with hardware-enforced issuance.

## Validate

```powershell
npm run typecheck:crypto
node --test tests/client-crypto.test.mjs
npm test
```

Tests use Node's standards-compatible Web Crypto implementation with real PDFs and actual ML-KEM/ML-DSA operations. The module performs no network request during decrypt/mark. Tests also compare Node-generated and browser-generated AES envelopes and canonical CBOR bytes. These tests are not a claim of screenshot robustness or a completed ledger integration.
