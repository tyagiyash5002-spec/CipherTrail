# CipherTrail working demonstration

This build supports a live three-computer demonstration: encrypt a PDF, deny an unauthorized recipient, let an authorized recipient unlock and sign for a marked copy, then identify the original issued file during a simulated leak investigation.

It uses the SRS cryptographic profile for the implemented operations. It is not the complete SRS implementation: distributed BFT consensus/finality, rendered-channel watermarking, and assessed hardware isolation are not implemented. The application displays those limits rather than simulating success.

## Start on this computer

Use Node.js 24.7 or later in the Node 24 release line. Dependencies are already installed in this workspace.

```powershell
cd 'C:\Users\tyagi\Downloads\New folder\ciphertrail-ui'
npm run build
npm start
```

Open http://localhost:3001. The server serves both the built React application and its API; a separate frontend host is unnecessary.

On first startup, the server creates three accounts with random passwords:

- `admin`: uploads, grants access, investigates, and views the audit.
- `recipient.a`: Recipient A.
- `recipient.b`: Recipient B.

Find their passwords in `data/initial-accounts.json`. Give each participant only their own credentials. This file is outside the served web root and excluded from version control. The database stores salted scrypt password hashes. This setup file is retained for demonstration convenience; protect the data directory using operating-system permissions.

## Three computers on one network

Stop any existing server on port 3001, then run:

```powershell
npm run start:lan
```

This binds to all interfaces and prints the server's LAN addresses. Everyone opens the same printed address, for example `http://192.168.1.20:3001`. The server computer must remain running. Windows Firewall may need an inbound rule for TCP 3001 on the private network. Guest Wi-Fi/client isolation can prevent participants from reaching each other.

If `.env` explicitly sets `HOST=127.0.0.1`, change it to `HOST=0.0.0.0` for LAN use. Internet access is not required once dependencies are installed. Plain HTTP is only appropriate for a trusted local demonstration with synthetic files; use HTTPS and secure cookies on a hosted deployment.

One computer can rehearse all roles using different browser profiles or browsers. Ordinary tabs in the same browser share the login cookie, so use separate profiles for simultaneous users.

## Presentation walkthrough

1. On computer 2, sign in as `recipient.a`, open **My private keys**, and select **Generate & save private keys**. Keep the downloaded JSON file on that computer.
2. Repeat on computer 3 as `recipient.b`. Only public ML-KEM and ML-DSA keys are registered on the server. Private keys remain in browser memory and the recipient's downloaded key file.
3. On computer 1, sign in as `admin`. Open **People & access** and confirm that both recipients have registered keys.
4. Select **Protect a PDF**, upload `samples/harbor-briefing.pdf`, and select only Recipient A. The server stores one AES-256-GCM encrypted payload, creates A's ML-KEM-768 envelope, and signs the package with ML-DSA-65.
5. On computer 3, open **Documents** and press **Try access**. The server rejects B's request. The administrator can show the denial in **Audit history**.
6. On computer 2, select **Request my copy**. A's local key decapsulates the envelope. The trusted demo server decrypts internally, embeds and self-extracts a fresh mark, and prepares canonical CBOR event bytes.
7. A reviews the document, recipient, session, and digest, then selects **Sign & download my copy**. The browser creates the ML-DSA-65 signature using A's private key. The server verifies it, records the signed event and a separate device attestation, and releases the exact marked bytes.
8. The administrator grants Recipient B access using **Manage access**. B repeats the request/sign/download flow and receives a different copy.
9. Transfer A's downloaded PDF to computer 1, simulating a leak. Upload it under **Investigation**. The result identifies Recipient A's issuance using the exact SHA-384 digest, authenticated structural mark, recipient signature, device attestation, and local audit checks.
10. Repeat with B's downloaded PDF. Upload the unissued source PDF or an edited copy to demonstrate an inconclusive result.

The application associates a file with an issued copy. It does not establish who deliberately disclosed it.

After a browser refresh or logout, a recipient selects **Load private key file** to reload the original JSON file. The file contains unencrypted software private keys: keep it private. Key rotation/recovery is not implemented. A prepared session can be resumed from **Decryption sessions** for 15 minutes if the access policy has not changed. Declining signing releases no file.

## Technologies and SRS mapping

| SRS technology | Working implementation |
| --- | --- |
| ML-KEM-768 | `@noble/post-quantum`, one encapsulation and encrypted DEK envelope per authorized recipient |
| ML-DSA-65 | Sender package signature, browser-side recipient signature, separate device attestation |
| AES-256-GCM | Single document payload and envelopes; random 96-bit nonces and full 128-bit tags |
| HKDF-SHA-384 | Context-bound envelope key derivation |
| SHA-384 | Domain-separated document, output, identity, package and local audit digests |
| HMAC-SHA-384, truncated to 192 bits | Authenticated structural PDF session marker, separate versioned local secret |
| Canonical CBOR | Exact package and issuance bytes signed, stored, and verified without JSON reserialization |
| PDF-first handling | `pdf-lib`, bounded worker threads, 10 MB / 100-page input limits |
| Web interface | Existing React/Vite/Tailwind foundation, Radix dialogs and Lucide icons |
| Local service and persistence | Node.js 24, Express, SQLite, encrypted file storage |

The SRS specifies cryptography and trust requirements but does not mandate React, a particular backend language, or a named ledger platform. SQLite is application persistence and local audit storage here; it is **not represented as the SRS distributed ledger**.

Independent interoperability tests check ML-DSA signatures and ML-KEM shared secrets against Node's OpenSSL-backed implementation. This is not a FIPS module validation or exhaustive algorithm certification.

## Storage and deployment

The default data-directory budget is 700 MiB, configurable with `STORAGE_LIMIT_MB`. One encrypted source is retained per document. Marked downloads are generated on demand; plaintext copies and investigation uploads are not stored. The signed digest, marker-bearing event, and evidence remain in SQLite. Deleting a document removes its encrypted payload but retains issuance and investigation history.

The budget applies to the data directory, not the operating system, container image, dependencies, platform logs, or host backups. A provider advertising 1 GB must also support a persistent volume and a long-running Node service. Whether a specific plan fits still needs checking. RAM and disk storage are separate limits.

Hosted setup:

- Build with `npm ci` and `npm run build`; start with `npm start`.
- Set `HOST=0.0.0.0` and the platform-assigned `PORT`.
- Set `DATA_DIR` to a private persistent volume.
- Terminate HTTPS at the platform/reverse proxy and set `COOKIE_SECURE=true`.
- Keep a single application instance for this SQLite demo.
- Use `/api/health` as the readiness endpoint.
- Retrieve first-run accounts privately from the mounted data volume.

A Dockerfile is provided for compatible hosts. Mount persistent storage at `/app/data`. The container definition has not been executed in this workspace. Nothing has been published to an external hosting provider.

Back up the complete data directory while the service is stopped, including the database, master key, sender/device keys, watermark key, and encrypted documents. Keep recipient key files separately with their owners. An incomplete or mismatched key restore fails startup. Losing the master key loses access to the encrypted content.

## Verification

```powershell
npm test
npm run build
npm run sample
```

Tests exercise real HTTP requests through isolated server instances and real synthetic PDFs. They cover authorization, recipient-key possession, invalid signatures, distinct session output, idempotent/concurrent retries, cancellation, permission revocation, expiry, investigation, ciphertext/audit tampering, restart persistence, and algorithm interoperability. Test workspaces are retained under ignored `.test-runs/` for diagnosis.

Export an issuance's evidence from **Decryption sessions**. Verify local signatures and optionally a PDF independently of the application database:

```powershell
npm run verify -- evidence.json issued.pdf trusted-recipient-public-key.txt
```

The optional final file contains the recipient's trusted base64 public signing key obtained separately. Without it, the signature is checked against the bundle-supplied key, which does not independently prove identity. This verifier does not verify BFT finality, independent governance, or secret watermark authentication.

## Deliberate boundaries

- PDF marks are structural metadata, invisible on the page but removable by editing or reserialization. Rendered DCT watermarking and robustness qualification are future work.
- `EXACT_ISSUED_COPY` means verified local issuance association. It is not the complete SRS `EXACT_MATCH` classification with independently validated ledger evidence.
- The demo server is the trusted decryption component. It retains a master-wrapped DEK to update recipient envelopes and reproduce signed outputs. It is not a hardware-enforced, non-bypassable boundary.
- Recipient keys are generated locally, software-held and exportable. Public-key registration has one authenticated recipient's approval rather than the SRS two-person enrollment process.
- The local hash chain has no independent validators, trusted genesis, inclusion/finality proofs, or independently retained checkpoints. No blockchain or quorum success is fabricated.
- Issuance commit before release means a durable SQLite transaction, not SRS consensus finality. Ordinary HTTP/TLS does not establish a fully post-quantum transport.
- Audit display is limited to the latest 150 records; the full local chain is retained and verified. Session display shows the latest 200 and case history the latest 50.
- Use synthetic PDFs. A maintained, hostile-file scanning and sanitization pipeline is outside this demonstration.

The earlier simulated interface is preserved in `src/main.jsx` and its feature files. The working entry is `src/live/main.jsx`. Its previous documentation is in `UI-DEMO-ARCHIVE.md`.
