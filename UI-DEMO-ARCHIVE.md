# CipherTrail interface

A local React interface for the CipherTrail SRS, using a naval blue-and-white theme. This is an interactive frontend demonstration, not an implemented cryptographic system.

## Run

Requires Node.js 22.12+ or 24.

```sh
npm ci
npm run dev
```

Open the local address printed by Vite. To build static files, run `npm run build`. Preview that build with `npm run preview`. All interface assets are local; no fonts, CDNs or external APIs are requested at runtime. An air-gapped installation must bring the build or preinstalled dependencies onto the enclave.

## Stack

React, Vite, Tailwind CSS, locally composed shadcn-style Button and Radix Dialog primitives, Lucide React, Framer Motion, React Router, Axios, Recharts, React Dropzone and Sonner. The custom design is implemented in `src/styles.css` alongside Tailwind.

## Screens and interactions

- Overview: session and document counts from shared demo state, clickable system-flow diagram, live demo release readiness, illustrative activity chart, search and report export.
- Documents: guided packaging (PDF/sample selection, content approval, active recipients, manifest review and registration), classification filter, package details, editable versioned recipient policies, policy revocation, related issuance history and demo manifest export.
- Decryption sessions: authorization check, preparation animation, recipient approval/decline, quorum check, finalized event creation and demo receipt export.
- Audit ledger: the single issuance-history and ledger-evidence view, validator availability controls, record search, historical key/policy references, evidence inspection, sample checkpoint export, and a separate local workspace activity feed. The issuance screen links here rather than maintaining a duplicate history table.
- Investigation: exact, transformed, mixed, missing and invalid sample scenarios. Real file selection never produces a fabricated attribution result. Sample cases are retained during the session with individual report exports.
- Evidence workbench: local JSON receipt import with size/type validation, required-field inspection, and explicit reporting that signatures/finality remain unverified.
- Identities: pending enrollment, simulated second approval, key-version rotation, historical-version inspection and revocation.
- Settings: live demo readiness, policy preferences, target crypto profile, offline deployment and recovery requirements, snapshot export and workflow guide.

The new workflow modules are in `src/features/documents.jsx` and `src/features/operations.jsx`; shared presentation helpers and demo context are in `src/shared.jsx`. Seven primary navigation destinations are retained, plus `/login`. Separate auto-passing signature, consensus, release and verification screens from the reference project were intentionally not copied. Report exports live under Cases & evidence; the analysis result links there. Dashboard totals show distinct metrics rather than counting the same events twice.

## Demo login

Use the public demonstration credentials shown on the login page:

- Operator ID: `navy.operator`
- Password: `CipherTrail@2026`

The Fill demo credentials button fills the form but does not submit it. Wrong credentials show an error. Logged-out routes redirect to `/login`; successful login returns to the requested workspace route. The sidebar has a Sign out control. Login state is stored in tab-scoped sessionStorage without the password. Logout unmounts the workspace and discards its in-memory demo records.

This client-side gate is for demonstrating the product flow only. Public credentials and browser state do not provide real authentication, authorization or key custody. A real enclave identity service must replace `src/features/auth.jsx` authentication logic and enforce every protected operation on the backend. Do not enter real passwords.

## SRS integration boundary

`src/api.js` defines an Axios client and representative SRS API calls. Set `VITE_API_BASE_URL` during the build when the backend exists. Current pages intentionally use in-memory demo state; merely setting the URL does not enable real operations. Connect each workflow explicitly and enforce all policy checks server-side.

| SRS module | Interface coverage | Required backend |
| --- | --- | --- |
| M1 Identity | Enrollment, approval, rotation, revocation | Identity proofing, separate recipient-owned keys, signatures, historical registry |
| M2 Packaging | PDF selection, classification, recipients | Safe parsing, one AEAD payload, ML-KEM envelopes, sender signature |
| M3 Decryption | State progression, authorization and release-gate simulation | Trusted processing, protected staging, idempotence and crash recovery |
| M4 Watermark | Profile labels, sample scenario inspection | Real embedding, self-extraction, content binding and measured robustness |
| M5 Signing | Explicit recipient authorization | Canonical CBOR, recipient ML-DSA signing, separate device attestation |
| M6 Ledger | Node state, event inspection and proof structure | Independent private BFT nodes, PQ votes, real finality and inclusion proofs |
| M7 Forensics | Required result classes, report structure | Extraction, artifact hashing, historical identity verification, independent verifier |
| M8 Deployment | Local settings, recovery information and demo export | Offline installer, signed updates, secure backup/restore and independent checkpoints |

## Limitations

Data resets on reload. Uploads only create local metadata; PDF contents are not encrypted, embedded, persisted or sent anywhere. All signatures, finality, ledger blocks and sample forensic results are simulations. Exported JSON is explicitly marked as demo data and contains no cryptographic proof. The UI is not an authentication boundary. Administrator and recipient roles are views within one demo, not separate authenticated sessions. Four node cards do not establish independent control. Settings do not change real security policy. No cloud hosting is configured.

Imported JSON receipts are untrusted data. The workbench validates only a small demo schema, not digital signatures or trust roots. Local workspace activity is mutable in-memory state, not a substitute for DLT. Recipient policy editing does not construct real cryptographic key envelopes. `qa/` contains synthetic receipt fixtures for manual validation.
