# Task 2: signed client events on Tendermint

This is a working Node ABCI implementation for **Tendermint 0.34.24**, plus an authenticated Express broadcast endpoint. Each validator executes the same deterministic application against its own durable state. Issuance transactions are verified with **native Node/OpenSSL ML-DSA-65**, not a simulated signature check. Requires Node 24.7–24.x.

Task 1's React components remain staged: the existing pages still use the legacy SQLite/server-decryption workflow. The new `/api/ledger/events` endpoint is wired into Express; connecting `ClientDecryptButton` to it is shown below. The live integration script exercises client encryption → client marking → native signature verification → three-validator consensus. SQLite remains for existing login/UI data and is not the authority for these new ledger transactions. Old audit rows are not automatically migrated or presented as historical BFT commits.

## Run on this Windows machine

The checked release binary is already in ignored `data/tooling`. On a clean checkout:

```powershell
npm ci
./ledger/install-tendermint.ps1
npm run ledger:init -- 3
npm run ledger:start
```

The network is already initialized here; run only `npm run ledger:start` after stopping any existing instance. Initialization refuses to overwrite an existing network. Stop with Ctrl+C. Restart uses the same chain, validator keys and application state. Never copy or reset a validator's signing state independently of its key.

RPC endpoints are `127.0.0.1:26657`, `26667`, `26677`; ABCI uses `26658`, `26668`, `26678`. All listeners are loopback-only. Do not expose raw RPC or ABCI through Cloudflare. Cloudflare can proxy the authenticated Express application.

For Linux/macOS, install the official 0.34.24 release for your platform, check its published SHA256, and set `TENDERMINT_BIN` to the executable before initialization. This code uses classic ABCI; CometBFT ABCI++ is not a drop-in replacement.

```powershell
# Separate terminal: commits synthetic data and saves test evidence.
node scripts/test-ledger-live.mjs
npm test
npm run typecheck:crypto
npm run build
```

`data/ledger` contains three node homes, logs and a governance private key. Keep that key outside the Express machine in a deployment involving separate trust domains. `LEDGER_HOME`, `LEDGER_BASE_PORT`, and `LEDGER_NETWORK_ID` allow independent networks. `TENDERMINT_RPC` selects the Express/governance RPC endpoint. Example four-validator network:

```powershell
$env:LEDGER_HOME='data/ledger-four'
$env:LEDGER_BASE_PORT='27656'
$env:LEDGER_NETWORK_ID='ciphertrail-four-1'
npm run ledger:init -- 4
npm run ledger:start
```

Three equal-power validators need **all three** votes, because Tendermint requires strictly more than two-thirds. Four need three and can tolerate one Byzantine validator under Tendermint's assumptions. The local three-process demonstration does not provide independent-machine fault isolation. Consensus votes use stock Tendermint **Ed25519**; only application events use ML-DSA. This is not a fully post-quantum consensus protocol.

## Authorize identities and encrypted documents

Validators do not fetch identities from SQLite or trust a public key supplied with an issuance. Genesis pins a governance ML-DSA public key. The corresponding operator submits signed, monotonically sequenced governance transactions to register/revoke identities and set document permissions. Express never receives that private key.

Create an identity JSON file using the recipient's **independently verified** signing public key:

```json
{"recipientId":"recipient.a","keyId":"registered-key-id","publicKey":"BASE64_ML_DSA_65_PUBLIC_KEY","active":true}
```

```powershell
npm run ledger:govern -- data/ledger/governance-PRIVATE-keys.json identity identity.json
```

Create a document policy JSON file:

```json
{"documentId":"document-id","documentVersion":1,"policyEpoch":1,"packageDigest":"96_LOWERCASE_HEX_CHARACTERS","recipients":["recipient.a"]}
```

`packageDigest` must be Task 1's `await digest(pkg.manifestBytes, 'CipherTrail/package/v1')`, verified by the governance operator. It is not the ciphertext digest. Subsequent document-policy updates must increase `policyEpoch`. An empty recipients array revokes future ledger issuance approvals; it cannot erase plaintext already downloaded or keys already distributed.

```powershell
npm run ledger:govern -- data/ledger/governance-PRIVATE-keys.json document document-policy.json
```

Revocation uses another `identity` transaction with `active:false`. Governance signatures bind the chain ID and sequence. Issuance signatures bind the chain, session, recipient, registered key, package digest, output digest, document version and policy epoch. `createdAt` is a client assertion, not trusted time; the Tendermint block records consensus time separately.

## Connect the staged React flow

```tsx
import { ClientDecryptButton } from './crypto/ClientDecryptButton';
import { recordLedgerEvent } from './crypto/ledgerRecorder';

// Pass the other Task 1 props (package, local keys, pinned sender key,
// issuance context) as before. These stay local to the client.
<ClientDecryptButton {...clientProps} recordEvent={recordLedgerEvent} />
```

Use `networkId:'ciphertrail-demo-1'` and the currently committed policy epoch in the issuance context. HTTP login `req.user.id` and `req.user.key_id` must match the event. Validators then independently check their own committed registry and policy. No plaintext, DEK, KEM private key or decapsulated shared secret is sent to this endpoint.

Equivalent Express usage (already mounted after authentication in `server/app.mjs`):

```js
import { TendermintLedger } from './server/ledger-client.mjs';
const ledger = new TendermintLedger('http://127.0.0.1:26657');
const receipt = await ledger.broadcast(eventBytes, signature);
```

Transactions are canonical CBOR `{version:1,event:<exact signed CBOR bytes>,signature:<bytes>}`. Both `CheckTx` and `DeliverTx` verify the native signature and permissions. A failed transaction cannot change state. `Commit` flushes a temporary state file before atomic replacement; `Info` reports persisted height and app hash for Tendermint replay. Separate application files are replica snapshots, not a replacement single-machine audit authority.

The adapter checks both execution results, verifies the returned transaction matches the submitted bytes, and retrieves the transaction proof and signed block commit. On timeout it looks up that exact transaction hash; otherwise it reports an uncertain outcome. Retry the same signed bytes/session. It never treats a mempool acknowledgment as commitment.

## Evidence and limits

The HTTP adapter currently trusts its configured Tendermint RPC endpoint for the receipt and execution status. It fetches proofs but **does not implement an independent light client**. The browser recorder trusts the authenticated API's acknowledgment; a malicious API could falsely acknowledge commitment. For independent offline verification, a verifier must pin the network genesis/validator set, validate the block header and >2/3 commit signatures, validate transaction inclusion, and verify the ML-DSA event against trusted identity history. A JSON file containing its own public key is not sufficient evidence of identity or finality.

ABCI `/session` and `/state` query the latest committed state. Historical state queries and ABCI state proofs deliberately fail rather than return invented proofs. Tendermint retains blocks (`retainHeight:0`). Snapshots/state sync and dynamic validator changes are not implemented. The small-demo application rewrites its public-state snapshot each block; budget disk space and use a proper state backend for larger workloads. Do not call this an unbounded production ledger or assume it fits indefinitely into 1 GB.

Structural watermark detection remains Task 1's exact-PDF profile. This ledger does not make stripped metadata or arbitrary screenshots attributable; Task 3 needs a matching visual embedder and tested extractor.

Protocol references: [Tendermint v0.34.24 ABCI protobuf](https://github.com/tendermint/tendermint/blob/v0.34.24/proto/tendermint/abci/types.proto), [signed-varint socket framing](https://github.com/tendermint/tendermint/blob/v0.34.24/abci/types/messages.go), [release binaries](https://github.com/tendermint/tendermint/releases/tag/v0.34.24).
