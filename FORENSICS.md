# Task 3: offline visual forensic demonstration

Implemented components:

- `src/crypto/visualWatermark.ts`: browser-compatible DCT carrier generator and PDF footer embedder. No server plaintext or image-generation service.
- `forensic_extractor.py`: PDF/PNG/JPEG CLI, perspective alignment, OpenCV DCT extraction, offline signed-record matching, JSON Forensic Attribution Report.
- `forensics/verify-record.mjs`: native Node/OpenSSL ML-DSA-65 verification of the exact canonical CBOR event, against an independently supplied public key.
- `forensics/export-ledger.mjs`: exports signed events from the real Tendermint ABCI state; the extractor also accepts a mock JSON snapshot.

## Try the prepared offline demo

Run from the project directory. Node 24.7–24.x and the project's npm dependencies are required, including for signature verification. The Python CLI invokes the fixed local Node verification helper without a shell. No network is used in snapshot mode.

The isolated Python environment is already installed here. On a clean machine:

```powershell
python -m venv .venv-forensics
./.venv-forensics/Scripts/python.exe -m pip install -r forensics/requirements.txt
npm ci
```

The synthetic fixtures are in `samples/forensics`. They contain no private keys. `snapshot.json` is explicitly a mock signed-record file, not a fabricated blockchain proof. To regenerate them, run `node scripts/make-forensic-demo.mjs`; this changes the demo public key and signature.

```powershell
./.venv-forensics/Scripts/python.exe forensic_extractor.py samples/forensics/marked.pdf --snapshot samples/forensics/snapshot.json --trust samples/forensics/trusted-identities.json

# Generate screenshot/alteration fixtures and test them.
./.venv-forensics/Scripts/python.exe tests/forensics_test.py

./.venv-forensics/Scripts/python.exe forensic_extractor.py .test-runs/forensics/screenshot.png --snapshot samples/forensics/snapshot.json --trust samples/forensics/trusted-identities.json --output .test-runs/forensics/report.json
```

Expected `status`: `SIGNED_ISSUANCE_MATCH`. For the original PDF, `exact_issued_pdf` is true; for a screenshot, re-encoded image or raster-only PDF it is false. `INCONCLUSIVE` means no intact marker or no unique trusted signed record. Exit codes: 0 match, 2 inconclusive, 3 input/processing error. Matching means a signed issuance association, not proof of who leaked a file.

## Connect to Task 1 and Task 2

```tsx
<ClientDecryptButton
  {...clientProps}
  visualWatermark={true}
  recordEvent={recordLedgerEvent}
/>
```

Or pass `visualWatermark:true` directly to `decryptAndMarkPdf`. The function embeds the visual footer **before** calculating and signing the output digest. The signed profile becomes `dct-footer-v1`; the ledger accepts this profile alongside `structural-client-v1`. All validators need this version of the application. Restart them together for this demo upgrade. The existing legacy pages are still not wired to these staged client components.

To exercise real consensus and export an offline snapshot:

```powershell
# Keep npm run ledger:start running in a separate terminal.
$env:VISUAL_WATERMARK='1'
node scripts/test-ledger-live.mjs
node forensics/export-ledger.mjs .test-runs/live-ledger/snapshot.json
./.venv-forensics/Scripts/python.exe forensic_extractor.py .test-runs/live-ledger/marked.pdf --snapshot .test-runs/live-ledger/snapshot.json --trust .test-runs/live-ledger/trusted-identities.json
```

Explicit online lookup is also supported:

```powershell
./.venv-forensics/Scripts/python.exe forensic_extractor.py .test-runs/live-ledger/marked.pdf --ledger http://127.0.0.1:26657 --trust .test-runs/live-ledger/trusted-identities.json
```

The integration script creates a synthetic recipient locally and writes its public trust fixture separately from the ledger snapshot. For real users, obtain the trust file through an independently authenticated registration process. Do not trust public keys supplied by the leaked document or an arbitrary snapshot. A trusted registry looks like:

```json
{"networkId":"ciphertrail-demo-1","identities":[{"recipientId":"recipient.a","keyId":"registered-key-id","publicKey":"BASE64_ML_DSA_65_PUBLIC_KEY"}]}
```

The report verifies the event's signature, network, identity and key binding. It **does not verify Tendermint consensus proofs or historical governance**, so it explicitly reports `ledger_finality: NOT_INDEPENDENTLY_VERIFIED`. Offline BFT proof verification remains separate work; a signed record alone is not evidence of a quorum commit.

## Pixel format and measured behavior

Each 280px tile has a black registration border and a pale 256px carrier. The carrier represents a 16×16 grid of 8×8 blocks at 2× pixel scale. Each bit changes the difference between DCT coefficients `(3,2)` and `(2,3)` by approximately ±90. These mid-frequency AC coefficients are a deliberate compromise for JPEG survival; the highest frequencies disappear quickly under compression.

The 32-byte payload is `CTV1` + 16-byte session token + 4-byte SHA-256 checksum + 8 repeated header bytes. The token is the first 16 bytes of SHA-256 over UTF-8 `CipherTrail/visual/v1\0<networkId>\0<sessionId>`. The ledger lookup resolves that token to the full signed Session ID. The checksum rejects damaged extraction; it is not an authenticity mechanism. ML-DSA supplies record authenticity. There is repetition across two tiles per page, but no error-correction code within each tile.

The footer adds 160pt to each page and draws the tiles at 140pt each without covering source content. This profile rejects rotated, cropped, narrow (<310pt), annotated or form-bearing pages rather than silently damage their layout. It retains vector text. The black frames and faint texture are visible; the encoded ID is not ordinary readable text or a QR code.

Tests cover a PDF render at 144dpi, PNG, JPEG quality 65, 75% resizing, 90° rotation, a synthetic perspective warp, and a raster-only PDF with no structural marker. Unmarked images, cropped-away footers, tampered signatures and wrong trusted identities are tested as inconclusive. These are controlled synthetic tests, not a measured guarantee for arbitrary cameras, glare, blur, severe compression or every document.

At least one complete, sufficiently resolved tile must survive. Cropping both footers defeats this profile. A copied/transplanted tile can associate unrelated pixels with a legitimate issuance, which is why the report distinguishes exact output-digest equality from visual-token association. A recipient controlling their browser can also bypass local marking. This demo cannot promise airtight leak attribution against those attacks.

Offline detection can be run on a disconnected machine with the CLI, Node dependencies, Python environment, trusted registry and signed snapshot copied in advance. It detects supplied evidence; it does not automatically discover leaked files on other computers.
