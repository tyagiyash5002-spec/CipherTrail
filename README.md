# CipherTrail working demo

The working application supports separate accounts, SRS-profile post-quantum encryption and signing, recipient-specific PDF copies, and exact-copy leak investigation.

See [WORKING-DEMO.md](WORKING-DEMO.md) for startup, account setup, the three-computer presentation walkthrough, technology mapping, deployment, tests, and limitations.

For participants on different networks, run `npm run share`. See [CLOUDFLARE.md](CLOUDFLARE.md) for the public HTTPS sharing setup.

The visual watermark and offline forensic CLI are documented in [FORENSICS.md](FORENSICS.md), with synthetic PDF and signed-record fixtures under `samples/forensics`.

Quick start with Node.js 24: `npm run build`, then `npm start`. Open http://localhost:3001. Initial account passwords are in the private `data/initial-accounts.json` file created at first startup.

The existing pages use structural PDF marks and a local signed audit. The new client-only crypto modules are documented in [CLIENT-CRYPTO.md](CLIENT-CRYPTO.md), and the working three-validator Tendermint service and Express adapter in [LEDGER.md](LEDGER.md). These new modules are not yet connected to the existing pages. The previous simulated UI remains in source; its documentation is [UI-DEMO-ARCHIVE.md](UI-DEMO-ARCHIVE.md).
