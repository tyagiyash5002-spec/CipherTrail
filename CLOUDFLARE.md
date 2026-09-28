# Share CipherTrail with Cloudflare

Cloudflare Quick Tunnel gives this application a temporary public HTTPS address. Participants on different networks can use the same application, log in with separate accounts, request marked PDFs, and transfer downloaded PDFs for a leak demonstration.

## Start sharing

Cloudflared is already installed on this computer. From PowerShell:

```powershell
cd 'C:\Users\tyagi\Downloads\New folder\ciphertrail-ui'
npm run build
npm run share
```

Keep the terminal open. It starts a dedicated origin on loopback port 3002 with HTTPS-only session cookies, then connects Cloudflare. It prints an address such as `https://random-words.trycloudflare.com`. Share the actual printed address with your participants. It is also saved temporarily to `data/share-url.txt`.

The existing local server on port 3001 may remain running. Both use the same data directory. Sign in through the HTTPS tunnel URL when using sharing mode.

Give Recipient A only the `recipient.a` password and Recipient B only the `recipient.b` password from `data/initial-accounts.json`. Keep the administrator password private. Each recipient creates or loads their own private key file on their own computer. The app's server-side permissions still protect uploads, issuance, investigation and evidence endpoints.

Use the walkthrough in [WORKING-DEMO.md](WORKING-DEMO.md) to upload a sample PDF, deny access, grant access, issue marked copies and investigate them. Refresh polling runs every ten seconds; participants can also select Refresh.

## Stop or restart

Press Ctrl+C in the sharing terminal. This stops the tunnel and its dedicated origin; it does not delete accounts, documents or evidence. Restart with `npm run share`. A new Quick Tunnel gets a different public address, so send participants the new link and have them sign in again. Registered key files and stored documents remain valid.

The server computer must stay awake, online and running for the link to work. Cloudflare routes HTTPS traffic to the application; it does not move the database or encrypted files into Cloudflare storage. Local storage limits still apply. Internet access is required, so this is not the air-gapped demonstration mode.

## Troubleshooting

- If port 3002 is occupied, stop the previous sharing session or set `SHARE_PORT` to an unused local port.
- If cloudflared is elsewhere, set `CLOUDFLARED_PATH` to its executable path.
- If the interface has changed, run `npm run build` before sharing.
- Check `data/cloudflare.log` if the connection fails. Corporate networks may block outbound tunnel connections.
- Cloudflare documents that a `.cloudflared/config.yaml` file can conflict with Quick Tunnels. Do not overwrite an existing tunnel configuration; use a separate named tunnel if necessary.
- A Quick Tunnel can take a short time to connect after printing its hostname. Wait for `Cloudflare connection established` and retry the link.

## Stable URL later

For a stable address, configure a named Cloudflare Tunnel and a hostname in your Cloudflare account, pointing its HTTP service to `http://127.0.0.1:3002`. Run the application with `COOKIE_SECURE=true` and `HOST=127.0.0.1`. Keep tunnel credentials outside source control. An always-on host is still needed if the application must work when this computer is off.

Quick Tunnels are for testing: Cloudflare provides no uptime SLA, currently limits them to 200 concurrent in-flight requests, and does not support SSE. This app uses ordinary HTTP requests and polling.

Official documentation: [Cloudflare Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).
