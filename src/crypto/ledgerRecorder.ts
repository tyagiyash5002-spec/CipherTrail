import { toBase64, type SignedClientEvent } from './clientDocument';

/** Adapter for ClientDecryptButton.recordEvent. Requires a trusted HTTPS API.
 * A full RPC receipt is returned by the server; this is not a browser light client.
 */
export async function recordLedgerEvent(event: SignedClientEvent): Promise<void> {
  const response = await fetch('/api/ledger/events', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type':'application/json','X-CipherTrail':'1'},
    body: JSON.stringify({eventBytes:toBase64(event.eventBytes),signature:toBase64(event.signature)}),
  });
  const result = await response.json();
  if (!response.ok || result.status !== 'committed' || !result.txHash || Number(result.height) < 1)
    throw new Error(result.error || 'Ledger commitment was not confirmed.');
}
