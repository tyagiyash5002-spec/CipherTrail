import { decode } from 'cborg';
import { transactionBytes, txHash, unpack } from '../ledger/application.mjs';

export class TendermintLedger {
  constructor(url = process.env.TENDERMINT_RPC || 'http://127.0.0.1:26657') { this.url = url; }
  async rpc(method,params = {}) {
    const response = await fetch(this.url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(20000)});
    if (!response.ok) throw new Error(`Ledger HTTP ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(body.error.data || body.error.message);
    if (!body.result) throw new Error('Missing Tendermint response');
    return body.result;
  }
  async query(path,key = '') {
    const {response:r} = await this.rpc('abci_query',{path,data:Buffer.from(key).toString('hex'),prove:false});
    if (r.code) throw new Error(r.log || 'Ledger query rejected');
    return decode(Buffer.from(r.value,'base64'));
  }
  async broadcast(eventBytes,signature) {
    const tx = transactionBytes(eventBytes,signature);
    unpack(tx); // Validate framing before spending network resources.
    const expectedHash = txHash(tx);
    let result;
    try { result = await this.rpc('broadcast_tx_commit',{tx:tx.toString('base64')}); }
    catch (error) {
      // A timed out submission may have committed. Resolve only by exact tx hash.
      try { return await this.receipt(expectedHash,tx); }
      catch { throw new Error(`Ledger outcome unconfirmed; retry the same signed event. ${error.message}`); }
    }
    if (result.check_tx?.code || result.deliver_tx?.code) {
      // An exact retry can be rejected as replay after an earlier successful commit.
      try { return await this.receipt(expectedHash,tx); }
      catch { throw new Error(result.check_tx?.log || result.deliver_tx?.log || 'Transaction rejected'); }
    }
    if (result.hash?.toUpperCase() !== expectedHash || Number(result.height) < 1 || !result.deliver_tx) throw new Error('Invalid commit acknowledgment');
    return this.receipt(expectedHash,tx);
  }
  async receipt(hash,expectedTx) {
    let record;
    for (let attempt=0;attempt<10;attempt++) {
      try { record = await this.rpc('tx',{hash:Buffer.from(hash,'hex').toString('base64'),prove:true}); break; }
      catch(error) {
        if (attempt===9 || !/not found/i.test(error.message)) throw error;
        await new Promise(resolve=>setTimeout(resolve,150));
      }
    }
    if (record.tx_result?.code || record.hash?.toUpperCase() !== hash || !Buffer.from(record.tx || '', 'base64').equals(expectedTx) || Number(record.height) < 1 || !record.proof) throw new Error('No matching successful committed transaction');
    const commit = await this.rpc('commit',{height:record.height});
    return {status:'committed',txHash:hash,height:record.height,transaction:record,commit};
  }
}
