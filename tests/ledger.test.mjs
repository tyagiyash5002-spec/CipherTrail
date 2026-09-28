import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync } from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { LedgerApplication, canonical, transactionBytes, SUITE } from '../ledger/application.mjs';
import { createAbciServer, Request, Response, frame } from '../ledger/abci-server.mjs';
import { TendermintLedger } from '../server/ledger-client.mjs';

function fixture() {
  mkdirSync('.test-runs',{recursive:true});
  const directory = mkdtempSync(path.resolve('.test-runs/ledger-'));
  const admin = ml_dsa65.keygen(), recipient = ml_dsa65.keygen();
  const app = new LedgerApplication(directory);
  app.init({chainId:'test-chain',appStateBytes:Buffer.from(JSON.stringify({networkId:'test-chain',authorityPublicKey:Buffer.from(admin.publicKey).toString('base64')}))});
  const tx = (event,key=recipient) => { const bytes = canonical(event); return transactionBytes(bytes,ml_dsa65.sign(bytes,key.secretKey)); };
  const govern = (sequence,operation,value) => tx({domain:'CipherTrail/ledger-governance/v1',networkId:'test-chain',sequence,operation,value},admin);
  const identity = govern(1,'identity',{recipientId:'alice',keyId:'alice-key',publicKey:recipient.publicKey,active:true});
  const document = govern(2,'document',{documentId:'doc',documentVersion:1,policyEpoch:1,packageDigest:'a'.repeat(96),recipients:['alice']});
  const event = {domain:'CipherTrail/client-issuance/v1',suite:SUITE,networkId:'test-chain',sessionId:'session-1',documentId:'doc',documentVersion:1,recipientId:'alice',keyId:'alice-key',policyEpoch:1,createdAt:'2026-09-27T12:00:00.000Z',packageDigest:'a'.repeat(96),outputDigest:'b'.repeat(96),watermarkProfile:'structural-client-v1'};
  return {app,directory,admin,recipient,tx,govern,identity,document,event};
}
function block(app,txs) {
  app.begin({header:{height:app.state.height+1,chainId:'test-chain'}});
  for (const tx of txs) assert.equal(app.deliver(tx).code,0);
  return app.commit();
}
test('native signature verification, authorization, replay and persistence',()=>{
  const f = fixture();
  assert.equal(f.app.check(f.tx(f.event)).code,1);
  assert.equal(f.app.check(f.identity).code,0);
  assert.equal(f.app.state.sequence,0,'CheckTx must not mutate state');
  block(f.app,[f.identity,f.document]);
  assert.equal(f.app.check(f.tx(f.event)).code,0);
  for (const changed of [{networkId:'other'},{keyId:'other'},{policyEpoch:2},{packageDigest:'c'.repeat(96)},{recipientId:'mallory'}])
    assert.equal(f.app.check(f.tx({...f.event,...changed})).code,1);
  assert.equal(f.app.check(f.tx(f.event,f.admin)).code,1);
  const tampered = f.tx(f.event); tampered[tampered.length-1]^=1;
  assert.equal(f.app.check(tampered).code,1);
  const committed = block(f.app,[f.tx(f.event)]);
  assert.equal(f.app.check(f.tx(f.event)).code,1);
  const restored = new LedgerApplication(f.directory);
  assert.deepEqual(restored.info().lastBlockAppHash,committed.data);
  assert.equal(restored.query({path:'/session',data:Buffer.from('session-1')}).code,0);
  assert.equal(restored.query({path:'/session',data:Buffer.from('session-1'),prove:true}).code,1);
  assert.equal(restored.query({path:'/session',data:Buffer.from('missing')}).code,1);
});
test('replicas produce identical application hashes and reject revoked identities',()=>{
  const f = fixture(), g = fixture();
  g.app.state = structuredClone(f.app.state);
  const transactions = [f.identity,f.document,f.tx(f.event)];
  assert.deepEqual(block(f.app,transactions).data,block(g.app,transactions).data);
  const revoke = f.govern(3,'identity',{recipientId:'alice',keyId:'alice-key',publicKey:f.recipient.publicKey,active:false});
  block(f.app,[revoke]);
  assert.equal(f.app.check(f.tx({...f.event,sessionId:'session-2'})).code,1);
});
test('uncommitted state is not visible to queries or crash recovery',()=>{
  const f = fixture();
  f.app.begin({header:{height:1,chainId:'test-chain'}});
  assert.equal(f.app.deliver(f.identity).code,0);
  assert.equal(f.app.state.sequence,0);
  assert.equal(new LedgerApplication(f.directory).state.sequence,0);
});
test('ABCI socket handles split frames and multiple ordered messages',async t=>{
  const f=fixture(),server=createAbciServer(f.app);
  server.listen(0,'127.0.0.1'); await new Promise(r=>server.once('listening',r));
  const client=net.connect(server.address().port,'127.0.0.1');
  await new Promise(r=>client.once('connect',r));
  t.after(()=>{client.destroy();server.close();});
  const responses=[];
  let received=Buffer.alloc(0);
  const done=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('socket timeout')),3000);
    client.on('data',chunk=>{
      received=Buffer.concat([received,chunk]);
      while(received.length){
        try {
          // Both test response frames fit in a one-byte length prefix.
          const size=received[0]/2;
          if(received.length<size+1) break;
          responses.push(Response.decode(received.subarray(1,size+1)));
          received=received.subarray(size+1);
        } catch(error){clearTimeout(timer);reject(error);return;}
      }
      if(responses.length===2){clearTimeout(timer);resolve();}
    });
  });
  const bytes=Buffer.concat([frame(Request,{echo:{message:'split'}}),frame(Request,{flush:{}})]);
  client.write(bytes.subarray(0,1));
  await new Promise(r=>setTimeout(r,10));
  client.write(bytes.subarray(1));
  await done;
  assert.equal(responses[0].echo.message,'split'); assert.ok(responses[1].flush);
});
test('Express adapter fails closed on rejection and uncertain outcomes',async()=>{
  const f=fixture(),bytes=canonical(f.event),sig=ml_dsa65.sign(bytes,f.recipient.secretKey);
  const ledger=new TendermintLedger();
  ledger.rpc=async method=>{if(method==='broadcast_tx_commit')return {check_tx:{code:1,log:'denied'}};throw new Error('not found');};
  await assert.rejects(ledger.broadcast(bytes,sig),/denied/);
  ledger.rpc=async()=>{throw new Error('timeout');};
  await assert.rejects(ledger.broadcast(bytes,sig),/unconfirmed/);
  ledger.rpc=async method=>{if(method==='broadcast_tx_commit')return {check_tx:{code:0},deliver_tx:{code:1,log:'revoked'}};throw new Error('not found');};
  await assert.rejects(ledger.broadcast(bytes,sig),/revoked/);
});
test('receipt lookup tolerates Tendermint indexing delay',async()=>{
  const f=fixture(),tx=f.tx(f.event);
  const {txHash}=await import('../ledger/application.mjs');
  const hash=txHash(tx),ledger=new TendermintLedger();
  let attempts=0;
  ledger.rpc=async method=>{
    if(method==='commit') return {signed_header:{}};
    if(++attempts<3) throw new Error('tx not found');
    return {hash,tx:tx.toString('base64'),height:'1',tx_result:{code:0},proof:{}};
  };
  assert.equal((await ledger.receipt(hash,tx)).status,'committed');
  assert.equal(attempts,3);
});
