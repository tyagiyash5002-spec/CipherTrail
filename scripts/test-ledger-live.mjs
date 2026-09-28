import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { canonical } from '../ledger/application.mjs';
import { TendermintLedger } from '../server/ledger-client.mjs';
import { encryptPdfForRecipients, decryptAndMarkPdf, signClientIssuance, digest } from '../src/crypto/clientDocument.ts';

const home=path.resolve(process.env.LEDGER_HOME || 'data/ledger');
const network=JSON.parse(readFileSync(path.join(home,'network.json'),'utf8'));
const authority=JSON.parse(readFileSync(path.join(home,'governance-PRIVATE-keys.json'),'utf8'));
const ledgers=network.nodes.map(n=>new TendermintLedger(`http://127.0.0.1:${n.rpc}`));
const ledger=ledgers[0],state=await ledger.query('/state');
let sequence=state.sequence;
async function govern(operation,value) {
  const bytes=canonical({domain:'CipherTrail/ledger-governance/v1',networkId:network.networkId,sequence:++sequence,operation,value});
  return ledger.broadcast(bytes,ml_dsa65.sign(bytes,Buffer.from(authority.secretKey,'base64')));
}
const recipientId='test-'+randomUUID(),documentId=randomUUID(),keyId=randomUUID();
const kem=ml_kem768.keygen(),recipient=ml_dsa65.keygen(),sender=ml_dsa65.keygen();
await govern('identity',{recipientId,keyId,publicKey:recipient.publicKey,active:true});
const pdf=await PDFDocument.create();pdf.addPage().drawText('Client-encrypted three-validator integration test');
const pkg=await encryptPdfForRecipients({pdfBytes:await pdf.save(),documentId,filename:'ledger-test.pdf',recipients:[{recipientId,keyId,kemPublicKey:kem.publicKey}],senderSigningPrivateKey:sender.secretKey});
await govern('document',{documentId,documentVersion:1,policyEpoch:1,packageDigest:await digest(pkg.manifestBytes,'CipherTrail/package/v1'),recipients:[recipientId]});
const copy=await decryptAndMarkPdf({package:pkg,recipient:{recipientId,keyId,kemPrivateKey:kem.secretKey},trustedSenderPublicKey:sender.publicKey,issuance:{networkId:network.networkId,sessionId:randomUUID(),policyEpoch:1,createdAt:new Date().toISOString()},visualWatermark:process.env.VISUAL_WATERMARK==='1'});
const signed=await signClientIssuance(copy,recipient.secretKey,recipient.publicKey);
const receipt=await ledger.broadcast(signed.eventBytes,signed.signature);
assert.equal(receipt.status,'committed');
const retry=await ledger.broadcast(signed.eventBytes,signed.signature);
assert.equal(retry.txHash,receipt.txHash);
for(const peer of ledgers) {
  let record;
  for(let attempt=0;attempt<20;attempt++) {
    try {record=await peer.query('/session',copy.event.sessionId);break;}catch{await new Promise(r=>setTimeout(r,200));}
  }
  assert.ok(record,'All replicas must expose the committed session');
  assert.equal(record.txHash,receipt.txHash);
  assert.deepEqual(Buffer.from(record.event),Buffer.from(signed.eventBytes));
}
const bad=signed.signature.slice();bad[0]^=1;
await assert.rejects(ledger.broadcast(signed.eventBytes,bad));
const output=path.resolve('.test-runs/live-ledger');mkdirSync(output,{recursive:true});
writeFileSync(path.join(output,'marked.pdf'),copy.pdfBytes);
writeFileSync(path.join(output,'receipt.json'),JSON.stringify(receipt,null,2));
writeFileSync(path.join(output,'signed-event.json'),JSON.stringify({eventBytes:Buffer.from(signed.eventBytes).toString('base64'),signature:Buffer.from(signed.signature).toString('base64'),publicKey:Buffer.from(recipient.publicKey).toString('base64')},null,2));
writeFileSync(path.join(output,'trusted-identities.json'),JSON.stringify({networkId:network.networkId,identities:[{recipientId,keyId,publicKey:Buffer.from(recipient.publicKey).toString('base64')}]},null,2));
console.log(JSON.stringify({validators:ledgers.length,sessionId:copy.event.sessionId,txHash:receipt.txHash,height:receipt.height,idempotentRetry:true,allReplicasVerified:true,artifacts:output},null,2));
