import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {PDFDocument} from 'pdf-lib';
import {decode} from 'cborg';
import {ml_dsa65} from '@noble/post-quantum/ml-dsa.js';
import {ml_kem768} from '@noble/post-quantum/ml-kem.js';
import {createApp} from '../server/app.mjs';
import {LedgerApplication,canonical,transactionBytes} from '../ledger/application.mjs';
import {encryptPdfForRecipients,decryptAndMarkPdf,signClientIssuance,digest,toBase64} from '../src/crypto/clientDocument.ts';

test('connected HTTP workflow stores ciphertext, gates policy, signs locally and investigates pixels',async t=>{
  mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(path.resolve('.test-runs/connected-'));
  const authority=ml_dsa65.keygen(),chain=new LedgerApplication(path.join(dir,'application'));
  chain.init({chainId:'connected-test',appStateBytes:Buffer.from(JSON.stringify({networkId:'connected-test',authorityPublicKey:toBase64(authority.publicKey)}))});
  // Deterministic application adapter for HTTP testing; real consensus is covered by test-ledger-live.mjs.
  const ledger={query:async()=>structuredClone(chain.state),broadcast:async(event,signature)=>{
    const tx=transactionBytes(event,signature),check=chain.check(tx);if(check.code)throw new Error(check.log);
    chain.begin({header:{height:chain.state.height+1,chainId:'connected-test'}});const result=chain.deliver(tx);if(result.code)throw new Error(result.log);chain.commit();return {status:'committed',height:String(chain.state.height),txHash:'test-application-receipt'};
  }};
  const instance=createApp({dataDir:path.join(dir,'web'),ledger}),server=instance.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  t.after(()=>{server.close();instance.close();});
  const base='http://127.0.0.1:'+server.address().port+'/api',cookies={},keysets={},accounts=JSON.parse(readFileSync(path.join(dir,'web/initial-accounts.json')));
  async function call(route,{actor='admin',method='GET',body,status=200}={}){
    const multipart=body instanceof FormData;
    const r=await fetch(base+route,{method,headers:{'X-CipherTrail':'1',...(cookies[actor]?{cookie:cookies[actor]}:{}),...(!multipart&&body?{'Content-Type':'application/json'}:{})},body:body?(multipart?body:JSON.stringify(body)):undefined});
    const value=await r.json();assert.equal(r.status,status,JSON.stringify(value));return {r,value};
  }
  for(const account of accounts){const {r}=await call('/login',{method:'POST',body:{id:account.id,password:account.password}});cookies[account.id]=r.headers.get('set-cookie').split(';')[0];}
  for(const actor of ['recipient.a','recipient.b']){
    const kem=ml_kem768.keygen(),dsa=ml_dsa65.keygen();keysets[actor]={kem,dsa};
    const {value}=await call('/keys',{actor,method:'POST',body:{kemPublic:toBase64(kem.publicKey),signPublic:toBase64(dsa.publicKey),proof:toBase64(ml_dsa65.sign(Buffer.from(`CipherTrail/enroll/v1/${actor}/${toBase64(kem.publicKey)}`),dsa.secretKey))}});keysets[actor].keyId=value.keyId;
  }
  async function govern(operation,value){const event=canonical({domain:'CipherTrail/ledger-governance/v1',networkId:'connected-test',sequence:chain.state.sequence+1,operation,value});return call('/client/governance',{method:'POST',body:{eventBytes:toBase64(event),signature:toBase64(ml_dsa65.sign(event,authority.secretKey))}});}
  for(const [id,k] of Object.entries(keysets))await govern('identity',{recipientId:id,keyId:k.keyId,publicKey:k.dsa.publicKey,active:true});
  const sender=ml_dsa65.keygen(),pdf=await PDFDocument.create();pdf.addPage([595,842]).drawText('Connected workflow synthetic document');const source=await pdf.save();
  const pkg=await encryptPdfForRecipients({pdfBytes:source,documentId:'connected-document',filename:'connected.pdf',recipients:Object.entries(keysets).map(([id,k])=>({recipientId:id,keyId:k.keyId,kemPublicKey:k.kem.publicKey})),senderSigningPrivateKey:sender.secretKey});
  const form=()=>{const f=new FormData();f.append('payload',new Blob([pkg.encryptedPayload]),'encrypted.bin');f.append('manifestBytes',toBase64(pkg.manifestBytes));f.append('senderSignature',toBase64(pkg.senderSignature));f.append('senderPublicKey',toBase64(sender.publicKey));return f;};
  await call('/client/documents',{actor:'recipient.a',method:'POST',body:form(),status:403});
  await call('/client/documents',{method:'POST',body:form(),status:201});
  const row=instance.store.db.prepare('SELECT * FROM client_documents').get();assert.equal(Buffer.from(row.ciphertext).includes(Buffer.from(source)),false);assert.equal('wrapped_key' in row,false);
  await call('/client/documents/connected-document/package',{actor:'recipient.a',status:403});
  await govern('document',{documentId:'connected-document',documentVersion:1,policyEpoch:1,packageDigest:await digest(pkg.manifestBytes,'CipherTrail/package/v1'),recipients:['recipient.a','recipient.b']});
  const copies=[];
  for(const [actor,k] of Object.entries(keysets)){
    const {value:p}=await call('/client/documents/connected-document/package',{actor});
    const copy=await decryptAndMarkPdf({package:{encryptedPayload:Buffer.from(p.encryptedPayload,'base64'),manifestBytes:Buffer.from(p.manifestBytes,'base64'),senderSignature:Buffer.from(p.senderSignature,'base64')},recipient:{recipientId:actor,keyId:k.keyId,kemPrivateKey:k.kem.secretKey},trustedSenderPublicKey:sender.publicKey,issuance:{networkId:p.networkId,policyEpoch:p.policyEpoch,sessionId:'connected-'+actor,createdAt:new Date().toISOString()},visualWatermark:true});
    const signed=await signClientIssuance(copy,k.dsa.secretKey,k.dsa.publicKey);
    await call('/ledger/events',{actor,method:'POST',body:{eventBytes:toBase64(signed.eventBytes),signature:toBase64(signed.signature)}});copies.push(copy);
    const {value:w}=await call('/client/workspace',{actor});assert.equal(w.sessions.length,1);assert.equal(w.sessions[0].event.recipientId,actor);
  }
  assert.notEqual(copies[0].event.outputDigest,copies[1].event.outputDigest);
  await call('/client/evidence/connected-recipient.a',{actor:'recipient.b',status:403});
  await call('/client/snapshot',{actor:'recipient.a',status:403});
  const f=new FormData();f.append('artifact',new Blob([copies[0].pdfBytes]),'leak.pdf');f.append('trust',new Blob([JSON.stringify({networkId:'connected-test',identities:[{recipientId:'recipient.a',keyId:keysets['recipient.a'].keyId,publicKey:toBase64(keysets['recipient.a'].dsa.publicKey)}]})]),'trust.json');
  const {value:report}=await call('/client/investigate',{method:'POST',body:f});assert.equal(report.status,'SIGNED_ISSUANCE_MATCH');assert.equal(report.matches[0].recipientId,'recipient.a');assert.equal(report.matches[0].exact_issued_pdf,true);
  await govern('document',{documentId:'connected-document',documentVersion:1,policyEpoch:2,packageDigest:await digest(pkg.manifestBytes,'CipherTrail/package/v1'),recipients:[]});
  await call('/client/documents/connected-document/package',{actor:'recipient.a',status:403});
});
