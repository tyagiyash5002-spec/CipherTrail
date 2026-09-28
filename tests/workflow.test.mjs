import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync,readdirSync} from 'node:fs';
import path from 'node:path';
import {randomBytes,randomUUID,createPublicKey,verify as nodeVerify,generateKeyPairSync,encapsulate,decapsulate} from 'node:crypto';
import {PDFDocument,PDFName,PDFHexString} from 'pdf-lib';
import {ml_kem768} from '@noble/post-quantum/ml-kem.js';
import {ml_dsa65} from '@noble/post-quantum/ml-dsa.js';
import {createApp} from '../server/app.mjs';
import {b64,from64,hash,canonical,verify} from '../server/crypto.mjs';
import {verifyEvidence} from '../scripts/verify-evidence.mjs';

test('SRS algorithms interoperate with Node OpenSSL implementations',()=>{
  const message=Buffer.from('CipherTrail interoperability test'),dsa=ml_dsa65.keygen();
  // RFC 9881 ML-DSA-65 SubjectPublicKeyInfo, absent algorithm parameters.
  const spki=Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100','hex'),Buffer.from(dsa.publicKey)]);
  const publicKey=createPublicKey({key:spki,format:'der',type:'spki'});
  const signature=ml_dsa65.sign(message,dsa.secretKey);
  assert.equal(nodeVerify(null,message,publicKey,signature),true);
  const bad=Buffer.from(signature);bad[0]^=1;assert.equal(nodeVerify(null,message,publicKey,bad),false);
  const kem=ml_kem768.keygen();
  const kemSpki=Buffer.concat([Buffer.from('308204b2300b0609608648016503040402038204a100','hex'),Buffer.from(kem.publicKey)]);
  const nativeEncapsulation=encapsulate(createPublicKey({key:kemSpki,format:'der',type:'spki'}));
  assert.deepEqual(Buffer.from(ml_kem768.decapsulate(nativeEncapsulation.ciphertext,kem.secretKey)),nativeEncapsulation.sharedKey);
  const nativeKeys=generateKeyPairSync('ml-kem-768');
  const rawPublic=nativeKeys.publicKey.export({format:'der',type:'spki'}).subarray(-1184);
  const nobleEncapsulation=ml_kem768.encapsulate(rawPublic);
  assert.deepEqual(decapsulate(nativeKeys.privateKey,Buffer.from(nobleEncapsulation.cipherText)),Buffer.from(nobleEncapsulation.sharedSecret));
});

test('three-account workflow, permissions, signatures, forensics, persistence and failure cases',async t=>{
  const parent=path.resolve('.test-runs');mkdirSync(parent,{recursive:true});const dataDir=mkdtempSync(path.join(parent,'workflow-'));
  let instance=createApp({dataDir}),server=instance.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  let base=`http://127.0.0.1:${server.address().port}`;
  t.after(async()=>{await new Promise(r=>server.close(r));instance.close();});
  const accounts=JSON.parse(readFileSync(path.join(dataDir,'initial-accounts.json'),'utf8'));
  const cookies={};
  async function call(route,{actor,method='GET',body,expected=200,binary=false,header=true}={}) {
    const multipart=body instanceof FormData;
    const res=await fetch(base+'/api'+route,{method,headers:{...(header?{'X-CipherTrail':'1'}:{}),...(actor?{cookie:cookies[actor]}:{}),...(!multipart&&body?{'Content-Type':'application/json'}:{})},body:body?(multipart?body:JSON.stringify(body)):undefined});
    const value=binary?Buffer.from(await res.arrayBuffer()):await res.json();
    assert.equal(res.status,expected,`${method} ${route}: ${JSON.stringify(value)}`);
    return {value,res};
  }
  async function login(actor) {const account=accounts.find(a=>a.id===actor);const {res}=await call('/login',{method:'POST',body:{id:actor,password:account.password}});cookies[actor]=res.headers.get('set-cookie').split(';')[0];}
  const keysets={};
  async function enroll(actor) {const kem=ml_kem768.keygen(),dsa=ml_dsa65.keygen();keysets[actor]={kem,dsa};await call('/keys',{actor,method:'POST',body:{kemPublic:b64(kem.publicKey),signPublic:b64(dsa.publicKey),proof:b64(ml_dsa65.sign(Buffer.from(`CipherTrail/enroll/v1/${actor}/${b64(kem.publicKey)}`),dsa.secretKey))}});}
  const source=await PDFDocument.create();source.addPage().drawText('Synthetic CipherTrail integration test');const pdf=Buffer.from(await source.save());
  function form(bytes=pdf,recipients) {const body=new FormData();body.append('file',new Blob([bytes],{type:'application/pdf'}),'test.pdf');if(recipients)body.append('recipients',JSON.stringify(recipients));return body;}
  let docId,first,firstOutput,bOutput;
  async function prepare(actor,requestId=randomUUID().replaceAll('-','')) {const {value:envelope}=await call(`/documents/${docId}/envelope`,{actor});const secret=ml_kem768.decapsulate(from64(envelope.cipherText),keysets[actor].kem.secretKey);return (await call(`/documents/${docId}/prepare`,{actor,method:'POST',body:{requestId,sharedSecret:b64(secret)}})).value;}
  async function release(actor,row) {return (await call(`/issuances/${row.id}/release`,{actor,method:'POST',body:{signature:b64(ml_dsa65.sign(from64(row.event),keysets[actor].dsa.secretKey))},binary:true})).value;}
  await t.test('authentication, request protection and distinct recipient-owned public keys',async()=>{
    await call('/documents',{expected:401});
    await call('/login',{method:'POST',header:false,body:{id:'admin',password:'wrong'},expected:403});
    await call('/login',{method:'POST',body:{id:'admin',password:'wrong'},expected:401});
    for(const a of accounts)await login(a.id);
    await enroll('recipient.a');await enroll('recipient.b');
    await call('/users',{actor:'recipient.a',expected:403});
    await call('/documents',{actor:'recipient.a',method:'POST',body:form(),expected:403});
  });
  await t.test('one encrypted master, sender signature and authorization denial',async()=>{
    const {value}=await call('/documents',{actor:'admin',method:'POST',body:form(pdf,['recipient.a']),expected:201});docId=value.id;
    const ciphertext=readFileSync(path.join(dataDir,'documents',docId+'.enc'));
    assert.equal(ciphertext.subarray(0,5).toString()==='%PDF-',false);assert.equal(ciphertext.includes(pdf),false);
    assert.equal(readdirSync(path.join(dataDir,'documents')).length,1);
    const doc=instance.store.db.prepare('SELECT * FROM documents WHERE id=?').get(docId);
    assert.equal(verify(Buffer.from(doc.manifest),Buffer.from(doc.signature),from64(instance.store.sender.publicKey)),true);
    await call(`/documents/${docId}/envelope`,{actor:'recipient.b',expected:403});
    await call(`/documents/${docId}/prepare`,{actor:'recipient.b',method:'POST',body:{requestId:randomUUID()},expected:403});
    await call('/documents',{actor:'admin',method:'POST',body:form(Buffer.from('not a pdf'),[]),expected:422});
  });
  await t.test('wrong key and forged signature cannot release a PDF',async()=>{
    await call(`/documents/${docId}/prepare`,{actor:'recipient.a',method:'POST',body:{requestId:randomUUID(),sharedSecret:b64(randomBytes(32))},expected:403});
    first=await prepare('recipient.a');
    const sig=ml_dsa65.sign(from64(first.event),keysets['recipient.b'].dsa.secretKey);
    await call(`/issuances/${first.id}/release`,{actor:'recipient.a',method:'POST',body:{signature:b64(sig)},expected:403});
    await call(`/issuances/${first.id}/evidence`,{actor:'recipient.b',expected:404});
    firstOutput=await release('recipient.a',first);assert.equal(firstOutput.subarray(0,5).toString(),'%PDF-');
    assert.equal(hash(firstOutput),first.summary.outputDigest);
  });
  await t.test('retries preserve bytes; fresh sessions have distinct marks',async()=>{
    assert.deepEqual(await release('recipient.a',first),firstOutput);
    const next=await prepare('recipient.a');const output=await release('recipient.a',next);
    assert.notEqual(hash(output),hash(firstOutput));
    assert.equal((await PDFDocument.load(output)).getPageCount(),1);
    const declined=await prepare('recipient.a');await call(`/issuances/${declined.id}/cancel`,{actor:'recipient.a',method:'POST'});
    await call(`/issuances/${declined.id}/release`,{actor:'recipient.a',method:'POST',body:{signature:b64(ml_dsa65.sign(from64(declined.event),keysets['recipient.a'].dsa.secretKey))},expected:409});
  });
  await t.test('simultaneous transport retries produce one event and identical output',async()=>{
    const requestId=randomUUID().replaceAll('-','');
    const [a,b]=await Promise.all([prepare('recipient.a',requestId),prepare('recipient.a',requestId)]);
    assert.equal(a.id,b.id);assert.equal(a.event,b.event);
    const [one,two]=await Promise.all([release('recipient.a',a),release('recipient.a',b)]);
    assert.deepEqual(one,two);
    const count=instance.store.db.prepare("SELECT COUNT(*) AS n FROM audit WHERE payload LIKE ? AND payload LIKE '%COPY_ISSUED%'").get('%'+a.id+'%').n;
    assert.equal(count,1);
  });
  await t.test('grant B and identify both original issued copies',async()=>{
    await call(`/documents/${docId}/permissions`,{actor:'admin',method:'PUT',body:{recipients:['recipient.a','recipient.b']}});
    const prepared=await prepare('recipient.b');bOutput=await release('recipient.b',prepared);assert.notEqual(hash(firstOutput),hash(bOutput));
    for(const [actor,bytes]of [['recipient.a',firstOutput],['recipient.b',bOutput]]){
      const {value}=await call('/investigate',{actor:'admin',method:'POST',body:form(bytes)});
      assert.equal(value.classification,'EXACT_ISSUED_COPY');assert.equal(value.recipientId,actor);assert.equal(value.ledgerFinality,false);
      const result=verifyEvidence(value.evidence,bytes,b64(keysets[actor].dsa.publicKey));assert.equal(result.valid,true);
      const bad=structuredClone(value.evidence);bad.event=b64(Buffer.from('altered'));
      assert.throws(()=>verifyEvidence(bad,bytes));
    }
  });
  await t.test('edited/foreign PDFs stay inconclusive; investigation is admin-only',async()=>{
    await call('/investigate',{actor:'recipient.a',method:'POST',body:form(firstOutput),expected:403});
    const modified=await PDFDocument.load(firstOutput);modified.setTitle('Edited copy');const edited=Buffer.from(await modified.save());
    assert.equal((await call('/investigate',{actor:'admin',method:'POST',body:form(edited)})).value.classification,'INCONCLUSIVE');
    assert.equal((await call('/investigate',{actor:'admin',method:'POST',body:form(pdf)})).value.classification,'INCONCLUSIVE');
  });
  await t.test('revocation invalidates prepared sessions and future issuance',async()=>{
    const pending=await prepare('recipient.a');
    await call(`/documents/${docId}/permissions`,{actor:'admin',method:'PUT',body:{recipients:['recipient.b']}});
    await call(`/issuances/${pending.id}/release`,{actor:'recipient.a',method:'POST',body:{signature:b64(ml_dsa65.sign(from64(pending.event),keysets['recipient.a'].dsa.secretKey))},expected:403});
    await call(`/documents/${docId}/envelope`,{actor:'recipient.a',expected:403});
  });
  await t.test('expired unsigned sessions fail closed',async()=>{
    const pending=await prepare('recipient.b');
    instance.store.db.prepare('UPDATE issuances SET created_at=? WHERE id=?').run('2020-01-01T00:00:00.000Z',pending.id);
    await call(`/issuances/${pending.id}/prepared`,{actor:'recipient.b',expected:409});
    await call(`/issuances/${pending.id}/release`,{actor:'recipient.b',method:'POST',body:{signature:b64(ml_dsa65.sign(from64(pending.event),keysets['recipient.b'].dsa.secretKey))},expected:409});
  });
  await t.test('ciphertext and local audit tampering block release',async()=>{
    const file=path.join(dataDir,'documents',docId+'.enc'),original=readFileSync(file),bad=Buffer.from(original);bad[40]^=1;writeFileSync(file,bad);
    await call(`/documents/${docId}/envelope`,{actor:'recipient.b',expected:409});writeFileSync(file,original);
    const pending=await prepare('recipient.b'),db=instance.store.db,row=db.prepare('SELECT * FROM audit LIMIT 1').get();
    db.prepare('UPDATE audit SET payload=? WHERE seq=?').run('{}',row.seq);
    await call(`/issuances/${pending.id}/release`,{actor:'recipient.b',method:'POST',body:{signature:b64(ml_dsa65.sign(from64(pending.event),keysets['recipient.b'].dsa.secretKey))},expected:409});
    db.prepare('UPDATE audit SET payload=? WHERE seq=?').run(row.payload,row.seq);
  });
  await t.test('server restart preserves accounts, encrypted files and forensic evidence',async()=>{
    await new Promise(r=>server.close(r));instance.close();instance=createApp({dataDir});server=instance.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));base=`http://127.0.0.1:${server.address().port}`;
    assert.equal((await call('/documents',{actor:'admin'})).value.length,1);
    assert.equal((await call('/investigate',{actor:'admin',method:'POST',body:form(firstOutput)})).value.recipientId,'recipient.a');
    await call(`/documents/${docId}`,{actor:'admin',method:'DELETE'});
    assert.equal(readdirSync(path.join(dataDir,'documents')).length,0);
    assert.equal((await call('/investigate',{actor:'admin',method:'POST',body:form(bOutput)})).value.recipientId,'recipient.b');
  });
});
