import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {PDFDocument,PDFName,PDFHexString} from 'pdf-lib';
import {ml_kem768} from '@noble/post-quantum/ml-kem.js';
import {ml_dsa65} from '@noble/post-quantum/ml-dsa.js';
import {encode,decode} from 'cborg';
import cbor from 'cbor';
import {encryptPdfForRecipients,decryptAndMarkPdf,signClientIssuance,digest,fromBase64,toBase64} from '../src/crypto/clientDocument.ts';
import {envelope,seal,unseal,deriveEnvelopeKey,envelopeContext,hash} from '../server/crypto.mjs';

test('client-only packaging, decryption, marking and signing',async t=>{
  const sender=ml_dsa65.keygen(),a=ml_kem768.keygen(),b=ml_kem768.keygen(),signerA=ml_dsa65.keygen();
  const documentId=randomUUID(),pdf=await PDFDocument.create();pdf.addPage([400,600]).drawText('Local-only synthetic plaintext');
  const source=await pdf.save();
  const recipients=[{recipientId:'recipient.a',keyId:'key-a',kemPublicKey:a.publicKey},{recipientId:'recipient.b',keyId:'key-b',kemPublicKey:b.publicKey}];
  const pkg=await encryptPdfForRecipients({pdfBytes:source,documentId,filename:'local-demo.pdf',recipients,senderSigningPrivateKey:sender.secretKey});
  const identity={recipientId:'recipient.a',keyId:'key-a',kemPrivateKey:a.secretKey};
  const issuance={networkId:'test-network',sessionId:randomUUID(),createdAt:'2026-09-27T10:00:00.000Z',policyEpoch:1};
  const input={package:pkg,recipient:identity,trustedSenderPublicKey:sender.publicKey,issuance};
  let output;
  await t.test('one ciphertext and recipient envelopes contain no plaintext or DEK',async()=>{
    assert.equal(Object.keys(pkg).sort().join(),['encryptedPayload','manifestBytes','senderSignature'].sort().join());
    assert.equal(Buffer.from(pkg.encryptedPayload).includes(Buffer.from(source)),false);
    const manifest=decode(pkg.manifestBytes);
    assert.equal(manifest.recipients.length,2);
    assert.deepEqual(Buffer.from(pkg.manifestBytes),cbor.encodeCanonical(manifest));
    assert.equal(ml_dsa65.verify(pkg.senderSignature,pkg.manifestBytes,sender.publicKey),true);
    assert.equal(await digest(source),hash(Buffer.from(source)));
  });
  await t.test('browser-generated envelopes decrypt with the existing Node AES/HKDF implementation',()=>{
    const m=decode(pkg.manifestBytes),e=m.recipients[0],ctx=envelopeContext(documentId,'recipient.a');
    const shared=ml_kem768.decapsulate(fromBase64(e.cipherText),a.secretKey);
    const dek=unseal(Buffer.from(fromBase64(e.wrappedKey)),deriveEnvelopeKey(shared,ctx),ctx);
    assert.deepEqual(unseal(Buffer.from(pkg.encryptedPayload),dek,'document/'+documentId),Buffer.from(source));
    shared.fill(0);dek.fill(0);
  });
  await t.test('decryption and structural marking run locally without fetch',async()=>{
    const originalFetch=globalThis.fetch;
    globalThis.fetch=()=>{throw new Error('Network access forbidden inside crypto utility');};
    try{output=await decryptAndMarkPdf(input);}finally{globalThis.fetch=originalFetch;}
    assert.notEqual(await digest(output.pdfBytes),await digest(source));
    const issued=await PDFDocument.load(output.pdfBytes),original=await PDFDocument.load(source);
    assert.equal(issued.getPageCount(),1);
    assert.deepEqual(issued.getPage(0).getSize(),original.getPage(0).getSize());
    const mark=issued.catalog.get(PDFName.of('CipherTrailIssuance'));
    assert.ok(mark instanceof PDFHexString);
    const decoded=decode(fromBase64(mark.decodeText().split(':')[1]));
    assert.equal(decoded.sessionId,issuance.sessionId);assert.equal(decoded.recipientId,'recipient.a');
    assert.deepEqual(Buffer.from(output.eventBytes),cbor.encodeCanonical(output.event));
    assert.equal(await digest(output.pdfBytes),output.event.outputDigest);
  });
  await t.test('recipient signs exact event bytes; wrong signing key and changed output fail',async()=>{
    const signed=await signClientIssuance(output,signerA.secretKey,signerA.publicKey);
    assert.equal(ml_dsa65.verify(signed.signature,signed.eventBytes,signerA.publicKey),true);
    await assert.rejects(signClientIssuance(output,sender.secretKey,signerA.publicKey),/registered recipient/);
    const modified={...output,pdfBytes:output.pdfBytes.slice()};modified.pdfBytes[100]^=1;
    await assert.rejects(signClientIssuance(modified,signerA.secretKey,signerA.publicKey),/changed before signing/);
  });
  await t.test('retry output is identical; fresh sessions and recipients are distinct',async()=>{
    assert.deepEqual((await decryptAndMarkPdf(input)).pdfBytes,output.pdfBytes);
    const newSession=await decryptAndMarkPdf({...input,issuance:{...issuance,sessionId:randomUUID()}});
    assert.notEqual(newSession.event.outputDigest,output.event.outputDigest);
    const other=await decryptAndMarkPdf({...input,recipient:{recipientId:'recipient.b',keyId:'key-b',kemPrivateKey:b.secretKey},issuance:{...issuance,sessionId:randomUUID()}});
    assert.notEqual(other.event.outputDigest,output.event.outputDigest);
  });
  await t.test('untrusted signer, changed ciphertext, absent envelope and wrong private key fail closed',async()=>{
    await assert.rejects(decryptAndMarkPdf({...input,trustedSenderPublicKey:signerA.publicKey}),/signature/);
    const tampered={...pkg,encryptedPayload:pkg.encryptedPayload.slice()};tampered.encryptedPayload[40]^=1;
    await assert.rejects(decryptAndMarkPdf({...input,package:tampered}),/digest mismatch/);
    await assert.rejects(decryptAndMarkPdf({...input,recipient:{...identity,recipientId:'unauthorized'}}),/no envelope/);
    await assert.rejects(decryptAndMarkPdf({...input,recipient:{...identity,kemPrivateKey:b.secretKey}}));
  });
  await t.test('Node-generated AES payload and ML-KEM envelope decrypt in the browser utility',async()=>{
    const dek=randomBytes(32),payload=seal(Buffer.from(source),dek,'document/'+documentId);
    const e=envelope(dek,a.publicKey,envelopeContext(documentId,'recipient.a'));
    const manifest={...decode(pkg.manifestBytes),ciphertextDigest:hash(payload,'CipherTrail/ciphertext/v1'),recipients:[{recipientId:'recipient.a',keyId:'key-a',...e}]};
    const manifestBytes=encode(manifest),nodePkg={encryptedPayload:payload,manifestBytes,senderSignature:ml_dsa65.sign(manifestBytes,sender.secretKey)};
    const result=await decryptAndMarkPdf({...input,package:nodePkg});
    assert.deepEqual(result.pdfBytes,output.pdfBytes);dek.fill(0);
  });
  await t.test('tampered envelope, noncanonical and unknown signed schemas fail',async()=>{
    const m=decode(pkg.manifestBytes);const wrapped=fromBase64(m.recipients[0].wrappedKey);wrapped[25]^=1;m.recipients[0].wrappedKey=toBase64(wrapped);
    const bytes=encode(m),sig=ml_dsa65.sign(bytes,sender.secretKey);
    await assert.rejects(decryptAndMarkPdf({...input,package:{...pkg,manifestBytes:bytes,senderSignature:sig}}));
    const unknown=encode({...decode(pkg.manifestBytes),unexpected:true});
    await assert.rejects(decryptAndMarkPdf({...input,package:{...pkg,manifestBytes:unknown,senderSignature:ml_dsa65.sign(unknown,sender.secretKey)}}),/schema/);
    const notCanonical=cbor.encode(decode(pkg.manifestBytes));
    // Normal map insertion order differs from canonical key order after reversal.
    const reversed=cbor.encode(Object.fromEntries(Object.entries(decode(notCanonical)).reverse()));
    await assert.rejects(decryptAndMarkPdf({...input,package:{...pkg,manifestBytes:reversed,senderSignature:ml_dsa65.sign(reversed,sender.secretKey)}}),/canonical/);
  });
});
