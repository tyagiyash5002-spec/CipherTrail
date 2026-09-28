import {readFileSync} from 'node:fs';
import cbor from 'cbor';
import {verify,from64,hash,canonical} from '../server/crypto.mjs';
export function verifyEvidence(bundle,artifact,pinnedRecipientKey) {
  if(bundle.format!=='ciphertrail-evidence-v1')throw new Error('Unsupported evidence format.');
  const event=from64(bundle.event),decoded=cbor.decodeFirstSync(event);
  const canonicalEncoding=canonical(decoded).equals(event);
  const publicKey=from64(pinnedRecipientKey || bundle.recipient.publicKey);
  const checks={canonicalEncoding,recipientSignature:verify(event,from64(bundle.signature||''),publicKey),deviceAttestation:verify(event,from64(bundle.attestation||''),from64(bundle.devicePublicKey)),recipientBinding:decoded.recipientId===bundle.recipient.id,outputBinding:decoded.outputDigest===bundle.outputDigest,artifactDigest:artifact?hash(artifact)===decoded.outputDigest:null,independentRecipientKey:!!pinnedRecipientKey,ledgerFinality:false};
  const valid=checks.canonicalEncoding&&checks.recipientSignature&&checks.deviceAttestation&&checks.recipientBinding&&checks.outputBinding&&checks.artifactDigest!==false;
  return {valid,checks,event:decoded,scope:'Local signature and optional exact-file verification only. Device key is bundle-supplied; identity governance, watermark authentication and BFT finality are not independently verified.'};
}
if(process.argv[1]?.endsWith('verify-evidence.mjs')) {
  try {
    const [bundlePath,pdfPath,pinnedKeyPath]=process.argv.slice(2);
    if(!bundlePath)throw new Error('Usage: npm run verify -- evidence.json [issued.pdf] [trusted-recipient-public-key.txt]');
    const result=verifyEvidence(JSON.parse(readFileSync(bundlePath,'utf8')),pdfPath?readFileSync(pdfPath):undefined,pinnedKeyPath?readFileSync(pinnedKeyPath,'utf8').trim():undefined);
    console.log(JSON.stringify(result,null,2));if(!result.valid)process.exitCode=1;
  }catch(error){console.error(error.message);process.exitCode=1;}
}
