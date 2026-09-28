import { parseCanonical, verifyNative, SUITE } from '../ledger/application.mjs';
let input='';
for await(const chunk of process.stdin){input+=chunk;if(input.length>50000)throw new Error('Input too large');}
try {
  const record=JSON.parse(input);
  const bytes=Buffer.from(record.eventBytes,'base64'),sig=Buffer.from(record.signature,'base64'),key=Buffer.from(record.trustedPublicKey,'base64');
  const event=parseCanonical(bytes);
  verifyNative(bytes,sig,key);
  if(event.domain!=='CipherTrail/client-issuance/v1'||event.suite!==SUITE||event.watermarkProfile!=='dct-footer-v1')throw new Error('Wrong signed event profile');
  console.log(JSON.stringify(event));
} catch(error){console.error(error.message);process.exitCode=1;}
