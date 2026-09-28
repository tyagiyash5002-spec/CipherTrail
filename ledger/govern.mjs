import { readFileSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { canonical } from './application.mjs';
import { TendermintLedger } from '../server/ledger-client.mjs';

// Deliberately separate from Express: a storage-server compromise must not
// authorize identities or documents. Run on the governance operator's machine.
const [keyFile,operation,valueFile] = process.argv.slice(2);
if (!keyFile || !['identity','document'].includes(operation) || !valueFile)
  throw new Error('Usage: node ledger/govern.mjs GOVERNANCE_PRIVATE_KEY.json identity|document VALUE.json');
const keys = JSON.parse(readFileSync(keyFile,'utf8'));
const value = JSON.parse(readFileSync(valueFile,'utf8'));
if (operation === 'identity') value.publicKey = new Uint8Array(Buffer.from(value.publicKey,'base64'));
const ledger = new TendermintLedger();
const state = await ledger.query('/state');
if (!Buffer.from(state.authority).equals(Buffer.from(keys.publicKey,'base64'))) throw new Error('Wrong governance key');
const event = canonical({domain:'CipherTrail/ledger-governance/v1',networkId:state.networkId,sequence:state.sequence+1,operation,value});
const signature = ml_dsa65.sign(event,Buffer.from(keys.secretKey,'base64'));
const result = await ledger.broadcast(event,signature);
console.log(JSON.stringify({status:result.status,txHash:result.txHash,height:result.height},null,2));
