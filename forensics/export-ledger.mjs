import { writeFileSync } from 'node:fs';
import { TendermintLedger } from '../server/ledger-client.mjs';
const state=await new TendermintLedger(process.env.TENDERMINT_RPC).query('/state');
const records=Object.values(state.sessions).map(r=>({eventBytes:Buffer.from(r.event).toString('base64'),signature:Buffer.from(r.signature).toString('base64'),height:r.height,txHash:r.txHash}));
const snapshot={format:'CipherTrail/forensic-snapshot/v1',networkId:state.networkId,provenance:'RPC snapshot; consensus proofs not independently verified',records};
if(process.argv[2])writeFileSync(process.argv[2],JSON.stringify(snapshot,null,2));
else console.log(JSON.stringify(snapshot));
