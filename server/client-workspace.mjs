import { Router } from 'express';
import multer from 'multer';
import { decode } from 'cborg';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { TendermintLedger } from './ledger-client.mjs';
import { verifyNative, parseCanonical, SUITE } from '../ledger/application.mjs';
import { hash } from './crypto.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const execute=promisify(execFile);
const fault=(status,message)=>Object.assign(new Error(message),{status});
const b64=b=>Buffer.from(b).toString('base64');
function bytes(s,length) {
  if(typeof s!=='string'||s.length>180000)throw fault(400,'Invalid encoded data');
  const b=Buffer.from(s,'base64');
  if(b64(b)!==s||(length&&b.length!==length))throw fault(400,'Invalid cryptographic data length');
  return b;
}
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Administrator required'});
export function clientWorkspace({db,directory,capacity,ledger=new TendermintLedger()}) {
  db.exec(`CREATE TABLE IF NOT EXISTS client_documents(id TEXT PRIMARY KEY, manifest BLOB NOT NULL, signature BLOB NOT NULL, ciphertext BLOB NOT NULL, sender_public BLOB NOT NULL, created_at TEXT NOT NULL);`);
  const router=Router();
  const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:10*1024*1024+28,files:1,fields:4,fieldSize:180000}}).single('payload');
  const investigation=multer({storage:multer.memoryStorage(),limits:{fileSize:10*1024*1024,files:2,fields:0}}).fields([{name:'artifact',maxCount:1},{name:'trust',maxCount:1}]);
  async function state() {try{return await ledger.query('/state');}catch {throw fault(503,'Ledger unavailable. Start the validator network and try again.');}}
  const rows=()=>db.prepare('SELECT id,manifest,signature,sender_public,created_at,length(ciphertext) AS size FROM client_documents ORDER BY created_at DESC').all();
  router.get('/workspace',async(req,res)=>{
    let current,error;
    try{current=await state();}catch(e){error=e.message;}
    const isAdmin=req.user.role==='admin';
    const documents=rows().flatMap(row=>{
      const manifest=decode(row.manifest),policy=current?.documents[row.id];
      if(!isAdmin&&!manifest.recipients.some(r=>r.recipientId===req.user.id))return [];
      return [{id:row.id,name:manifest.filename,size:row.size,createdAt:row.created_at,packageDigest:hash(row.manifest,'CipherTrail/package/v1'),senderKeyId:manifest.senderKeyId,senderPublicKey:b64(row.sender_public),recipients:manifest.recipients.map(r=>r.recipientId),policy:policy||null}];
    });
    const sessions=Object.values(current?.sessions||{}).map(r=>({event:decode(r.event),txHash:r.txHash,height:r.height})).filter(r=>isAdmin||r.event.recipientId===req.user.id);
    const identities=Object.values(current?.identities||{}).filter(r=>isAdmin||r.recipientId===req.user.id).map(r=>({...r,publicKey:b64(r.publicKey)}));
    res.json({available:!!current,error,networkId:current?.networkId,height:current?.height,sequence:current?.sequence,transactionCount:current?current.sequence+Object.keys(current.sessions).length:null,authorityPublicKey:current?b64(current.authority):null,documents,sessions,identities,finality:'RPC acknowledgment; independent proof verification not implemented'});
  });
  router.get('/validators',admin,async(req,res)=>{
    const urls=(process.env.TENDERMINT_PEERS||'http://127.0.0.1:26657,http://127.0.0.1:26667,http://127.0.0.1:26677').split(',');
    const nodes=await Promise.all(urls.slice(0,8).map(async(url,index)=>{
      try{
        const response=await fetch(url+'/status',{signal:AbortSignal.timeout(2000)}),body=await response.json();
        if(!response.ok||!body.result)throw new Error('Unavailable');
        const r=body.result;
        let consensus;
        try {const c=await fetch(url+'/consensus_state',{signal:AbortSignal.timeout(2000)});consensus=(await c.json()).result?.round_state;}catch{}
        return {name:`Node ${index}`,online:true,networkId:r.node_info.network,height:r.sync_info.latest_block_height,blockTime:r.sync_info.latest_block_time,blockAgeSeconds:Math.max(0,Math.floor((Date.now()-Date.parse(r.sync_info.latest_block_time))/1000)),catchingUp:r.sync_info.catching_up,address:r.validator_info.address,power:r.validator_info.voting_power,round:consensus?.['height/round/step'],precommits:consensus?.height_vote_set?.at(-1)?.precommits_bit_array};
      }catch{return {name:`Node ${index}`,online:false};}
    }));res.json(nodes);
  });
  router.get('/blocks',admin,async(req,res)=>{
    try {
      const s=await ledger.rpc('status'),height=Number(s.sync_info.latest_block_height);
      if(!height)return res.json([]);
      const result=await ledger.rpc('blockchain',{minHeight:String(Math.max(1,height-19)),maxHeight:String(height)});
      const blocks=(result.block_metas||[]).map(b=>({height:Number(b.header.height),time:b.header.time,transactions:Number(b.num_txs),hash:b.block_id.hash})).sort((a,b)=>a.height-b.height);
      res.json(blocks.map((b,i)=>({...b,interval:i?Math.max(0,(Date.parse(b.time)-Date.parse(blocks[i-1].time))/1000):null})));
    }catch {res.status(503).json({error:'Block history is temporarily unavailable'});}
  });
  router.post('/documents',admin,upload,(req,res)=>{
    if(!req.file)throw fault(400,'Encrypted payload required');
    capacity(req.file.size+180000);
    const manifest=bytes(req.body.manifestBytes),signature=bytes(req.body.senderSignature,3309),sender=bytes(req.body.senderPublicKey,1952);
    const m=parseCanonical(manifest,128*1024);
    if(m.domain!=='CipherTrail/client-package/v1'||m.suite!==SUITE||m.version!==1||!/^[-a-zA-Z0-9._:]{1,128}$/.test(m.documentId)||typeof m.filename!=='string'||m.filename.length>160||!Array.isArray(m.recipients)||!m.recipients.length||m.recipients.length>20)throw fault(400,'Unsupported client package');
    verifyNative(manifest,signature,sender);
    if(m.senderKeyId!==hash(sender,'CipherTrail/sender-key/v1')||m.ciphertextDigest!==hash(req.file.buffer,'CipherTrail/ciphertext/v1'))throw fault(400,'Package digest mismatch');
    for(const r of m.recipients){
      bytes(r.cipherText,1088);bytes(r.wrappedKey,60);
      const user=db.prepare('SELECT key_id FROM users WHERE id=? AND role=?').get(r.recipientId,'recipient');
      if(!user||user.key_id!==r.keyId)throw fault(400,'Recipient enrollment mismatch');
    }
    if(db.prepare('SELECT id FROM client_documents WHERE id=?').get(m.documentId))throw fault(409,'Document ID already stored');
    db.prepare('INSERT INTO client_documents VALUES (?,?,?,?,?,?)').run(m.documentId,manifest,signature,req.file.buffer,sender,new Date().toISOString());
    res.status(201).json({id:m.documentId,packageDigest:hash(manifest,'CipherTrail/package/v1')});
  });
  router.get('/documents/:id/package',async(req,res)=>{
    const row=db.prepare('SELECT * FROM client_documents WHERE id=?').get(req.params.id);
    if(!row)throw fault(404,'Client document not found');
    const current=await state(),policy=current.documents[row.id],identity=current.identities[req.user.id];
    if(!identity?.active||identity.keyId!==req.user.key_id||!policy?.recipients.includes(req.user.id)||policy.packageDigest!==hash(row.manifest,'CipherTrail/package/v1'))throw fault(403,'Ledger policy does not authorize this recipient');
    res.json({manifestBytes:b64(row.manifest),senderSignature:b64(row.signature),encryptedPayload:b64(row.ciphertext),senderPublicKey:b64(row.sender_public),networkId:current.networkId,policyEpoch:policy.policyEpoch});
  });
  router.post('/governance',admin,async(req,res)=>{
    const event=bytes(req.body.eventBytes),signature=bytes(req.body.signature,3309),e=parseCanonical(event);
    if(e.domain!=='CipherTrail/ledger-governance/v1')throw fault(400,'Governance transaction required');
    res.json(await ledger.broadcast(event,signature));
  });
  router.get('/evidence/:id',async(req,res)=>{
    const current=await state(),record=current.sessions[req.params.id];
    if(!record)throw fault(404,'Session not found');
    const e=decode(record.event);
    if(req.user.role!=='admin'&&req.user.id!==e.recipientId)throw fault(403,'Access denied');
    res.json({eventBytes:b64(record.event),signature:b64(record.signature),publicKey:b64(record.publicKey),txHash:record.txHash,height:record.height,independentFinalityVerified:false});
  });
  router.get('/snapshot',admin,async(req,res)=>{
    const current=await state();res.json(snapshot(current));
  });
  function snapshot(current){return {format:'CipherTrail/forensic-snapshot/v1',networkId:current.networkId,provenance:'RPC snapshot; independent finality not verified',records:Object.values(current.sessions).map(r=>({eventBytes:b64(r.event),signature:b64(r.signature),height:r.height,txHash:r.txHash}))};}
  router.post('/investigate',admin,investigation,async(req,res)=>{
    const artifact=req.files?.artifact?.[0],trust=req.files?.trust?.[0];
    if(!artifact||!trust||trust.size>128000)throw fault(400,'Choose an artifact and a public trusted-identities JSON file (up to 128 KB)');
    const extension=path.extname(artifact.originalname).toLowerCase();
    if(!['.pdf','.png','.jpg','.jpeg'].includes(extension))throw fault(400,'Choose PDF, PNG or JPEG');
    let trusted;try{trusted=JSON.parse(trust.buffer.toString());}catch{throw fault(400,'Malformed trust JSON');}
    if(!Array.isArray(trusted.identities))throw fault(400,'Trusted registry must contain an identities array. Export trusted-identities.json from Client documents.');
    if(trusted.identities.length>20)throw fault(400,'Trusted registry may contain at most 20 public identities.');
    if(Object.keys(trusted).some(k=>!['networkId','identities'].includes(k))||trusted.identities.some(i=>Object.keys(i).some(k=>!['recipientId','keyId','publicKey'].includes(k))))throw fault(400,'Use only networkId and public identity fields; never private keys');
    const current=await state();
    if(trusted.networkId!==current.networkId)
      throw fault(422,`Trusted registry belongs to network ${trusted.networkId||'unknown'}, but this ledger is ${current.networkId}. Export a fresh public registry from Client documents.`);
    const base=path.join(directory,'forensic-temp');mkdirSync(base,{recursive:true});
    const temp=mkdtempSync(path.join(base,'case-'));
    try {
      writeFileSync(path.join(temp,'artifact'+extension),artifact.buffer);
      writeFileSync(path.join(temp,'trust.json'),JSON.stringify(trusted));
      writeFileSync(path.join(temp,'snapshot.json'),JSON.stringify(snapshot(current)));
      const python=process.env.FORENSICS_PYTHON||path.join(root,'.venv-forensics',process.platform==='win32'?'Scripts/python.exe':'bin/python');
      if(!existsSync(python))throw fault(503,'Forensic Python environment not installed. See FORENSICS.md.');
      const args=[path.join(root,'forensic_extractor.py'),path.join(temp,'artifact'+extension),'--snapshot',path.join(temp,'snapshot.json'),'--trust',path.join(temp,'trust.json')];
      let stdout;
      try{({stdout}=await execute(python,args,{cwd:root,timeout:45000,maxBuffer:1024*1024,windowsHide:true}));}
      catch(e){
        // The CLI deliberately uses exit 2 for an inconclusive finding and exit 3
        // for invalid evidence or an untrusted snapshot. Both cases emit a JSON
        // report; preserve it so the UI can explain the actual forensic result.
        if((e.code===2||e.code===3)&&e.stdout)stdout=e.stdout;
        else throw fault(422,e.killed?'Forensic analysis timed out':'Forensic processing failed; check the input and Python installation');
      }
      let result;
      try { result=JSON.parse(stdout); }
      catch { throw fault(422,'Forensic extractor returned an invalid report. Check the input and Python installation.'); }
      if(result.status==='ERROR') throw fault(422,result.reason||'Forensic evidence could not be verified.');
      result.caseId=randomUUID();result.createdAt=new Date().toISOString();
      result.artifactHash=hash(artifact.buffer);result.classification=result.status;
      db.prepare('INSERT INTO cases VALUES (?,?,?,?)').run(result.caseId,result.artifactHash,JSON.stringify(result),result.createdAt);
      res.json(result);
    }finally{artifact.buffer.fill(0);rmSync(temp,{recursive:true,force:true});}
  });
  return router;
}
