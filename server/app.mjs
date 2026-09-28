import express from 'express';
import multer from 'multer';
import cbor from 'cbor';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, unlinkSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { openStore, transaction, appendAudit, verifyAudit } from './store.mjs';
import { hash, passwordHash, passwordMatches, seal, unseal, canonical, b64, from64, sign, verify, envelope, envelopeContext, deriveEnvelopeKey, marker } from './crypto.mjs';
import { inspectPdf, markedCopy, extractMarker } from './pdf-jobs.mjs';
import { ledgerRoutes } from './ledger-routes.mjs';
import { clientWorkspace } from './client-workspace.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MAX_FILE = 10 * 1024 * 1024;
const fail = (status,message) => Object.assign(new Error(message),{status});
const now = () => new Date().toISOString();
const publicUser = u => ({id:u.id,name:u.name,role:u.role,keyId:u.key_id,kemPublic:u.kem_public,signPublic:u.sign_public});
function decode(value, length) {
  if (typeof value !== 'string' || value.length > 30000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw fail(400,'Invalid encoded cryptographic data.');
  const bytes = from64(value);
  if (length && bytes.length !== length) throw fail(400,'Incorrect cryptographic data length.');
  return bytes;
}
function directorySize(dir) {
  return readdirSync(dir,{withFileTypes:true}).reduce((total,entry) => {
    const file = path.join(dir,entry.name);
    return total + (entry.isDirectory() ? directorySize(file) : statSync(file).size);
  },0);
}

export function createApp({dataDir = process.env.DATA_DIR || path.join(root,'data'), secureCookies = process.env.COOKIE_SECURE === 'true', storageLimit = Number(process.env.STORAGE_LIMIT_MB || 700) * 1024 * 1024, ledger} = {}) {
  const store = openStore(path.resolve(dataDir));
  const {db,key,directory,sender,device,watermarkKey} = store;
  const app = express();
  app.disable('x-powered-by');
  app.use((req,res,next) => {
    res.set({'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"});
    if (req.path.startsWith('/api/')) {
      res.set('Cache-Control','no-store');
      if (!['GET','HEAD','OPTIONS'].includes(req.method) && req.get('X-CipherTrail') !== '1') return res.status(403).json({error:'Missing request protection header.'});
    }
    next();
  });
  app.use(express.json({limit:'128kb'}));
  const upload = multer({storage:multer.memoryStorage(),limits:{fileSize:MAX_FILE,files:1,fields:4,fieldSize:16384}}).single('file');
  const attempts = new Map();
  const fakePassword = passwordHash(randomBytes(20).toString('hex'));
  function audit(actor,action,details) { appendAudit(db,actor,action,details); }
  function authenticated(req,res,next) {
    const token = (req.headers.cookie || '').split(';').map(s=>s.trim()).find(s=>s.startsWith('ct_session='))?.slice(11);
    const row = token && db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').get(hash(token,'session'),Date.now());
    if (!row) return res.status(401).json({error:'Please sign in.'});
    req.user = row; req.sessionToken = token; next();
  }
  const admin = (req,res,next) => req.user.role === 'admin' ? next() : res.status(403).json({error:'Administrator access required.'});
  function capacity(extra = 0) {
    if (directorySize(directory) + extra > storageLimit) throw fail(507,'Demo storage limit reached. Ask the administrator to delete old documents.');
    if (db.prepare('SELECT COUNT(*) AS n FROM audit').get().n > 50000) throw fail(507,'Demo audit capacity reached. Archive this workspace before continuing.');
  }
  function document(id) {
    const row = db.prepare('SELECT * FROM documents WHERE id=? AND deleted=0').get(id);
    if (!row) throw fail(404,'Document not found.');
    return row;
  }
  function permission(req,id) {
    if (req.user.role !== 'recipient') throw fail(403,'Sign in as a recipient to request a copy.');
    const doc = document(id);
    const grant = db.prepare('SELECT envelope FROM permissions WHERE document_id=? AND user_id=?').get(id,req.user.id);
    if (!grant) { audit(req.user.id,'ACCESS_DENIED',{documentId:id}); throw fail(403,'Access denied. The administrator has not authorized you for this document.'); }
    return {doc,envelope:JSON.parse(grant.envelope)};
  }
  const filePath = id => path.join(directory,'documents',id + '.enc');
  function clearDocument(doc) {
    const dek = unseal(Buffer.from(doc.wrapped_key),key,'master/' + doc.id);
    try { return unseal(readFileSync(filePath(doc.id)),dek,'document/' + doc.id); }
    finally { dek.fill(0); }
  }
  function setPermissions(doc,ids,dek) {
    if (!Array.isArray(ids) || ids.length > 20 || new Set(ids).size !== ids.length) throw fail(400,'Choose valid recipients.');
    const recipients = ids.map(id => db.prepare("SELECT * FROM users WHERE id=? AND role='recipient' AND kem_public IS NOT NULL").get(id));
    if (recipients.some(u=>!u)) throw fail(400,'Every recipient must first register their keys.');
    db.prepare('DELETE FROM permissions WHERE document_id=?').run(doc.id);
    const entries = [];
    for (const user of recipients.sort((a,b)=>a.id.localeCompare(b.id))) {
      const value = envelope(dek,from64(user.kem_public),envelopeContext(doc.id,user.id));
      db.prepare('INSERT INTO permissions VALUES (?,?,?)').run(doc.id,user.id,JSON.stringify(value));
      entries.push({recipient:user.id,keyId:user.key_id,...value});
    }
    const manifest = canonical({domain:'CipherTrail/package/v1',suite:'ML-KEM-768+ML-DSA-65+AES-256-GCM+HKDF-SHA-384',documentId:doc.id,version:1,name:doc.name,sourceDigest:doc.digest,ciphertextDigest:hash(readFileSync(filePath(doc.id)),'CipherTrail/ciphertext/v1'),policyEpoch:doc.epoch,recipients:entries});
    db.prepare('UPDATE documents SET manifest=?,signature=? WHERE id=?').run(manifest,sign(manifest,from64(sender.secretKey)),doc.id);
  }
  function verifiedPackage(doc) {
    if (!verify(Buffer.from(doc.manifest),Buffer.from(doc.signature),from64(sender.publicKey))) throw fail(409,'Package signature verification failed.');
    // Bind stored ciphertext to the sender-signed manifest, in addition to AEAD checks.
    const parsed = cbor.decodeFirstSync(Buffer.from(doc.manifest));
    if (parsed.ciphertextDigest !== hash(readFileSync(filePath(doc.id)),'CipherTrail/ciphertext/v1')) throw fail(409,'Encrypted document integrity check failed.');
  }

  app.get('/api/health', (req,res)=>res.json({status:'ok',mode:'working-demo',ledgerFinality:false}));
  app.post('/api/login',(req,res) => {
    const {id,password} = req.body || {};
    if (typeof id !== 'string' || id.length > 80 || typeof password !== 'string' || password.length > 256) throw fail(400,'Enter your account ID and password.');
    const rateKey = req.socket.remoteAddress;
    const current = Date.now();
    for (const [k,v] of attempts) if (v.until < current) attempts.delete(k);
    const state = attempts.get(rateKey) || {count:0,until:current+60000};
    if (++state.count > 20) throw fail(429,'Too many login attempts. Try again in one minute.');
    attempts.set(rateKey,state);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(id.trim());
    const valid = passwordMatches(password,user?.password || fakePassword);
    if (!user || !valid) throw fail(401,'Incorrect account ID or password.');
    const token = randomBytes(32).toString('hex');
    db.prepare('DELETE FROM sessions WHERE expires<?').run(current);
    db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(hash(token,'session'),user.id,current+8*60*60*1000);
    res.cookie('ct_session',token,{httpOnly:true,secure:secureCookies,sameSite:'strict',maxAge:8*60*60*1000,path:'/'});
    audit(user.id,'SIGNED_IN',{}); res.json(publicUser(user));
  });
  app.use('/api',authenticated);
  app.use('/api/ledger',ledgerRoutes(ledger));
  app.use('/api/client',clientWorkspace({db,directory,capacity,ledger}));
  app.get('/api/me',(req,res)=>res.json(publicUser(req.user)));
  app.post('/api/logout',(req,res)=>{
    db.prepare('DELETE FROM sessions WHERE token=?').run(hash(req.sessionToken,'session'));
    res.clearCookie('ct_session',{path:'/',httpOnly:true,sameSite:'strict',secure:secureCookies}); res.json({ok:true});
  });
  app.get('/api/users',admin,(req,res)=>res.json(db.prepare('SELECT * FROM users').all().map(publicUser)));
  app.post('/api/keys',(req,res)=>{
    if (req.user.role !== 'recipient') throw fail(403,'Recipient account required.');
    if (req.user.key_id) throw fail(409,'This account already has registered keys. Load your original key file.');
    const kem = decode(req.body.kemPublic,1184), signing = decode(req.body.signPublic,1952), proof = decode(req.body.proof,3309);
    const enrollment = Buffer.from(`CipherTrail/enroll/v1/${req.user.id}/${b64(kem)}`);
    if (!verify(enrollment,proof,signing)) throw fail(400,'Key possession signature failed.');
    const keyId = hash(Buffer.concat([kem,signing]),'CipherTrail/identity/v1');
    transaction(db,()=>{
      db.prepare('UPDATE users SET kem_public=?,sign_public=?,key_id=? WHERE id=?').run(b64(kem),b64(signing),keyId,req.user.id);
      audit(req.user.id,'KEYS_REGISTERED',{keyId,algorithms:['ML-KEM-768','ML-DSA-65']});
    });
    res.json(publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)));
  });
  app.get('/api/documents',(req,res)=>{
    const rows = db.prepare('SELECT id,name,size,pages,created_at,epoch FROM documents WHERE deleted=0 ORDER BY created_at DESC').all();
    res.json(rows.map(doc=>{
      const recipients = db.prepare('SELECT user_id FROM permissions WHERE document_id=?').all(doc.id).map(r=>r.user_id);
      return {...doc,authorized:recipients.includes(req.user.id),...(req.user.role==='admin'?{recipients}: {})};
    }));
  });
  app.post('/api/documents',admin,upload,async(req,res)=>{
    if (!req.file) throw fail(400,'Select a PDF.');
    capacity(req.file.size + 50000);
    let ids; try { ids = JSON.parse(req.body.recipients || '[]'); } catch { throw fail(400,'Invalid recipient list.'); }
    const pdf = await inspectPdf(req.file.buffer);
    capacity(req.file.size + 50000);
    const doc = {id:randomUUID(),name:path.basename(req.file.originalname.replaceAll('\\','/')).replace(/[\x00-\x1f]/g,'').slice(0,160) || 'document.pdf',size:req.file.size,pages:pdf.pages,digest:hash(req.file.buffer),created_at:now(),epoch:1};
    const dek = randomBytes(32);
    try {
      writeFileSync(filePath(doc.id),seal(req.file.buffer,dek,'document/'+doc.id),{flag:'wx',mode:0o600});
      transaction(db,()=>{
        db.prepare('INSERT INTO documents(id,name,size,pages,digest,wrapped_key,created_at) VALUES (?,?,?,?,?,?,?)').run(doc.id,doc.name,doc.size,doc.pages,doc.digest,seal(dek,key,'master/'+doc.id),doc.created_at);
        setPermissions(doc,ids,dek); audit(req.user.id,'DOCUMENT_ENCRYPTED',{documentId:doc.id,name:doc.name,recipients:ids});
      });
    } catch(error) { try { unlinkSync(filePath(doc.id)); } catch {} throw error; }
    finally { dek.fill(0); req.file.buffer.fill(0); }
    res.status(201).json({id:doc.id});
  });
  app.put('/api/documents/:id/permissions',admin,(req,res)=>{
    const doc = document(req.params.id), dek = unseal(Buffer.from(doc.wrapped_key),key,'master/'+doc.id);
    try { transaction(db,()=>{
      doc.epoch++; db.prepare('UPDATE documents SET epoch=? WHERE id=?').run(doc.epoch,doc.id);
      setPermissions(doc,req.body.recipients,dek); audit(req.user.id,'ACCESS_UPDATED',{documentId:doc.id,recipients:req.body.recipients,epoch:doc.epoch});
    }); } finally { dek.fill(0); }
    res.json({ok:true});
  });
  app.delete('/api/documents/:id',admin,(req,res)=>{
    const doc = document(req.params.id);
    transaction(db,()=>{
      db.prepare('UPDATE documents SET deleted=1 WHERE id=?').run(doc.id);
      db.prepare('DELETE FROM permissions WHERE document_id=?').run(doc.id);
      audit(req.user.id,'DOCUMENT_DELETED',{documentId:doc.id});
    });
    unlinkSync(filePath(doc.id)); res.json({ok:true});
  });
  app.get('/api/documents/:id/envelope',(req,res)=>{
    const {doc,envelope:value} = permission(req,req.params.id); verifiedPackage(doc);
    res.json({...value,documentId:doc.id,keyId:req.user.key_id});
  });
  app.get('/api/documents/:id/package',(req,res)=>{
    const {doc,envelope:value} = permission(req,req.params.id); verifiedPackage(doc);
    res.json({
      profile: 'legacy-server-v1',
      manifestBytes: b64(doc.manifest),
      encryptedPayload: b64(readFileSync(filePath(doc.id))),
      senderSignature: b64(doc.signature),
      envelope: {...value,documentId:doc.id,keyId:req.user.key_id}
    });
  });
  app.post('/api/documents/:id/prepare',async(req,res)=>{
    capacity(30000);
    const {doc,envelope:value} = permission(req,req.params.id); verifiedPackage(doc);
    const requestId = req.body.requestId;
    if (typeof requestId !== 'string' || !/^[a-zA-Z0-9_-]{16,80}$/.test(requestId)) throw fail(400,'A unique request ID is required.');
    const sharedSecret = decode(req.body.sharedSecret,32);
    let dek,source;
    try {
      const context = envelopeContext(doc.id,req.user.id);
      dek = unseal(from64(value.wrappedKey),deriveEnvelopeKey(sharedSecret,context),context);
      source = unseal(readFileSync(filePath(doc.id)),dek,'document/'+doc.id);
    } catch { throw fail(403,'Recipient key could not unlock this document.'); }
    finally { sharedSecret.fill(0); dek?.fill(0); }
    let row = db.prepare('SELECT * FROM issuances WHERE recipient_id=? AND request_id=?').get(req.user.id,requestId);
    if (row && (row.document_id !== doc.id || row.epoch !== doc.epoch || row.status==='cancelled')) { source.fill(0); throw fail(409,'This request is no longer valid. Start a new session.'); }
    if (!row) {
      row = {id:randomUUID(),document_id:doc.id,recipient_id:req.user.id,request_id:requestId,created_at:now(),epoch:doc.epoch};
      try {
        const output = await markedCopy(source,marker(row,watermarkKey),row.created_at);
        row.digest = hash(output); output.fill(0);
        row.event = canonical({domain:'CipherTrail/issuance/v1',suite:'CT-SRS-DEMO-1',network:'ciphertrail-demo',sessionId:row.id,documentId:doc.id,documentName:doc.name,version:1,recipientId:req.user.id,keyId:req.user.key_id,requestId,nonce:randomBytes(24).toString('hex'),outputDigest:row.digest,packageDigest:hash(Buffer.from(doc.manifest),'CipherTrail/package/v1'),policyEpoch:doc.epoch,watermarkProfile:'structural-pdf-v1',watermarkToken:marker(row,watermarkKey),createdAt:row.created_at,timeAssurance:'server-clock-unverified',ledger:'local-signed-log-no-BFT-finality'});
        // Recheck policy after the asynchronous parser yields.
        const current = permission(req,doc.id).doc;
        if (current.epoch !== row.epoch) throw fail(409,'Access policy changed. Start again.');
        transaction(db,()=>{
          const existing = db.prepare('SELECT * FROM issuances WHERE recipient_id=? AND request_id=?').get(req.user.id,requestId);
          if (existing) {
            if (existing.document_id!==doc.id || existing.epoch!==doc.epoch || existing.status==='cancelled') throw fail(409,'Request ID was already used for a different session.');
            row=existing; return;
          }
          db.prepare('INSERT INTO issuances(id,document_id,recipient_id,request_id,digest,created_at,epoch,event,status) VALUES (?,?,?,?,?,?,?,?,?)').run(row.id,doc.id,req.user.id,requestId,row.digest,row.created_at,doc.epoch,row.event,'prepared');
          audit(req.user.id,'COPY_PREPARED',{sessionId:row.id,documentId:doc.id});
        });
      } finally { source.fill(0); }
    } else source.fill(0);
    res.json({id:row.id,event:b64(row.event),summary:cbor.decodeFirstSync(Buffer.from(row.event)),status:row.status || 'prepared'});
  });
  app.get('/api/issuances/:id/prepared',(req,res)=>{
    const row=db.prepare("SELECT * FROM issuances WHERE id=? AND recipient_id=? AND status='prepared'").get(req.params.id,req.user.id);
    if(!row) throw fail(404,'Unsigned session not found.');
    const {doc}=permission(req,row.document_id);
    if(row.epoch!==doc.epoch || Date.now()-Date.parse(row.created_at)>15*60*1000) throw fail(409,'Session expired or policy changed. Request a new copy.');
    res.json({id:row.id,event:b64(row.event),summary:cbor.decodeFirstSync(Buffer.from(row.event)),status:row.status});
  });
  app.post('/api/issuances/:id/cancel',(req,res)=>{
    const row = db.prepare('SELECT * FROM issuances WHERE id=? AND recipient_id=?').get(req.params.id,req.user.id);
    if (!row) throw fail(404,'Session not found.');
    if (row.status !== 'prepared') throw fail(409,'Only an unsigned session can be cancelled.');
    transaction(db,()=>{db.prepare("UPDATE issuances SET status='cancelled' WHERE id=?").run(row.id);audit(req.user.id,'SIGNING_DECLINED',{sessionId:row.id});});
    res.json({ok:true});
  });
  app.post('/api/issuances/:id/release',async(req,res)=>{
    const row = db.prepare('SELECT * FROM issuances WHERE id=? AND recipient_id=?').get(req.params.id,req.user.id);
    if (!row) throw fail(404,'Session not found.');
    const {doc} = permission(req,row.document_id); verifiedPackage(doc);
    if (row.status==='cancelled' || row.epoch !== doc.epoch) throw fail(409,'Session cancelled or permissions changed. Start a new session.');
    if (row.status==='prepared' && Date.now()-Date.parse(row.created_at)>15*60*1000) throw fail(409,'Unsigned session expired. Request a new copy.');
    const signature = decode(req.body.signature,3309);
    if (!verify(Buffer.from(row.event),signature,from64(req.user.sign_public))) throw fail(403,'Recipient ML-DSA-65 signature is invalid.');
    const source = clearDocument(doc);
    let output;
    try { output = await markedCopy(source,marker(row,watermarkKey),row.created_at); } finally { source.fill(0); }
    if (hash(output) !== row.digest) throw fail(409,'Prepared output changed. Nothing was released.');
    const current = permission(req,doc.id).doc;
    if (current.epoch !== row.epoch || db.prepare('SELECT status FROM issuances WHERE id=?').get(row.id).status==='cancelled') throw fail(409,'Session changed while processing. Nothing was released.');
    if (!verifyAudit(db).valid) throw fail(409,'Audit integrity check failed. Release blocked.');
    transaction(db,()=>{
      if (!db.prepare('SELECT signature FROM issuances WHERE id=?').get(row.id).signature) {
        db.prepare("UPDATE issuances SET signature=?,attestation=?,status='issued' WHERE id=?").run(signature,sign(Buffer.from(row.event),from64(device.secretKey)),row.id);
        audit(req.user.id,'COPY_ISSUED',{sessionId:row.id,documentId:doc.id,outputDigest:row.digest,recipientSignature:'ML-DSA-65',ledgerFinality:false});
      }
    });
    res.set({'Content-Type':'application/pdf','Content-Disposition':`attachment; filename="ciphertrail-${row.id}.pdf"`,'X-Issuance-Id':row.id});
    res.send(output);
  });
  app.get('/api/issuances',(req,res)=>{
    const rows = req.user.role==='admin' ? db.prepare('SELECT * FROM issuances ORDER BY created_at DESC LIMIT 200').all() : db.prepare('SELECT * FROM issuances WHERE recipient_id=? ORDER BY created_at DESC LIMIT 200').all(req.user.id);
    res.json(rows.map(row=>({id:row.id,documentId:row.document_id,documentName:db.prepare('SELECT name FROM documents WHERE id=?').get(row.document_id).name,recipientId:row.recipient_id,status:row.status,createdAt:row.created_at,digest:row.digest,signatureVerified:!!row.signature && verify(Buffer.from(row.event),Buffer.from(row.signature),from64(db.prepare('SELECT sign_public FROM users WHERE id=?').get(row.recipient_id).sign_public))})));
  });
  function evidence(row) {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(row.recipient_id);
    return {format:'ciphertrail-evidence-v1',event:b64(row.event),signature:row.signature?b64(row.signature):null,recipient:{id:user.id,name:user.name,keyId:user.key_id,publicKey:user.sign_public},devicePublicKey:device.publicKey,attestation:row.attestation?b64(row.attestation):null,outputDigest:row.digest,ledgerFinality:false,trust:'Keys are supplied by this demo server; independent enrollment and BFT proofs are not implemented.'};
  }
  app.get('/api/issuances/:id/evidence',(req,res)=>{
    const row = db.prepare('SELECT * FROM issuances WHERE id=?').get(req.params.id);
    if (!row || (req.user.role!=='admin' && req.user.id!==row.recipient_id)) throw fail(404,'Session not found.');
    res.json(evidence(row));
  });
  app.post('/api/investigate',admin,upload,async(req,res)=>{
    if (!req.file) throw fail(400,'Select a PDF to investigate.'); capacity(20000);
    const digest = hash(req.file.buffer), token = await extractMarker(req.file.buffer);
    const row = db.prepare("SELECT * FROM issuances WHERE digest=? AND status='issued'").get(digest);
    let result = {classification:'INCONCLUSIVE',message:'No exact issued copy matched. Edited files, screenshots and print/scan are outside this demo profile.',artifactHash:digest,markerPresent:!!token,ledgerFinality:false};
    if (row) {
      const bundle = evidence(row);
      const signedEvent = cbor.decodeFirstSync(Buffer.from(row.event));
      const markerValid = token === marker(row,watermarkKey);
      const signatureValid = signedEvent.outputDigest===digest && signedEvent.recipientId===row.recipient_id && signedEvent.sessionId===row.id && verify(Buffer.from(row.event),Buffer.from(row.signature),from64(bundle.recipient.publicKey));
      const attestationValid = !!row.attestation && verify(Buffer.from(row.event),Buffer.from(row.attestation),from64(device.publicKey));
      const auditValid = verifyAudit(db).valid;
      if (markerValid && signatureValid && attestationValid && auditValid) result = {...result,classification:'EXACT_ISSUED_COPY',message:'This PDF exactly matches a copy issued by this demo. It associates the issued copy, not personal responsibility for a leak.',sessionId:row.id,recipient:bundle.recipient.name,recipientId:row.recipient_id,documentName:db.prepare('SELECT name FROM documents WHERE id=?').get(row.document_id).name,issuedAt:row.created_at,checks:{digest:true,marker:true,recipientSignature:true,deviceAttestation:true,localAudit:true},evidence:bundle};
      else result = {...result,classification:'INVALID_EVIDENCE',message:'A matching record exists, but one or more integrity checks failed.',checks:{marker:markerValid,recipientSignature:signatureValid,deviceAttestation:attestationValid,localAudit:auditValid}};
    }
    result.caseId = randomUUID(); result.createdAt = now();
    transaction(db,()=>{
      db.prepare('INSERT INTO cases VALUES (?,?,?,?)').run(result.caseId,digest,JSON.stringify(result),result.createdAt);
      audit(req.user.id,'ARTIFACT_INVESTIGATED',{caseId:result.caseId,classification:result.classification,artifactHash:digest});
    });
    req.file.buffer.fill(0); res.json(result);
  });
  app.get('/api/cases',admin,(req,res)=>res.json(db.prepare('SELECT result FROM cases ORDER BY created_at DESC LIMIT 50').all().map(r=>JSON.parse(r.result))));
  app.get('/api/audit',admin,(req,res)=>res.json({verification:verifyAudit(db),ledgerFinality:false,entries:db.prepare('SELECT * FROM audit ORDER BY seq DESC LIMIT 150').all().map(r=>({...r,payload:JSON.parse(r.payload)}))}));
  app.get('/api/status',(req,res)=>res.json({mode:'working-demo',accountCount:db.prepare('SELECT COUNT(*) AS n FROM users').get().n,storageBytes:directorySize(directory),storageLimitBytes:storageLimit,maxFileBytes:MAX_FILE,ledgerFinality:false,algorithms:{envelopes:'ML-KEM-768',signatures:'ML-DSA-65',encryption:'AES-256-GCM',derivation:'HKDF-SHA-384',hash:'SHA-384',encoding:'Canonical CBOR',watermark:'HMAC-SHA-384 / 192-bit structural PDF mark'},secureCookies}));
  app.use('/api',(req,res)=>res.status(404).json({error:'API route not found.'}));
  app.use(express.static(path.join(root,'dist'),{index:false}));
  app.get('/{*path}',(req,res)=>res.sendFile(path.join(root,'dist','index.html')));
  app.use((error,req,res,next)=>{
    if (res.headersSent) return next(error);
    const status = error.code==='LIMIT_FILE_SIZE'?413:error instanceof multer.MulterError?400:error.status || (error.message?.includes('PDF')?400:500);
    if (status===500) console.error('Request failed:',error.message);
    res.status(status).json({error:status===413?'PDF must be 10 MB or smaller.':status===500?'The operation could not be completed. Check the server log.':error.message});
  });
  return {app,store,close:()=>db.close()};
}
