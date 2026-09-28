import React,{useEffect,useState} from 'react';
import {AreaChart,Area,BarChart,Bar,XAxis,YAxis,CartesianGrid,Tooltip,ResponsiveContainer,Legend} from 'recharts';
import {ml_dsa65} from '@noble/post-quantum/ml-dsa.js';
import {encode} from 'cborg';
import {Button} from '../components/ui/button';
import {ClientDecryptButton} from '../crypto/ClientDecryptButton';
import {encryptPdfForRecipients,toBase64,digest} from '../crypto/clientDocument';
import {recordLedgerEvent} from '../crypto/ledgerRecorder';
import {request,download,decode64} from './api';
import {Panel,Heading,Badge,Empty,time,short,size} from './components';

export function ActivityGraphs({events=[],docs=[]}) {
  const [days,setDays]=useState(7);
  const data=Array.from({length:days},(_,i)=>{
    const date=new Date();date.setHours(0,0,0,0);date.setDate(date.getDate()-days+1+i);
    const end=new Date(date);end.setDate(end.getDate()+1);
    const inDay=value=>{const n=Date.parse(value);return n>=+date&&n<+end;};
    return {date:date.toLocaleDateString(undefined,{month:'short',day:'numeric'}),uploads:docs.filter(d=>inDay(d.created_at||d.createdAt)).length,issued:events.filter(e=>e.status==='issued'&&inDay(e.createdAt)).length};
  });
  return <Panel title="Issuance activity" description="Documents and signed copies over time." action={<select aria-label="Activity period" value={days} onChange={e=>setDays(Number(e.target.value))}><option value={7}>7 days</option><option value={30}>30 days</option></select>}>
    <div className="connected-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="date"/><YAxis allowDecimals={false}/><Tooltip/><Legend/><Area type="monotone" name="Uploaded documents" dataKey="uploads" stroke="#2563eb" fill="#dbeafe"/><Area type="monotone" name="Signed copies" dataKey="issued" stroke="#0d9488" fill="#ccfbf1"/></AreaChart></ResponsiveContainer></div>
    <details><summary>View chart data</summary><table><thead><tr><th>Date</th><th>Uploads</th><th>Signed copies</th></tr></thead><tbody>{data.map(d=><tr key={d.date}><td>{d.date}</td><td>{d.uploads}</td><td>{d.issued}</td></tr>)}</tbody></table></details>
  </Panel>;
}
const readJson=async file=>{if(!file||file.size>128000)throw new Error('Choose a JSON file smaller than 128 KB');return JSON.parse(await file.text());};
const checkSigning=key=>{
  const secret=decode64(key.secretKey),pub=decode64(key.publicKey);
  if(secret.length!==4032||pub.length!==1952||toBase64(ml_dsa65.getPublicKey(secret))!==key.publicKey)throw new Error('Invalid ML-DSA-65 key pair');
  return key;
};
function FileInput({label,onFile,accept='.json'}) {return <label className="connected-file">{label}<input type="file" accept={accept} onChange={e=>{const file=e.target.files[0];e.target.value='';if(file)onFile(file);}}/></label>;}

export function ClientWorkspace({user,keys,users,run}) {
  const admin=user.role==='admin';
  const [data,setData]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[gov,setGov]=useState(null),[sender,setSender]=useState(null),[senderPin,setSenderPin]=useState(null),[selected,setSelected]=useState([]),[file,setFile]=useState(null),[opening,setOpening]=useState(null),[verifiedDirectory,setVerifiedDirectory]=useState(false);
  async function refresh(){try{setData(await request('/client/workspace'));setError('');}catch(e){setError(e.message);}}
  useEffect(()=>{refresh();},[]);
  async function action(fn){setBusy(true);try{await fn();await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}
  async function govern(operation,value){
    if(!gov)throw new Error('Load your local governance key file first');
    const current=await request('/client/workspace');
    if(!current.available)throw new Error(current.error);
    if(gov.publicKey!==current.authorityPublicKey)throw new Error('Governance key does not match network authority');
    const event=encode({domain:'CipherTrail/ledger-governance/v1',networkId:current.networkId,sequence:current.sequence+1,operation,value});
    return request('/client/governance',{method:'POST',body:{eventBytes:toBase64(event),signature:toBase64(ml_dsa65.sign(event,decode64(gov.secretKey)))}});
  }
  async function authorize(doc,recipients=doc.recipients){await govern('document',{documentId:doc.id,documentVersion:1,policyEpoch:(doc.policy?.policyEpoch||0)+1,packageDigest:doc.packageDigest,recipients});}
  async function upload(e){e.preventDefault();await action(async()=>{
    if(!sender||!file||!selected.length||!verifiedDirectory)throw new Error('Load sender keys, verify recipient fingerprints and select a PDF and recipients');
    if(file.size>10*1024*1024)throw new Error('PDF must be at most 10 MB');
    const recipients=users.filter(u=>selected.includes(u.id)).map(u=>({recipientId:u.id,keyId:u.keyId,kemPublicKey:decode64(u.kemPublic)}));
    const pkg=await encryptPdfForRecipients({pdfBytes:new Uint8Array(await file.arrayBuffer()),documentId:crypto.randomUUID(),filename:file.name,recipients,senderSigningPrivateKey:decode64(sender.secretKey)});
    const body=new FormData();body.append('payload',new Blob([pkg.encryptedPayload]),'ciphertext.bin');body.append('manifestBytes',toBase64(pkg.manifestBytes));body.append('senderSignature',toBase64(pkg.senderSignature));body.append('senderPublicKey',sender.publicKey);
    await request('/client/documents',{method:'POST',body});setFile(null);
  });}
  async function open(doc){await action(async()=>{
    if(!keys)throw new Error('Load your recipient private key file in My private keys first');
    if(!senderPin)throw new Error('Import the sender public trust file supplied through your trusted channel');
    const pkg=await request(`/client/documents/${doc.id}/package`);
    const pub=decode64(senderPin.publicKey);
    if(pub.length!==1952||await digest(pub,'CipherTrail/sender-key/v1')!==doc.senderKeyId)throw new Error('Pinned sender key does not match this package');
    setOpening({id:doc.id,pkg:{manifestBytes:decode64(pkg.manifestBytes),senderSignature:decode64(pkg.senderSignature),encryptedPayload:decode64(pkg.encryptedPayload)},publicKey:pub,issuance:{networkId:pkg.networkId,sessionId:crypto.randomUUID(),policyEpoch:pkg.policyEpoch,createdAt:new Date().toISOString()}});
  });}
  const enrolled=users.filter(u=>u.role==='recipient'&&u.keyId);
  return <><Heading title="Client-encrypted documents" description="Protect a document, choose its recipients and track every signed copy."><Button disabled={busy} onClick={()=>action(refresh)}>Refresh</Button></Heading>
    {(error||data?.error)&&<div className="live-alert" role="alert">{error||data.error}</div>}
    
    {admin?<>
      <Panel title="1. Load your keys" description="Private keys stay on this computer.">
        <div className="connected-controls"><FileInput label={gov?'Governance key loaded':'Load governance private key'} onFile={f=>action(async()=>setGov(checkSigning(await readJson(f))))}/><FileInput label={sender?'Sender key loaded':'Load sender private key'} onFile={f=>action(async()=>setSender(checkSigning(await readJson(f))))}/>
          <Button disabled={busy||!!sender} onClick={()=>action(async()=>{const k=ml_dsa65.keygen(),value={publicKey:toBase64(k.publicKey),secretKey:toBase64(k.secretKey)};setSender(value);download(value,'sender-PRIVATE-keys.json');})}>Create sender key</Button>
          {sender&&<Button variant="outline" onClick={()=>download({publicKey:sender.publicKey},'sender-public-trust.json')}>Export sender public trust</Button>}
        </div><p className="live-help">Share the public trust file with recipients. Keep private keys to yourself.</p>
      </Panel>
      <Panel title="2. Authorize recipients" description="Verify each participant�s key fingerprint before granting access.">
        <label><input type="checkbox" checked={verifiedDirectory} onChange={e=>setVerifiedDirectory(e.target.checked)}/> I checked the selected recipients’ public-key fingerprints through a trusted channel.</label>
        {enrolled.map(u=><div className="live-list-row" key={u.id}><div><strong>{u.id}</strong><code className="live-hash">{u.keyId}</code></div><Badge>{data?.identities.find(i=>i.recipientId===u.id)?.active?'Active on ledger':'Not active'}</Badge><Button disabled={busy||!gov||!verifiedDirectory} onClick={()=>action(()=>govern('identity',{recipientId:u.id,keyId:u.keyId,publicKey:decode64(u.signPublic),active:true}))}>Authorize identity</Button><Button variant="outline" disabled={busy||!gov} onClick={()=>action(()=>govern('identity',{recipientId:u.id,keyId:u.keyId,publicKey:decode64(u.signPublic),active:false}))}>Revoke</Button></div>)}
        {!enrolled.length&&<Empty>Recipients must first register keys in My private keys.</Empty>}
        <Button variant="outline" disabled={!data?.identities.length} onClick={()=>download({networkId:data.networkId,identities:data.identities.map(i=>({recipientId:i.recipientId,keyId:i.keyId,publicKey:i.publicKey}))},'trusted-identities.json')}>Export public forensic registry</Button><p className="live-help">Check fingerprints before sharing this public registry with investigators.</p>
      </Panel>
      <Panel title="3. Protect a PDF" description="Your file is encrypted here before it is uploaded."><form onSubmit={upload}><FileInput label={file?file.name:'Choose source PDF'} accept=".pdf" onFile={setFile}/>{enrolled.map(u=><label className="connected-choice" key={u.id}><input type="checkbox" checked={selected.includes(u.id)} onChange={e=>setSelected(e.target.checked?[...selected,u.id]:selected.filter(id=>id!==u.id))}/>{u.name}</label>)}<Button disabled={busy||!file||!sender||!selected.length||!verifiedDirectory}>{busy?'Processing…':'Encrypt locally & upload'}</Button></form></Panel>
    </>:<Panel title="Trust the sender" description="Import a public key obtained directly from the sender. Your recipient private keys are loaded separately on My private keys."><FileInput label={senderPin?'Sender public key pinned for this session':'Import sender public trust JSON'} onFile={f=>action(async()=>{const p=await readJson(f);if(decode64(p.publicKey||'').length!==1952)throw new Error('Expected sender ML-DSA public key');setSenderPin(p);})}/><Badge tone={keys?'success':'warning'}>{keys?'Recipient private keys loaded':'Recipient keys not loaded'}</Badge></Panel>}
    <Panel title={admin?'4. Authorize packages':'Encrypted package library'} description="Grant or revoke access to a protected package.">
      {data?.documents.length?<div className="table-scroll"><table><thead><tr><th>Document</th><th>Ledger policy</th><th>Actions</th></tr></thead><tbody>{data.documents.map(doc=><tr key={doc.id}><td><strong>{doc.name}</strong><small className="live-subtext">{size(doc.size)} · {short(doc.senderKeyId)}</small></td><td>{doc.policy?.recipients.length?`Epoch ${doc.policy.policyEpoch} · ${doc.policy.recipients.join(', ')}`:'No active permission'}</td><td>{admin?<><Button size="sm" disabled={busy||!gov} onClick={()=>action(()=>authorize(doc))}>Grant access</Button> <Button size="sm" variant="outline" disabled={busy||!gov||!doc.policy} onClick={()=>action(()=>authorize(doc,[]))}>Revoke access</Button></>:<Button disabled={busy||!doc.policy?.recipients.includes(user.id)} onClick={()=>open(doc)}>Open locally</Button>}</td></tr>)}</tbody></table></div>:<Empty>No client-encrypted packages yet.</Empty>}
    </Panel>
    {opening&&<Panel title="Prepare and approve your marked copy" description="The session ID stays fixed during retries."><ClientDecryptButton key={opening.issuance.sessionId} encryptedPackage={opening.pkg} recipient={{recipientId:user.id,keyId:user.keyId,kemPrivateKey:decode64(keys.kemSecret)}} recipientSigningPrivateKey={decode64(keys.signSecret)} registeredSigningPublicKey={decode64(user.signPublic)} trustedSenderPublicKey={opening.publicKey} issuance={opening.issuance} visualWatermark={true} recordEvent={async e=>{await recordLedgerEvent(e);await refresh();}}/></Panel>}
    <ClientSessions data={data}/>
  </>;
}
function ClientSessions({data}){
  const [error,setError]=useState('');
  return <Panel title="Committed client sessions" description="Signed copies and their committed block numbers.">{error&&<p role="alert">{error}</p>}{data?.sessions.length?<div className="table-scroll"><table><thead><tr><th>Session</th><th>Recipient</th><th>Block</th><th>Evidence</th></tr></thead><tbody>{data.sessions.slice().reverse().map(r=><tr key={r.event.sessionId}><td><code>{short(r.event.sessionId)}</code><small className="live-subtext">{time(r.event.createdAt)}</small></td><td>{r.event.recipientId}</td><td>{r.height}</td><td><Button size="sm" variant="outline" onClick={async()=>{try{download(await request('/client/evidence/'+r.event.sessionId),'evidence-'+r.event.sessionId+'.json');}catch(e){setError(e.message);}}}>Export signed record</Button></td></tr>)}</tbody></table></div>:<Empty>No client sessions committed.</Empty>}</Panel>;
}
function IssuanceGraph({data}) {
  const [chosen,setChosen]=useState(''),[session,setSession]=useState(null);
  const records=data?.sessions||[];
  const ids=[...new Set(records.map(r=>r.event.documentId))];
  const id=ids.includes(chosen)?chosen:ids[0];
  const selected=records.filter(r=>r.event.documentId===id);
  const visible=selected.slice(-6);
  const height=Math.max(170,visible.length*80+30);
  const name=data?.documents.find(d=>d.id===id)?.name||id;
  return <Panel title="Document-to-session graph" description="Select a document and explore its signed copies." action={ids.length>0&&<select aria-label="Graph document" value={id} onChange={e=>{setChosen(e.target.value);setSession(null);}}>{ids.map(i=><option key={i} value={i}>{data?.documents.find(d=>d.id===i)?.name||short(i)}</option>)}</select>}>
    {!visible.length?<Empty>A committed client issuance will appear here.</Empty>:<><div style={{overflowX:'auto'}}><svg viewBox={`0 0 760 ${height}`} style={{width:'100%',minWidth:560}} role="img" aria-label={`Signed issuance relationships for ${name}`}>
      <rect x="10" y={height/2-30} width="200" height="60" rx="10" fill="#dbeafe"/><text x="25" y={height/2-4} fill="#1e40af" fontSize="13">Encrypted document</text><text x="25" y={height/2+16} fill="#334155" fontSize="11">{String(name).slice(0,26)}</text>
      {visible.map((r,i)=>{const y=25+i*80;return <g key={r.event.sessionId}><path d={`M 210 ${height/2} C 280 ${height/2},280 ${y+25},340 ${y+25}`} fill="none" stroke="#94a3b8"/><g role="button" tabIndex={0} aria-label={`Inspect session ${r.event.sessionId}`} onClick={()=>setSession(r)} onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();setSession(r);}}} style={{cursor:'pointer'}}><rect x="340" y={y} width="400" height="54" rx="9" fill={session?.event.sessionId===r.event.sessionId?'#ccfbf1':'#f1f5f9'} stroke="#cbd5e1"/><text x="355" y={y+21} fill="#334155" fontSize="13">{r.event.recipientId.length>30?short(r.event.recipientId):r.event.recipientId} · block {r.height}</text><text x="355" y={y+40} fill="#64748b" fontSize="11">{short(r.event.sessionId)}</text></g></g>;})}
    </svg></div><p className="live-help">Showing the latest {visible.length} of {selected.length} signed sessions for this document. </p>{session&&<div className="live-detail"><span>Session</span><code>{session.event.sessionId}</code><span>Transaction</span><code>{session.txHash}</code><span>Profile</span><strong>{session.event.watermarkProfile}</strong></div>}</>}
  </Panel>;
}
export function LedgerDashboard(){
  const [data,setData]=useState(null),[nodes,setNodes]=useState([]),[blocks,setBlocks]=useState([]),[error,setError]=useState(''),[updated,setUpdated]=useState(null);
  async function refresh(){try{const [d,n,b]=await Promise.all([request('/client/workspace'),request('/client/validators'),request('/client/blocks').catch(()=>[])]);setData(d);setNodes(n);setBlocks(b);setUpdated(new Date());setError('');}catch(e){setError(e.message);}}
  useEffect(()=>{refresh();const timer=setInterval(refresh,10000);return()=>clearInterval(timer);},[]);
  const events=(data?.sessions||[]).map(r=>({createdAt:r.event.createdAt,status:'issued'}));
  const online=nodes.filter(n=>n.online).length;
  const recent=nodes.some(n=>n.online&&n.blockAgeSeconds<30&&!n.catchingUp);
  const phase=n=>!n.online?'Offline':n.catchingUp?'Syncing':({1:'New height',2:'New round',3:'Proposing',4:'Prevoting',5:'Awaiting prevotes',6:'Precommitting',7:'Awaiting precommits',8:'Committing'}[Number(n.round?.split('/')[2])]||'Status unavailable');
  return <><Heading title="Network health" description={updated?`Updated ${updated.toLocaleTimeString()} · refreshes every 10 seconds`:'Connecting to validators…'}><Button onClick={refresh}>Refresh network</Button></Heading>{(error||data?.error)&&<div className="live-alert">{error||data.error}</div>}
    <div className="stats-grid">{[['Nodes online',`${online}/${nodes.length||3}`],['Block height',data?.height??'—'],['Recorded transactions',data?.transactionCount??'—'],['Consensus',!nodes.length?'Checking':recent?'Producing blocks':online?'Waiting for progress':'Unavailable']].map(([label,value])=><div className="stat-card" key={label}><div className="stat-top">{label}</div><strong className="network-value">{value}</strong></div>)}</div>
    <div className="identity-grid">{nodes.map(n=><div className="identity-card" key={n.name}><div className="identity-card-top"><h3>{n.name}</h3><Badge tone={n.online?'success':'warning'}>{n.online?'Online':'Offline'}</Badge></div><p>Block <strong>{n.height||'—'}</strong></p><p>{phase(n)}{n.round?` · round ${n.round.split('/')[1]}`:''}</p><small>{n.blockTime?`Latest block ${time(n.blockTime)}`:'Waiting for a response'}</small>{n.blockAgeSeconds>60&&<p><Badge tone="warning">Block production delayed</Badge></p>}</div>)}</div>
    <div className="live-columns"><Panel title="Block production" description="Latest 20 blocks · time between consecutive blocks."><div className="connected-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={blocks}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="height" minTickGap={30}/><YAxis/><Tooltip/><Area dataKey="interval" name="Block interval (seconds)" stroke="#0d9488" fill="#ccfbf1" connectNulls/></AreaChart></ResponsiveContainer></div>{!blocks.length&&<p>Block history is unavailable.</p>}</Panel>
    <Panel title="Transactions per block" description="Included transactions in the latest 20 blocks."><div className="connected-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={blocks}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="height" minTickGap={30}/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="transactions" fill="#2563eb" name="Transactions"/></BarChart></ResponsiveContainer></div></Panel></div>
    <Panel title="Node synchronization"><div className="connected-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={nodes.map(n=>({...n,height:n.online?Number(n.height):null}))}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="height" fill="#2563eb" name="Block height"/></BarChart></ResponsiveContainer></div></Panel>
    <ActivityGraphs events={events} docs={data?.documents||[]}/><IssuanceGraph data={data}/><ClientSessions data={data}/>
    <Panel title="Evidence export"><Button disabled={!data?.available} onClick={async()=>{try{download(await request('/client/snapshot'),'ledger-snapshot.json');}catch(e){setError(e.message);}}}>Export signed event snapshot</Button><details className="verification-details"><summary>Network & verification details</summary><p>Recorded transactions counts accepted governance and issuance events. Per-block counts include all included transactions, including rejected executions. Three equal-power nodes require all three votes. Status is read from node RPCs; exported evidence does not independently verify consensus proofs.</p></details></Panel>
  </>;
}
export function VisualInvestigation(){
  const [file,setFile]=useState(null),[trust,setTrust]=useState(null),[result,setResult]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[cases,setCases]=useState([]);
  async function refresh(){setCases((await request('/cases')).filter(c=>c.profile==='dct-footer-v1'));}
  useEffect(()=>{refresh().catch(e=>setError(e.message));},[]);
  async function submit(e){e.preventDefault();setBusy(true);setError('');setResult(null);try{const body=new FormData();body.append('artifact',file);body.append('trust',trust);setResult(await request('/client/investigate',{method:'POST',body}));await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}
  return <><Heading title="Screenshot investigation" description="Find the signed record associated with a leaked copy."/><div className="live-columns"><Panel title="Examine an artifact" description="Upload a PDF or image for analysis on this server."><form onSubmit={submit}><FileInput label={file?file.name:'Choose PDF, PNG or JPEG (10 MB max)'} accept=".pdf,.png,.jpg,.jpeg" onFile={setFile}/><FileInput label={trust?trust.name:'Choose public trusted-identities JSON'} onFile={setTrust}/><Button disabled={busy||!file||!trust||file.size>10*1024*1024||trust.size>128000}>{busy?'Extracting and verifying…':'Run forensic extraction'}</Button></form>{error&&<p role="alert">{error}</p>}<p className="live-help">Use a public identity registry. Include the watermark in the image.</p></Panel><Panel title="Forensic Attribution Report">{result?<><Badge tone={result.status==='SIGNED_ISSUANCE_MATCH'?'success':'warning'}>{result.status}</Badge><p>{result.status==='SIGNED_ISSUANCE_MATCH'?'A signed issuance record matches this copy.':result.reason}</p>{result.matches?.map(m=><div className="live-detail" key={m.sessionId}><span>Recipient</span><strong>{m.recipientId}</strong><span>Session</span><code>{m.sessionId}</code><span>Signature</span><strong>{m.signature}</strong><span>Exact PDF bytes</span><strong>{m.exact_issued_pdf?'Match':'Visual association only'}</strong></div>)}<details className="verification-details"><summary>Verification details</summary><p>Signature checked against your trusted public key. Independent consensus verification: {result.ledger_finality}. The result associates a copy; it does not identify who shared it.</p></details><Button variant="outline" onClick={()=>download(result,`forensic-${result.caseId}.json`)}>Export report</Button></>:<Empty>Choose an artifact and its trusted identity registry.</Empty>}</Panel></div><Panel title="Saved visual investigations">{cases.length?cases.map(c=><button className="live-case-button" key={c.caseId} onClick={()=>setResult(c)}><strong>{c.status}</strong><span>{time(c.createdAt)}</span><code>{short(c.caseId)}</code></button>):<Empty>No visual investigations yet.</Empty>}</Panel></>;
}
