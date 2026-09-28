import React, {useCallback,useEffect,useState} from 'react';
import {NavLink,Routes,Route,Navigate,useNavigate} from 'react-router-dom';
import {ShieldCheck,Files,Fingerprint,ScanSearch,UsersRound,Settings2,LayoutDashboard,LockKeyhole,LogOut,RefreshCw,KeyRound,ArrowRight,Menu,Layers3} from 'lucide-react';
import {Toaster,toast} from 'sonner';
import {Button} from '../components/ui/button';
import {Dialog,DialogContent} from '../components/ui/dialog';
import {request,download,requestId} from './api';
import {generateKeys,enrollment,validateKeys,unlockEnvelope,signEvent} from './keys';
import {Badge} from './components';
import {ClientWorkspace,LedgerDashboard,VisualInvestigation} from './connected';
import {Overview,Documents,UploadDialog,PermissionDialog,KeyPanel,Sessions,Investigation,Audit,People,Settings} from './pages';

export default function App() {
  const [user,setUser]=useState(null),[checking,setChecking]=useState(true),[connectionError,setConnectionError]=useState('');
  const [keys,setKeys]=useState(null),[docs,setDocs]=useState([]),[events,setEvents]=useState([]),[users,setUsers]=useState([]),[status,setStatus]=useState(null),[busy,setBusy]=useState(false),[mobile,setMobile]=useState(false);
  const [prepared,setPrepared]=useState(null),[upload,setUpload]=useState(false),[editing,setEditing]=useState(null),[deleting,setDeleting]=useState(null);
  const [clientState,setClientState]=useState(null);
  const navigate=useNavigate();
  const refresh=useCallback(async()=>{
    const [d,e,s,u,c]=await Promise.all([request('/documents'),request('/issuances'),request('/status'),user?.role==='admin'?request('/users'):Promise.resolve([]),request('/client/workspace').catch(()=>null)]);
    setDocs(d);setEvents(e);setStatus(s);setUsers(u);setClientState(c);setConnectionError('');
  },[user?.role]);
  useEffect(()=>{request('/me').then(setUser).catch(error=>{if(error.status!==401)setConnectionError('Server unavailable. Start the CipherTrail server and refresh.');}).finally(()=>setChecking(false));},[]);
  useEffect(()=>{
    if(!user)return;
    let active=true;
    const update=()=>refresh().catch(error=>{if(!active)return;if(error.status===401){setUser(null);setKeys(null);setPrepared(null);}else setConnectionError(error.message);});
    update();const timer=setInterval(update,10000);return()=>{active=false;clearInterval(timer)};
  },[user,refresh]);
  async function run(action) {setBusy(true);try{return await action();}catch(error){toast.error(error.message);return null;}finally{setBusy(false);}}
  async function logout(){await run(async()=>{await request('/logout',{method:'POST'});setUser(null);setKeys(null);setPrepared(null);setDocs([]);setEvents([]);navigate('/');});}
  async function createKeys(){await run(async()=>{const value=generateKeys(user.id);setKeys(value);download(value,`${user.id}-PRIVATE-keys.json`);setUser(await request('/keys',{method:'POST',body:enrollment(value)}));toast.success('Public keys registered. Keep your downloaded private key file.');});}
  async function loadKeys(file){if(!file)return;await run(async()=>{if(file.size>40000)throw new Error('Key file is too large.');const value=validateKeys(JSON.parse(await file.text()),user);if(!user.keyId)setUser(await request('/keys',{method:'POST',body:enrollment(value)}));setKeys(value);toast.success('Private keys loaded on this computer.');});}
  async function prepare(doc){await run(async()=>{
    if(!keys){navigate('/keys');throw new Error('Load your private key file before opening this document.');}
    const envelope=await request(`/documents/${doc.id}/envelope`);
    setPrepared(await request(`/documents/${doc.id}/prepare`,{method:'POST',body:{requestId:requestId(),sharedSecret:unlockEnvelope(envelope,keys)}}));
  });}
  async function release(){await run(async()=>{const blob=await request(`/issuances/${prepared.id}/release`,{method:'POST',body:{signature:signEvent(prepared.event,keys)},blob:true});download(blob,`CipherTrail-${prepared.summary.recipientId}-${prepared.id.slice(0,8)}.pdf`);setPrepared(null);toast.success('Signature verified. Your uniquely marked PDF is ready.');await refresh();});}
  async function cancel(){await run(async()=>{await request(`/issuances/${prepared.id}/cancel`,{method:'POST'});setPrepared(null);await refresh();toast('Signing declined. No PDF was released.');});}
  if(checking)return <div className="live-loading"><ShieldCheck size={30}/><p>Connecting to your workspace…</p></div>;
  if(!user)return <><Login onLogin={setUser} connectionError={connectionError}/><Toaster richColors position="bottom-right"/></>;
  const admin=user.role==='admin';
  const links=[['/','Overview',LayoutDashboard],['/client','Client documents',LockKeyhole],['/documents','Documents',Files],['/issuance','Decryption sessions',Fingerprint],...(admin?[['/visual-investigation','Screenshot investigation',ScanSearch],['/investigation','Exact PDF investigation',ScanSearch],['/network','Live ledger',Layers3],['/ledger','Activity history',Layers3],['/identities','People & access',UsersRound]]:[['/keys','My private keys',KeyRound]]),['/settings','Settings',Settings2]];
  return <div className="live-app"><div className={`sidebar-backdrop ${mobile?'visible':''}`} onClick={()=>setMobile(false)}/><aside className={`sidebar ${mobile?'open':''}`}><NavLink to="/" className="brand"><ShieldCheck className="brand-icon" size={27}/>CipherTrail<span className="brand-dot">.</span></NavLink><div className="enclave-select"><span className="enclave-symbol"><LockKeyhole size={19}/></span><div><strong>Workspace</strong><small>Real files · Real access checks</small></div></div><nav><div className="nav-label">WORKSPACE</div>{links.map(([url,label,Icon])=><NavLink key={url} to={url} end={url==='/'} className={({isActive})=>`nav-item ${isActive?'active':''}`} onClick={()=>setMobile(false)}><Icon size={19}/>{label}</NavLink>)}</nav><div className="sidebar-bottom"><div className="airgap-card"><KeyRound size={20}/><strong>SRS cryptography profile</strong><p>ML-KEM-768 · ML-DSA-65<br/>AES-256-GCM · SHA-384</p><span>FUNCTIONAL DEMO · V2</span></div><div className="profile"><span className="avatar">{admin?'AD':user.id.endsWith('a')?'RA':'RB'}</span><div><strong>{user.name}</strong><small>{admin?'Administrator & investigator':'Authorized recipient'}</small></div><button className="icon-button logout-button" onClick={logout} disabled={busy} aria-label="Sign out"><LogOut size={18}/></button></div></div></aside><div className="workspace"><header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-toggle" onClick={()=>setMobile(true)} aria-label="Open navigation"><Menu/></button><ShieldCheck size={17}/><span>Workspace</span><span>/</span><strong>{user.name}</strong></div><div className="topbar-actions"><Badge tone={connectionError?'warning':'success'}>{connectionError?'Connection needs attention':'Shared server connected'}</Badge><Button variant="ghost" size="sm" disabled={busy} onClick={()=>run(refresh)}><RefreshCw size={15}/>Refresh</Button></div></header><main>
    {connectionError&&<div className="live-alert" role="alert">{connectionError}</div>}
    <Routes>
      <Route path="/" element={<Overview docs={[...docs,...(clientState?.documents||[])]} events={[...events,...(clientState?.sessions||[]).map(r=>({id:r.event.sessionId,status:'issued',recipientId:r.event.recipientId,createdAt:r.event.createdAt,documentName:clientState.documents.find(d=>d.id===r.event.documentId)?.name||r.event.documentId}))].sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt))} {...{user,status}} onUpload={()=>navigate('/client')} keysReady={!!keys}/>}/>
      <Route path="/client" element={<ClientWorkspace key={user.id} {...{user,keys,users,run}}/>}/>
      <Route path="/network" element={admin?<LedgerDashboard/>:<Navigate to="/" replace/>}/>
      <Route path="/visual-investigation" element={admin?<VisualInvestigation/>:<Navigate to="/" replace/>}/>
      <Route path="/documents" element={<Documents {...{docs,admin,busy}} onUpload={()=>setUpload(true)} onEdit={setEditing} onDelete={setDeleting} onPrepare={prepare}/>}/>
      <Route path="/issuance" element={<Sessions {...{events,busy}} run={run} canResume={!admin} onResume={id=>run(async()=>{if(!keys){navigate('/keys');throw new Error('Load your private key file first.');}setPrepared(await request(`/issuances/${id}/prepared`));})}/>}/>
      <Route path="/investigation" element={admin?<Investigation run={run} busy={busy}/>:<Navigate to="/" replace/>}/>
      <Route path="/ledger" element={admin?<Audit run={run}/>:<Navigate to="/" replace/>}/>
      <Route path="/identities" element={admin?<People users={users}/>:<Navigate to="/" replace/>}/>
      <Route path="/keys" element={!admin?<KeyPanel {...{user,keys,busy}} onGenerate={createKeys} onLoad={loadKeys}/>:<Navigate to="/" replace/>}/>
      <Route path="/settings" element={<Settings status={status}/>}/>
      <Route path="*" element={<Navigate to="/" replace/>}/>
    </Routes><footer><span><ShieldCheck size={14}/>CipherTrail · Document security</span><span>Client crypto · Visual extraction · Live ledger · Legacy audit</span></footer>
  </main></div>
  <UploadDialog open={upload} close={()=>setUpload(false)} users={users} busy={busy} submit={(file,recipients)=>run(async()=>{const body=new FormData();body.append('file',file);body.append('recipients',JSON.stringify(recipients));await request('/documents',{method:'POST',body});setUpload(false);await refresh();navigate('/documents');toast.success('PDF encrypted and sender-signed.');})}/>
  <PermissionDialog doc={editing} close={()=>setEditing(null)} {...{users,busy}} submit={recipients=>run(async()=>{await request(`/documents/${editing.id}/permissions`,{method:'PUT',body:{recipients}});setEditing(null);await refresh();toast.success('Access policy and ML-KEM envelopes updated.');})}/>
  <Dialog open={!!prepared} onOpenChange={open=>!open&&!busy&&cancel()}><DialogContent title="Approve legacy issuance" description="This existing profile decrypts and marks on the server. Use Client documents for local processing.">{prepared&&<><div className="live-detail"><span>Session</span><code>{prepared.id}</code><span>Recipient</span><strong>{prepared.summary.recipientId}</strong><span>Output digest</span><code>{prepared.summary.outputDigest}</code></div><div className="dialog-actions"><Button variant="outline" onClick={cancel} disabled={busy}>Decline</Button><Button onClick={release} disabled={busy}>Sign and download legacy copy</Button></div></>}</DialogContent></Dialog>
  <Dialog open={!!deleting} onOpenChange={open=>!open&&setDeleting(null)}><DialogContent title="Delete encrypted document?" description="This removes the stored payload and blocks future downloads. Issuance evidence is retained for investigating copies already downloaded."><p>{deleting?.name}</p><div className="dialog-actions"><Button variant="outline" onClick={()=>setDeleting(null)}>Keep document</Button><Button variant="destructive" disabled={busy} onClick={()=>run(async()=>{await request(`/documents/${deleting.id}`,{method:'DELETE'});setDeleting(null);await refresh();toast.success('Encrypted payload deleted; evidence retained.');})}>Delete document</Button></div></DialogContent></Dialog><Toaster richColors position="bottom-right"/>
  </div>;
}

function Login({onLogin,connectionError}) {
  const [id,setId]=useState(''),[password,setPassword]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function submit(e){e.preventDefault();setBusy(true);setError('');try{onLogin(await request('/login',{method:'POST',body:{id,password}}));}catch(error){setError(error.message);}finally{setBusy(false);}}
  return <div className="login-page"><section className="login-brand-panel"><div className="login-brand"><span><ShieldCheck size={29}/></span>CipherTrail<span className="login-brand-dot">.</span></div><div className="login-story"><div className="login-kicker">DOCUMENT ATTRIBUTION WORKSPACE</div><h1>One document.<br/>Individual access.<br/><span>A traceable copy.</span></h1><p>Protect a PDF, authorize its recipients, and follow an issued copy back to its signed record.</p><div className="login-pillars"><div><LockKeyhole/><span>Encrypt once<small>A separate ML-KEM envelope for every recipient.</small></span></div><div><Fingerprint/><span>Sign your own issuance<small>ML-DSA private keys stay on your computer.</small></span></div><div><ScanSearch/><span>Investigate a leaked copy<small>Match the original PDF to verified issuance evidence.</small></span></div></div></div><div className="login-brand-footer">WORKING DEMO · SHARED LOCAL OR HOSTED SERVER</div></section><section className="login-form-panel"><div className="login-form-wrap"><div className="login-form-icon"><ShieldCheck size={27}/></div><div className="eyebrow">YOUR SHARED WORKSPACE</div><h2>Welcome to CipherTrail.</h2><p className="login-intro">Use the account provided by the demonstration administrator.</p><form onSubmit={submit}><label htmlFor="account">Account ID</label><div className="login-input"><UsersRound size={18}/><input id="account" value={id} onChange={e=>setId(e.target.value)} autoComplete="username" placeholder="admin or recipient.a" required/></div><label htmlFor="password">Password</label><div className="login-input"><KeyRound size={18}/><input id="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password" required/></div>{(error||connectionError)&&<div role="alert" className="login-error">{error||connectionError}</div>}<Button className="login-submit" disabled={busy}>{busy?'Signing in…':'Sign in'}<ArrowRight size={18}/></Button></form><div className="demo-credentials"><strong>Three computers. One demonstration.</strong><p>Use separate accounts for the administrator, Recipient A and Recipient B. First-run passwords are in the server’s private setup file; they are not published here.</p></div></div></section></div>;
}
