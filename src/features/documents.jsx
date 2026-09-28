import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { toast } from 'sonner';
import { UploadCloud, FileText, LockKeyhole, UsersRound, Check, ArrowRight, Fingerprint, Download, Package, ShieldCheck, CircleHelp } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Dialog, DialogContent } from '../components/ui/dialog';
import { useApp, Badge, Avatar, shortId, exportJSON } from '../shared';

export function PackageDialog({ open, onClose }) {
  const { docs, setDocs, identities, addActivity } = useApp();
  const [step, setStep] = useState(0), [file, setFile] = useState(null), [sample, setSample] = useState(false);
  const [name, setName] = useState(''), [classification, setClassification] = useState('Restricted');
  const [recipients, setRecipients] = useState(['AK']), [approved, setApproved] = useState(false);
  const [created, setCreated] = useState(null);
  const activeIds = identities.filter(p => p.status === 'Active').map(p => p.id);
  const allowedRecipients = recipients.filter(id => activeIds.includes(id));
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: { 'application/pdf': ['.pdf'] }, maxFiles: 1, maxSize: 100 * 1024 * 1024,
    onDropAccepted: fs => { setFile(fs[0]); setSample(false); setName(fs[0].name.replace(/\.pdf$/i, '')); setApproved(false); },
    onDropRejected: () => toast.error('Choose one PDF smaller than 100 MB.'),
  });
  function close() { onClose(); setStep(0); setFile(null); setSample(false); setName(''); setApproved(false); setCreated(null); }
  function create() {
    if ((!file && !sample) || !name.trim() || !approved || !allowedRecipients.length) return toast.error('Approve the document and select active recipients.');
    const document = {
      id: `DOC-${shortId().toUpperCase()}`, packageId: `PKG-${shortId().toUpperCase()}`,
      name: name.trim(), classification, category: 'Packaged', size: file ? `${(file.size / 1048576).toFixed(2)} MB` : '2.4 MB',
      recipients: allowedRecipients, date: new Date().toLocaleDateString('en-GB'), status: 'Active', pages: sample ? 12 : '—',
      policyVersion: 1, version: 1, sourceName: file?.name || 'Demonstration PDF', policyHistory: [],
    };
    setDocs(items => [document, ...items]); setCreated(document); setStep(3);
    addActivity('Demo package registered', `${document.packageId} · ${allowedRecipients.length} recipients`);
    toast.success('Demo package added to the vault. No encryption performed.');
  }
  return <Dialog open={open} onOpenChange={v => !v && close()}><DialogContent title="Package a document" description="Review content, choose recipients, and register a demo package.">
    <div className="package-steps">{['Document', 'Recipients', 'Review', 'Registered'].map((label, i) => <div key={label} className={step >= i ? 'active' : ''}><span>{step > i ? <Check size={13}/> : i + 1}</span>{label}</div>)}</div>
    {step === 0 && <>
      <div {...getRootProps()} className={`dropzone ${isDragActive ? 'dragging' : ''}`}><input {...getInputProps()} aria-label="Upload PDF"/><span className="drop-icon"><UploadCloud size={26}/></span><strong>{file?.name || (sample ? 'Demonstration PDF selected' : 'Choose a PDF or drop it here')}</strong><p>PDF · Up to 100 MB · File contents stay on this device</p></div>
      <Button variant="outline" size="sm" onClick={() => { setSample(true); setFile(null); setName('Maritime operations brief — demo package'); }}>Use a sample document</Button>
      <label className="field-label" htmlFor="package-name">Document name</label><input id="package-name" value={name} maxLength={160} onChange={e => setName(e.target.value)}/>
      <label className="field-label" htmlFor="package-classification">Classification</label><select id="package-classification" value={classification} onChange={e => setClassification(e.target.value)}>{['Restricted', 'Confidential', 'Internal'].map(c => <option key={c}>{c}</option>)}</select>
      <label className="approval-check"><input type="checkbox" checked={approved} onChange={e => setApproved(e.target.checked)}/>I approve this document and classification for the demonstration.</label>
      <div className="dialog-actions"><Button variant="outline" onClick={close}>Cancel</Button><Button disabled={(!file && !sample) || !name.trim() || !approved} onClick={() => setStep(1)}>Choose recipients <ArrowRight size={16}/></Button></div>
    </>}
    {step === 1 && <>
      <h3>Who can request a copy?</h3><p className="muted">Only active identities can receive a package envelope.</p>
      <div className="recipient-options package-recipients">{identities.map(person => <label key={person.id}><input type="checkbox" disabled={person.status !== 'Active'} checked={allowedRecipients.includes(person.id)} onChange={e => setRecipients(ids => e.target.checked ? [...ids, person.id] : ids.filter(id => id !== person.id))}/><Avatar id={person.id} small/><span>{person.name}<small>{person.role}</small></span><Badge tone={person.status === 'Active' ? 'green' : 'neutral'}>{person.status}</Badge></label>)}</div>
      <div className="package-counts"><div><strong>1</strong><span>Shared payload</span></div><div><strong>{allowedRecipients.length}</strong><span>Recipient envelopes</span></div></div>
      <div className="dialog-actions"><Button variant="outline" onClick={() => setStep(0)}>Back</Button><Button disabled={!allowedRecipients.length} onClick={() => setStep(2)}>Review package <ArrowRight size={16}/></Button></div>
    </>}
    {step === 2 && <>
      <div className="package-review"><FileText size={30}/><div><h3>{name}</h3><p>{classification} · {allowedRecipients.length} authorized recipients</p></div></div>
      <div className="detail-grid"><div><small>Content encryption</small><strong>AES-256-GCM · one payload</strong></div><div><small>Recipient envelopes</small><strong>ML-KEM-768 · individual keys</strong></div><div><small>Sender manifest signature</small><strong>ML-DSA-65 · backend required</strong></div><div><small>Watermark timing</small><strong>At each decryption session</strong></div></div>
      <div className="inline-note"><CircleHelp size={17}/>Registration saves demonstration metadata. It does not encrypt the PDF, create key envelopes, or sign a manifest.</div>
      <div className="dialog-actions"><Button variant="outline" onClick={() => setStep(1)}>Back</Button><Button onClick={create}><Package size={16}/> Register demo package</Button></div>
    </>}
    {step === 3 && created && <div className="package-success"><span className="success-symbol"><ShieldCheck size={32}/></span><h3>Ready for a demo issuance</h3><p>{created.name}</p><code>{created.packageId}</code><p>The document is now available in the vault. Each new session will receive a different demo token.</p><div className="dialog-actions"><Button variant="outline" onClick={() => exportJSON(`${created.packageId}-manifest.json`, { manifest: created })}><Download size={16}/> Demo manifest</Button><Button onClick={close}>Return to workspace</Button></div></div>}
  </DialogContent></Dialog>;
}

export function DocumentDetails({ doc: selectedDoc, close }) {
  const { docs, setDocs, identities, events, addActivity } = useApp();
  const navigate = useNavigate();
  if (!selectedDoc) return null;
  const doc = docs.find(d => d.id === selectedDoc.id) || selectedDoc;
  return <DocumentDetailBody key={doc.id} doc={doc} close={close} identities={identities} events={events} setDocs={setDocs} addActivity={addActivity} navigate={navigate}/>;
}
function DocumentDetailBody({ doc, close, identities, events, setDocs, addActivity, navigate }) {
  const [tab, setTab] = useState('details'), [recipients, setRecipients] = useState(doc.recipients), [confirmRevoke, setConfirmRevoke] = useState(false);
  const related = events.filter(e => e.documentId === doc.id || (!e.documentId && e.document === doc.name));
  function save() {
    const current = recipients.filter(id => identities.some(p => p.id === id && p.status === 'Active'));
    if (!current.length) return toast.error('Select at least one active recipient or revoke future access.');
    setDocs(ds => ds.map(d => d.id === doc.id ? { ...d, recipients: current, policyVersion: (d.policyVersion || 1) + 1, policyHistory: [...(d.policyHistory || []), { version: d.policyVersion || 1, recipients: d.recipients, time: new Date().toISOString() }] } : d));
    addActivity('Recipient policy updated', `${doc.id} · ${current.length} recipients`); toast.success('Demo policy updated. Future sessions use this policy.');
  }
  return <Dialog open onOpenChange={v => !v && close()}><DialogContent title={doc.name} description={`${doc.id} · ${doc.size} · Demo package`}>
    <div className="workspace-tabs"><button className={tab === 'details' ? 'active' : ''} onClick={() => setTab('details')}>Package</button><button className={tab === 'access' ? 'active' : ''} onClick={() => setTab('access')}>Access policy</button><button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>Issuance history</button></div>
    {tab === 'details' && <><div className="detail-grid">{[['Package ID', doc.packageId || `PKG-${doc.id}`], ['Document version', `v${doc.version || 1}`], ['Policy version', `v${doc.policyVersion || 1}`], ['Classification', doc.classification], ['Key encapsulation', 'ML-KEM-768'], ['Manifest signing', 'ML-DSA-65']].map(([label, value]) => <div key={label}><small>{label}</small><strong>{value}</strong></div>)}</div><Badge tone={doc.status === 'Active' ? 'green' : 'red'}>{doc.status}</Badge><div className="package-counts"><div><strong>1</strong><span>Shared payload</span></div><div><strong>{doc.recipients.length}</strong><span>Recipient envelopes</span></div></div><Button variant="outline" onClick={() => exportJSON(`${doc.id}-manifest.json`, { manifest: doc })}><Download size={16}/> Export demo manifest</Button></>}
    {tab === 'access' && <><div className="recipient-options package-recipients">{identities.map(person => <label key={person.id}><input type="checkbox" disabled={doc.status !== 'Active' || person.status !== 'Active'} checked={recipients.includes(person.id)} onChange={e => setRecipients(ids => e.target.checked ? [...ids, person.id] : ids.filter(id => id !== person.id))}/><Avatar id={person.id} small/><span>{person.name}<small>{person.status}</small></span></label>)}</div><div className="inline-note"><LockKeyhole size={17}/>Changes affect future controlled issuance. Copies already received cannot be recalled. Real changes require authorized ledger transitions and updated envelopes.</div><div className="dialog-actions"><Button disabled={doc.status !== 'Active'} onClick={save}>Save demo policy</Button></div>{confirmRevoke ? <div className="callout"><h3>Block future sessions?</h3><p>Existing issuance records remain available.</p><div className="dialog-actions"><Button variant="outline" onClick={() => setConfirmRevoke(false)}>Cancel</Button><Button variant="destructive" onClick={() => { setDocs(ds => ds.map(d => d.id === doc.id ? { ...d, status: 'Revoked' } : d)); addActivity('Document access revoked', doc.id); setConfirmRevoke(false); toast.success('Future demo access revoked.'); }}>Confirm revocation</Button></div></div> : <Button variant="ghost" disabled={doc.status !== 'Active'} onClick={() => setConfirmRevoke(true)}>Revoke all future access</Button>}</>}
    {tab === 'history' && <>{related.length ? related.map(e => <div className="list-row" key={e.id}><span>{e.recipient}<small>{e.id} · {e.time}</small></span><Badge>{e.status}</Badge></div>) : <div className="empty"><Fingerprint/><h3>No copies issued</h3><p>Start a session to create a recipient-specific demo record.</p></div>}</>}
    <div className="dialog-actions"><Button variant="outline" onClick={close}>Close</Button><Button disabled={doc.status !== 'Active'} onClick={() => { close(); navigate('/issuance', { state: { documentId: doc.id } }); }}><Fingerprint size={16}/> Start session</Button></div>
  </DialogContent></Dialog>;
}
