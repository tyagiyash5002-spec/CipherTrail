import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { FileText, LockKeyhole, Fingerprint, Layers3, ScanSearch, ArrowRight, ArrowUpRight, UsersRound, Download, Search, ShieldCheck, CircleHelp, UploadCloud, AlertTriangle, KeyRound, Clock3, Activity, Server, Check, X } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Dialog, DialogContent } from '../components/ui/dialog';
import { useApp, Header, Panel, Badge, exportJSON } from '../shared';

export function SystemFlow() {
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);
  const stages = [
    { label: 'Package once', text: 'One encrypted payload with a separate key envelope for each recipient.', icon: LockKeyhole, path: '/documents', note: 'ML-KEM + AES-256-GCM' },
    { label: 'Issue a unique copy', text: 'A new watermark token and a recipient-authorized record for every session.', icon: Fingerprint, path: '/issuance', note: 'Watermark + ML-DSA' },
    { label: 'Commit, then release', text: 'Independent validators must finalize the event before a copy is released.', icon: Layers3, path: '/ledger', note: 'Private DLT · 3 of 4 quorum' },
    { label: 'Trace the evidence', text: 'Recover the mark and verify the associated issuance record and ledger proofs.', icon: ScanSearch, path: '/investigation', note: 'Offline investigation' },
  ];
  return <section className="system-flow panel"><div className="panel-heading"><div><h2>One document. A traceable journey.</h2><p>How the proposed security workflow fits together</p></div><Button variant="ghost" size="sm" aria-expanded={expanded} onClick={() => setExpanded(v => !v)}>{expanded ? 'Hide details' : 'How it works'} <CircleHelp size={15}/></Button></div><div className="system-stages">{stages.map((stage, i) => <React.Fragment key={stage.label}><button className="system-stage" onClick={() => navigate(stage.path)}><span className="stage-number">0{i + 1}</span><span className="system-stage-icon"><stage.icon size={22}/></span><span><strong>{stage.label}</strong><small>{stage.note}</small></span><ArrowUpRight size={15}/></button>{i < 3 && <ArrowRight className="stage-connector" size={16}/>}</React.Fragment>)}</div>{expanded && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="system-explanation">{stages.map(stage => <div key={stage.label}><strong>{stage.label}</strong><p>{stage.text}</p></div>)}</motion.div>}</section>;
}

const resultLabels = { exact: 'Exact-copy sample', transformed: 'Transformed-copy sample', mixed: 'Multiple associations', missing: 'Inconclusive', invalid: 'Invalid evidence' };
const proofRequirements = ['Preserved artifact digest', 'Authenticated watermark / content binding', 'Recipient signature over canonical event', 'Historical public-key binding', 'Device attestation', 'Merkle inclusion proof', 'Validator finality proof', 'Independent trusted checkpoint'];
export function EvidenceWorkbench() {
  const { cases, addActivity } = useApp();
  const [imported, setImported] = useState(null), [error, setError] = useState(''), [review, setReview] = useState(null), [selected, setSelected] = useState(null);
  const { getRootProps, getInputProps } = useDropzone({
    accept: { 'application/json': ['.json'] }, maxFiles: 1, maxSize: 1024 * 1024,
    onDropAccepted: async files => {
      setImported(null); setReview(null); setError('');
      try {
        const payload = JSON.parse(await files[0].text());
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Expected a JSON object.');
        setImported({ name: files[0].name, payload });
      } catch { setError('The selected file is not a supported JSON object.'); }
    },
    onDropRejected: () => setError('Choose one JSON file smaller than 1 MB.'),
  });
  function inspect() {
    const payload = imported.payload, event = payload.event || payload.associatedEvent;
    const isDemo = payload.demo === true;
    const fields = ['id', 'document', 'recipient', 'token', 'status'];
    const missing = fields.filter(field => typeof event?.[field] !== 'string' || !event[field].trim());
    const result = { isDemo, missing, known: isDemo && !!event, complete: isDemo && !!event && !missing.length };
    setReview(result); addActivity('Evidence structure inspected', `${imported.name} · ${result.complete ? 'demo structure complete' : 'unsupported or incomplete'}`);
  }
  return <><Header eyebrow="EVIDENCE WORKBENCH" title="Inspect the record. Keep the context." description="Review saved sample cases and inspect exported JSON receipts without claiming cryptographic verification."/><div className="two-column"><Panel title="Case reports" subtitle="Sample investigations from this browsing session"><div className="panel-body">{cases.length ? cases.map(item => <button className="case-row" key={item.id} onClick={() => setSelected(item)}><span className="case-icon"><ScanSearch size={18}/></span><span><strong>{item.id}</strong><small>{item.event?.document || 'Sample case'}</small><small>{new Date(item.createdAt).toLocaleString()}</small></span><Badge tone={item.scenario === 'invalid' ? 'red' : item.scenario === 'missing' ? 'orange' : 'neutral'}>{resultLabels[item.scenario]}</Badge></button>) : <div className="empty"><ScanSearch/><h3>No case reports yet</h3><p>Run a sample investigation to create a report here.</p></div>}</div></Panel><Panel title="Inspect an exported receipt" subtitle="JSON structure checks only · no signature verification"><div className="panel-body"><div {...getRootProps()} className="dropzone"><input {...getInputProps()} aria-label="Import evidence JSON"/><span className="drop-icon"><UploadCloud size={25}/></span><strong>{imported?.name || 'Select an exported demo receipt'}</strong><p>JSON · Up to 1 MB · Processed locally</p></div>{error && <div role="alert" className="demo-banner"><AlertTriangle size={17}/>{error}</div>}<Button disabled={!imported} onClick={inspect}><Search size={16}/> Inspect structure</Button>{review && <div className="callout" role="status"><h3>{review.complete ? 'Demo record structure complete' : 'Incomplete or unsupported record'}</h3><p>{review.complete ? 'Required record fields are present. Authenticity, signature validity and ledger finality remain unverified.' : review.known ? `Missing fields: ${review.missing.join(', ')}.` : 'This preview only recognizes explicitly labeled CipherTrail demo receipts.'}</p><Badge tone="orange">Cryptography not verified</Badge></div>}<details className="proof-requirements"><summary>What a production verifier must check</summary><ul className="checks">{proofRequirements.map(label => <li key={label}><ShieldCheck size={15}/>{label}</li>)}</ul></details></div></Panel></div><Dialog open={!!selected} onOpenChange={v => !v && setSelected(null)}><DialogContent title={selected?.id || 'Case report'} description="Saved demonstration result — not forensic evidence">{selected && <><Badge tone="purple">{resultLabels[selected.scenario]}</Badge><div className="detail-grid"><div><small>Document</small><strong>{selected.event?.document}</strong></div><div><small>Recorded</small><strong>{new Date(selected.createdAt).toLocaleString()}</strong></div>{['exact', 'transformed'].includes(selected.scenario) && <><div><small>Associated recipient</small><strong>{selected.event.recipient}</strong></div><div><small>Issuance event</small><strong>{selected.event.id}</strong></div></>}</div><div className="inline-note"><CircleHelp size={17}/>An issued-copy association does not establish personal intent. Unsupported or ambiguous evidence must not identify a single recipient.</div><div className="dialog-actions"><Button onClick={() => exportJSON(`${selected.id}-report.json`, { caseId: selected.id, result: selected.scenario, createdAt: selected.createdAt, associatedEvent: ['exact', 'transformed'].includes(selected.scenario) ? selected.event : null })}><Download size={16}/> Export sample report</Button></div></>}</DialogContent></Dialog></>;
}

export function AuditActivity() {
  const { audit } = useApp();
  const [query, setQuery] = useState('');
  return <div className="audit-section"><Panel title="Workspace activity" subtitle="Local UI actions · separate from finalized issuance records" action={<Button variant="ghost" size="sm" disabled={!audit.length} onClick={() => exportJSON('workspace-activity-demo.json', { activity: audit })}><Download size={15}/> Export</Button>}><div className="panel-body"><div className="input-icon"><Search size={16}/><input aria-label="Search workspace activity" value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter activity…"/></div>{audit.length ? audit.filter(a => `${a.action} ${a.detail}`.toLowerCase().includes(query.toLowerCase())).map(a => <div className="audit-row" key={a.id}><span className="activity-icon"><Activity size={15}/></span><div><strong>{a.action}</strong><p>{a.detail}</p></div><time>{new Date(a.time).toLocaleTimeString()}</time></div>) : <p className="empty">Package a document or run a session to see activity here.</p>}<div className="inline-note"><CircleHelp size={16}/>This in-memory activity feed is not immutable. Only a real distributed ledger can provide the required audit guarantees.</div></div></Panel></div>;
}

export function Readiness() {
  const { nodes, identities } = useApp();
  return <Panel className="readiness-panel" title="Enclave readiness" subtitle="Live demo state, with production dependencies kept explicit"><div className="readiness-grid"><div><Server size={21}/><strong>{nodes.filter(Boolean).length}/4</strong><span>Demo validators online</span><Badge tone={nodes.filter(Boolean).length >= 3 ? 'green' : 'red'}>{nodes.filter(Boolean).length >= 3 ? 'Quorum available' : 'Issuance blocked'}</Badge></div><div><UsersRound size={21}/><strong>{identities.filter(p => p.status === 'Active').length}</strong><span>Active demo identities</span><Badge tone="neutral">Local registry</Badge></div><div><ShieldCheck size={21}/><strong>Not connected</strong><span>Cryptography & watermarking</span><Badge tone="orange">Backend required</Badge></div></div></Panel>;
}

export function KeyHistory({ person }) {
  const [open, setOpen] = useState(false);
  return <><Button variant="ghost" size="sm" onClick={() => setOpen(true)}><Clock3 size={14}/> Key history</Button><Dialog open={open} onOpenChange={setOpen}><DialogContent title={`${person.name} · key history`} description="Demo key versions; no actual private keys are generated or stored here.">{(person.history || []).map((entry, i) => <div className="list-row" key={i}><span>Version {entry.version}<small>{new Date(entry.time).toLocaleString()}</small></span><Badge tone="neutral">{entry.status}</Badge></div>)}<div className="list-row"><span>Version {person.version}<small>ML-KEM-768 · ML-DSA-65</small></span><Badge tone={person.status === 'Active' ? 'green' : 'orange'}>{person.status}</Badge></div><div className="inline-note" style={{ marginTop: 18 }}><KeyRound size={17}/>Historical public keys must remain verifiable after rotation or revocation. A new key cannot retroactively sign an old event.</div></DialogContent></Dialog></>;
}
