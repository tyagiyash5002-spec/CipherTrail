import React, { createContext, useContext } from 'react';
export const initialDocs = [
 {id:'DOC-0084',name:'Maritime operations brief',category:'Operations',classification:'Restricted',pages:12,size:'2.4 MB',recipients:['AK','BR','CM'],date:'26 Sep 2026',status:'Active'},
 {id:'DOC-0083',name:'Coastal surveillance report',category:'Intelligence',classification:'Confidential',pages:24,size:'4.8 MB',recipients:['AK','BR'],date:'25 Sep 2026',status:'Active'},
 {id:'DOC-0082',name:'Network architecture review',category:'Engineering',classification:'Internal',pages:18,size:'3.1 MB',recipients:['BR','CM'],date:'25 Sep 2026',status:'Active'},
 {id:'DOC-0081',name:'Quarterly readiness assessment',category:'Operations',classification:'Restricted',pages:8,size:'1.7 MB',recipients:['AK','CM'],date:'24 Sep 2026',status:'Active'},
 {id:'DOC-0080',name:'Equipment procurement schedule',category:'Logistics',classification:'Internal',pages:6,size:'0.9 MB',recipients:['AK'],date:'23 Sep 2026',status:'Revoked'}
];
export const people = [{id:'AK',name:'Asha Kumar',role:'Operations officer',email:'asha.kumar@enclave.local'}, {id:'BR',name:'Bharat Rao',role:'Intelligence analyst',email:'bharat.rao@enclave.local'}, {id:'CM',name:'Charu Menon',role:'Engineering officer',email:'charu.menon@enclave.local'}];
export const initialEvents = [ {id:'EVT-1048',document:initialDocs[0].name,recipient:'Asha Kumar',time:'10:42:18',token:'ct_8e42b1a9',status:'Finalized'}, {id:'EVT-1047',document:initialDocs[1].name,recipient:'Bharat Rao',time:'10:38:04',token:'ct_6f91c2d4',status:'Finalized'}, {id:'EVT-1046',document:initialDocs[2].name,recipient:'Charu Menon',time:'10:31:52',token:'ct_2a73e6f0',status:'Finalized'} ];
export const Context = createContext();
export const useApp = () => useContext(Context);
export const shortId = () => crypto.randomUUID().slice(0,8);
export function exportJSON(name, data) { const url = URL.createObjectURL(new Blob([JSON.stringify({demo:true,notice:'UI simulation. Not cryptographic evidence.',...data},null,2)],{type:'application/json'})); const a=document.createElement('a'); a.href=url; a.download=name; a.click(); URL.revokeObjectURL(url); }
export function Badge({children,tone='green'}) {return <span className={`badge ${tone}`}>{children}</span>}
export function Avatar({id='AK',small=false}) {return <span className={`avatar ${small?'small':''} avatar-${id}`}>{id}</span>}
export function Header({eyebrow,title,description,children}) {return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="heading-actions">{children}</div></div>}
export function Panel({title,subtitle,action,children,className=''}) {return <section className={`panel ${className}`}><div className="panel-heading"><div><h2>{title}</h2>{subtitle&&<p>{subtitle}</p>}</div>{action}</div>{children}</section>}
