import React from 'react';
import {Files} from 'lucide-react';
export const size = bytes => bytes >= 1048576 ? `${(bytes/1048576).toFixed(1)} MB` : `${Math.ceil(bytes/1024)} KB`;
export const time = value => new Date(value).toLocaleString();
export const short = value => value ? `${value.slice(0,10)}…${value.slice(-6)}` : '—';
export function Badge({children,tone=''}) {return <span className={`live-badge ${tone}`}>{children}</span>}
export function Panel({title,description,children,action}) {return <section className="live-panel"><div className="live-panel-heading"><div><h2>{title}</h2>{description&&<p>{description}</p>}</div>{action}</div><div className="live-panel-body">{children}</div></section>}
export function Heading({eyebrow='WORKING DEMONSTRATION',title,description,children}) {return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="heading-actions">{children}</div></div>}
export function Empty({children}) {return <div className="live-empty"><Files size={30}/><p>{children}</p></div>}
