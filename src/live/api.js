export async function request(path, {method='GET',body,blob=false} = {}) {
  const form = body instanceof FormData;
  const response = await fetch('/api'+path,{method,credentials:'same-origin',headers:{'X-CipherTrail':'1',...(!form && body?{'Content-Type':'application/json'}:{})},body:body?(form?body:JSON.stringify(body)):undefined});
  if (!response.ok) {
    const error = await response.json().catch(()=>({error:'The server returned an unexpected response.'}));
    const failure = new Error(error.error || 'Request failed.'); failure.status=response.status; throw failure;
  }
  return blob ? response.blob() : response.json();
}
export function download(value,name,type='application/json') {
  const blob = value instanceof Blob ? value : new Blob([JSON.stringify(value,null,2)],{type});
  const url = URL.createObjectURL(blob), anchor = document.createElement('a');
  anchor.href=url; anchor.download=name; anchor.click(); setTimeout(()=>URL.revokeObjectURL(url),10000);
}
export const encode64 = bytes => btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));
export const decode64 = text => Uint8Array.from(atob(text),c=>c.charCodeAt(0));
export const requestId = () => Array.from(crypto.getRandomValues(new Uint8Array(24)),v=>v.toString(16).padStart(2,'0')).join('');
