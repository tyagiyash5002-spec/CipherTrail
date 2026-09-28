import {spawn} from 'node:child_process';
import {existsSync,writeFileSync,appendFileSync,unlinkSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server/app.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
if(!existsSync(path.join(root,'dist','index.html'))) {
  console.error('Build the interface first: npm run build');process.exit(1);
}
const binary=process.env.CLOUDFLARED_PATH || (process.platform==='win32' && existsSync('C:/Program Files (x86)/cloudflared/cloudflared.exe')?'C:/Program Files (x86)/cloudflared/cloudflared.exe':'cloudflared');
const port=Number(process.env.SHARE_PORT || 3002);
const instance=createApp({secureCookies:true});
const urlFile=path.join(instance.store.directory,'share-url.txt');
const logFile=path.join(instance.store.directory,'cloudflare.log');
let tunnel,publicUrl,stopping=false;
const server=instance.app.listen(port,'127.0.0.1',()=>{
  console.log(`Private origin ready at http://127.0.0.1:${server.address().port}`);
  console.log('HTTPS-only login cookies enabled. Use the public HTTPS link to sign in.');
  console.log('Starting Cloudflare Quick Tunnel. Keep this terminal and computer running.');
  writeFileSync(logFile,'CipherTrail Cloudflare sharing session\n',{mode:0o600});
  tunnel=spawn(binary,['tunnel','--no-autoupdate','--url',`http://127.0.0.1:${server.address().port}`],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  let pending='';
  function output(chunk) {
    const value=chunk.toString();appendFileSync(logFile,value);
    pending=(pending+value).slice(-12000);
    const match=pending.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if(match && !publicUrl) {
      publicUrl=match[0];writeFileSync(urlFile,publicUrl+'\n',{mode:0o600});
      console.log(`\nShare this HTTPS address with your participants:\n${publicUrl}\n`);
      console.log('Give each participant only their own account password. Never share private key files.');
      console.log('The address changes when this tunnel restarts. Press Ctrl+C to stop sharing.');
    }
    if(/Registered tunnel connection/.test(value)) console.log('Cloudflare connection established.');
    if(/ERR/.test(value)) console.error(value.trim());
  }
  tunnel.stdout.on('data',output);tunnel.stderr.on('data',output);
  tunnel.once('error',error=>{console.error(`Could not start cloudflared: ${error.message}. Install it or set CLOUDFLARED_PATH.`);stop(1);});
  tunnel.once('exit',code=>{if(!stopping){console.error(`Cloudflare tunnel stopped (code ${code}). See ${logFile}`);stop(code||1);}});
});
server.once('error',error=>{console.error(error.code==='EADDRINUSE'?`Port ${port} is occupied. Stop the other sharing session or set SHARE_PORT.`:error.message);stop(1);});
function stop(code=0) {
  if(stopping)return;stopping=true;tunnel?.kill();
  try {if(publicUrl && existsSync(urlFile) && readFileSync(urlFile,'utf8').trim()===publicUrl)unlinkSync(urlFile);}catch{}
  server.close(()=>{instance.close();process.exit(code);});
  setTimeout(()=>process.exit(code),3000).unref();
}
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>stop());
