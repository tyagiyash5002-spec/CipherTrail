import { createApp } from './app.mjs';
import { networkInterfaces } from 'node:os';
const {app,store,close} = createApp();
const port = Number(process.env.PORT || 3001);
const host = process.env.HOST || '127.0.0.1';
const server = app.listen(port,host,()=>{
  console.log(`CipherTrail: http://localhost:${port}`);
  console.log(`Private setup accounts: ${store.directory}/initial-accounts.json`);
  if (host==='0.0.0.0') for (const list of Object.values(networkInterfaces())) for (const address of list || []) if (address.family==='IPv4' && !address.internal) console.log(`LAN address: http://${address.address}:${port}`);
  console.log('Working demo: SRS crypto profile; structural PDF marks; local signed audit, no BFT finality.');
});
for (const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close(()=>{close();process.exit(0);}));
