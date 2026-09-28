import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync, writeFileSync, openSync, closeSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const root = fileURLToPath(new URL('../',import.meta.url));
const directory = path.resolve(process.env.LEDGER_HOME || path.join(root,'data/ledger'));
const binary = process.env.TENDERMINT_BIN || path.join(root,'data/tooling',process.platform === 'win32' ? 'tendermint.exe' : 'tendermint');
const configFile = path.join(directory,'network.json');
const command = process.argv[2];
function tm(...args) {
  const r = spawnSync(binary,args,{encoding:'utf8',windowsHide:true});
  if (r.error || r.status !== 0) throw new Error(r.error?.message || r.stderr);
  return r.stdout.trim();
}
if (command === 'init') {
  if (existsSync(configFile)) throw new Error('Network already initialized; use another LEDGER_HOME for a fresh chain.');
  if (tm('version') !== '0.34.24') throw new Error('This adapter requires Tendermint 0.34.24');
  const count = Number(process.argv[3] || 3);
  if (![3,4].includes(count)) throw new Error('Choose 3 or 4 validators');
  const basePort = Number(process.env.LEDGER_BASE_PORT || 26656);
  const networkId = process.env.LEDGER_NETWORK_ID || 'ciphertrail-demo-1';
  mkdirSync(directory,{recursive:true});
  const authority = ml_dsa65.keygen();
  const nodes = [];
  for (let i = 0; i < count; i++) {
    const home = path.join(directory,`node${i}`);
    if (existsSync(home)) throw new Error('Refusing to reuse a partial node directory');
    tm('init','--home',home);
    const validator = JSON.parse(readFileSync(path.join(home,'config/priv_validator_key.json'),'utf8'));
    nodes.push({home,id:tm('show-node-id','--home',home),p2p:basePort+i*10,rpc:basePort+i*10+1,abci:basePort+i*10+2,validator:{address:validator.address,pub_key:validator.pub_key,power:'10',name:`validator-${i}`}});
  }
  const genesis = JSON.parse(readFileSync(path.join(nodes[0].home,'config/genesis.json'),'utf8'));
  genesis.chain_id = networkId;
  genesis.validators = nodes.map(n=>n.validator);
  genesis.app_state = {networkId,authorityPublicKey:Buffer.from(authority.publicKey).toString('base64')};
  for (const node of nodes) {
    writeFileSync(path.join(node.home,'config/genesis.json'),JSON.stringify(genesis,null,2));
    const file = path.join(node.home,'config/config.toml');
    let config = readFileSync(file,'utf8');
    config = config.replace(/^proxy_app = .*$/m,`proxy_app = "tcp://127.0.0.1:${node.abci}"`)
      .replace('laddr = "tcp://127.0.0.1:26657"',`laddr = "tcp://127.0.0.1:${node.rpc}"`)
      .replace('laddr = "tcp://0.0.0.0:26656"',`laddr = "tcp://127.0.0.1:${node.p2p}"`)
      .replace(/^persistent_peers = .*$/m,`persistent_peers = "${nodes.filter(n=>n!==node).map(n=>`${n.id}@127.0.0.1:${n.p2p}`).join(',')}"`)
      .replace('addr_book_strict = true','addr_book_strict = false')
      .replace('allow_duplicate_ip = false','allow_duplicate_ip = true')
      .replace('log_level = "info"','log_level = "error"');
    writeFileSync(file,config);
  }
  writeFileSync(path.join(directory,'governance-PRIVATE-keys.json'),JSON.stringify({publicKey:Buffer.from(authority.publicKey).toString('base64'),secretKey:Buffer.from(authority.secretKey).toString('base64')},null,2),{mode:0o600});
  writeFileSync(configFile,JSON.stringify({networkId,binary,nodes},null,2));
  console.log(`Initialized ${count} validators in ${directory}. Governance private key stays outside Express.`);
} else if (command === 'start') {
  const network = JSON.parse(readFileSync(configFile,'utf8'));
  const children = [];
  const processes = [];
  let stopping = false;
  function stop() { if (stopping) return; stopping = true; children.forEach(p=>p.kill()); }
  for (const [i,node] of network.nodes.entries()) {
    for (const [label,exe,args] of [
      ['abci',process.execPath,[path.join(root,'ledger/abci-server.mjs'),path.join(node.home,'application'),String(node.abci)]],
      ['tendermint',network.binary,['node','--home',node.home]],
    ]) {
      const log = openSync(path.join(directory,`node${i}-${label}.log`),'a');
      const child = spawn(exe,args,{stdio:['ignore',log,log],windowsHide:true});
      closeSync(log);
      children.push(child);
      processes.push({node:i,service:label,pid:child.pid});
      child.on('error',e=>{ console.error(e.message); stop(); process.exitCode=1; });
      child.on('exit',code=>{ if (!stopping) { console.error(`${label} ${i} exited (${code}); other validators remain running`); process.exitCode=1; } });
    }
  }
  writeFileSync(path.join(directory,'processes.json'),JSON.stringify(processes,null,2));
  process.on('SIGINT',stop); process.on('SIGTERM',stop);
  console.log(`Running ${network.nodes.length} validators. RPC: http://127.0.0.1:${network.nodes[0].rpc}. Ctrl+C stops all.`);
} else throw new Error('Usage: node ledger/network.mjs init [3|4] | start');
