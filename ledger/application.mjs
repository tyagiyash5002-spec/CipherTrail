import { createHash, createPublicKey, verify } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import path from 'node:path';
import { encode, decode } from 'cborg';

export const SUITE = 'CT-CLIENT-1/ML-KEM-768/ML-DSA-65/AES-256-GCM/HKDF-SHA-384';
export const canonical = value => Buffer.from(encode(value));
const equal = (a,b) => Buffer.from(a).equals(Buffer.from(b));
const assert = (ok,message) => { if (!ok) throw new Error(message); };
export function parseCanonical(bytes, maxBytes = 32768) {
  assert(bytes.length > 0 && bytes.length <= maxBytes, 'Invalid CBOR size');
  const value = decode(bytes, {strict:true, allowIndefinite:false, allowDuplicateMapKeys:false});
  assert(equal(canonical(value),bytes), 'Noncanonical CBOR');
  return value;
}
function fields(value, names) {
  assert(value && typeof value === 'object' && !Array.isArray(value), 'Expected object');
  assert(Object.keys(value).sort().join(',') === names.split(' ').sort().join(','), 'Unexpected schema');
}
function id(s) { assert(typeof s === 'string' && /^[a-zA-Z0-9._:-]{1,128}$/.test(s), 'Invalid identifier'); }
function hash(s) { assert(typeof s === 'string' && /^[0-9a-f]{96}$/.test(s), 'Invalid SHA-384 digest'); }
function positive(n) { assert(Number.isSafeInteger(n) && n > 0, 'Invalid counter'); }
export function verifyNative(bytes, signature, rawPublicKey) {
  assert(rawPublicKey instanceof Uint8Array && rawPublicKey.length === 1952, 'Invalid ML-DSA-65 public key');
  assert(signature instanceof Uint8Array && signature.length === 3309, 'Invalid ML-DSA-65 signature');
  const key = createPublicKey({key:Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100','hex'),Buffer.from(rawPublicKey)]),format:'der',type:'spki'});
  assert(verify(null,bytes,key,signature), 'ML-DSA-65 signature verification failed');
}
export function transactionBytes(eventBytes,signature) {
  return canonical({version:1,event: new Uint8Array(eventBytes),signature: new Uint8Array(signature)});
}
export function unpack(tx) {
  const wrapper = parseCanonical(tx);
  fields(wrapper,'version event signature');
  assert(wrapper.version === 1 && wrapper.event instanceof Uint8Array && wrapper.signature instanceof Uint8Array,'Invalid transaction');
  return {...wrapper,parsed:parseCanonical(wrapper.event)};
}
export const txHash = tx => createHash('sha256').update(tx).digest('hex').toUpperCase();
const appHash = state => createHash('sha384').update('CipherTrail/ledger-state/v1\0').update(canonical(state)).digest();

// Consensus state contains only public identities, policies, signed events and hashes.
// Every validator owns a separate instance and separate durable directory.
export class LedgerApplication {
  constructor(directory) {
    this.directory = directory;
    this.file = path.join(directory,'state.cbor');
    mkdirSync(directory,{recursive:true});
    if (existsSync(this.file)) this.state = decode(readFileSync(this.file));
  }
  info() { return {data:'CipherTrail ABCI 0.34',version:'1.0.0',appVersion:1,lastBlockHeight:this.state?.height || 0,lastBlockAppHash:this.state ? appHash(this.state) : Buffer.alloc(0)}; }
  init(request) {
    const genesis = JSON.parse(Buffer.from(request.appStateBytes).toString('utf8'));
    id(request.chainId);
    assert(genesis.networkId === request.chainId,'Genesis network mismatch');
    const authority = Buffer.from(genesis.authorityPublicKey || '', 'base64');
    assert(authority.length === 1952,'Genesis requires a pinned governance ML-DSA-65 public key');
    const state = {networkId:request.chainId,authority:new Uint8Array(authority),height:0,sequence:0,identities:{},documents:{},sessions:{}};
    assert(!this.state || equal(appHash(this.state),appHash(state)),'Existing state does not match genesis');
    this.state = state;
    this.persist();
    return {appHash:appHash(state)};
  }
  begin(request) {
    assert(this.state,'InitChain required');
    const height = Number(request.header.height);
    assert(Number.isSafeInteger(height) && height === this.state.height + 1,'Unexpected block height');
    assert(request.header.chainId === this.state.networkId,'Wrong chain');
    this.pending = structuredClone(this.state);
    this.pending.height = height;
    return {};
  }
  apply(tx,state) {
    const {event,signature,parsed:e} = unpack(tx);
    assert(e.networkId === state.networkId,'Wrong network');
    if (e.domain === 'CipherTrail/ledger-governance/v1') {
      fields(e,'domain networkId sequence operation value');
      assert(e.sequence === state.sequence + 1,'Wrong governance sequence');
      verifyNative(event,signature,state.authority);
      if (e.operation === 'identity') {
        fields(e.value,'recipientId keyId publicKey active');
        const v = e.value;
        id(v.recipientId); id(v.keyId);
        assert(typeof v.active === 'boolean' && v.publicKey instanceof Uint8Array && v.publicKey.length === 1952,'Invalid identity');
        // Null-prototype semantics are obtained via own-property checks and safe IDs below.
        assert(!['__proto__','constructor','prototype'].includes(v.recipientId),'Reserved identifier');
        state.identities[v.recipientId] = v;
      } else if (e.operation === 'document') {
        fields(e.value,'documentId documentVersion policyEpoch packageDigest recipients');
        const v = e.value;
        id(v.documentId); positive(v.documentVersion); positive(v.policyEpoch); hash(v.packageDigest);
        assert(!['__proto__','constructor','prototype'].includes(v.documentId),'Reserved identifier');
        assert(Array.isArray(v.recipients) && v.recipients.length <= 20 && new Set(v.recipients).size === v.recipients.length,'Invalid recipients');
        v.recipients.forEach(id);
        const old = Object.hasOwn(state.documents,v.documentId) && state.documents[v.documentId];
        assert(!old || v.policyEpoch > old.policyEpoch,'Policy epoch must increase');
        state.documents[v.documentId] = v;
      } else throw new Error('Unknown governance operation');
      state.sequence = e.sequence;
      return {kind:'governance',id:String(e.sequence)};
    }
    fields(e,'domain suite networkId sessionId documentId documentVersion recipientId keyId policyEpoch createdAt packageDigest outputDigest watermarkProfile');
    assert(e.domain === 'CipherTrail/client-issuance/v1' && e.suite === SUITE && ['structural-client-v1','dct-footer-v1'].includes(e.watermarkProfile),'Unsupported issuance profile');
    [e.sessionId,e.documentId,e.recipientId,e.keyId].forEach(id);
    assert(!['__proto__','constructor','prototype'].includes(e.sessionId),'Reserved identifier');
    positive(e.documentVersion); positive(e.policyEpoch); hash(e.packageDigest); hash(e.outputDigest);
    assert(typeof e.createdAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(e.createdAt) && Number.isFinite(Date.parse(e.createdAt)),'Invalid client timestamp');
    assert(!Object.hasOwn(state.sessions,e.sessionId),'Session already committed');
    const identity = Object.hasOwn(state.identities,e.recipientId) && state.identities[e.recipientId];
    assert(identity?.active && identity.keyId === e.keyId,'Unregistered or revoked identity');
    const doc = Object.hasOwn(state.documents,e.documentId) && state.documents[e.documentId];
    assert(doc && doc.recipients.includes(e.recipientId) && doc.policyEpoch === e.policyEpoch && doc.documentVersion === e.documentVersion && doc.packageDigest === e.packageDigest,'Document policy mismatch');
    verifyNative(event,signature,identity.publicKey);
    state.sessions[e.sessionId] = {event:new Uint8Array(event),signature:new Uint8Array(signature),publicKey:new Uint8Array(identity.publicKey),txHash:txHash(tx),height:state.height};
    return {kind:'issuance',id:e.sessionId};
  }
  check(tx) { return this.result(() => this.apply(tx,structuredClone(this.state))); }
  deliver(tx) {
    return this.result(() => {
      assert(this.pending,'BeginBlock required');
      const next = structuredClone(this.pending);
      const result = this.apply(tx,next);
      this.pending = next;
      return result;
    });
  }
  result(fn) {
    try {
      const value = fn();
      return {code:0,events:[{type:'ciphertrail',attributes:[{key:Buffer.from('kind'),value:Buffer.from(value.kind),index:true},{key:Buffer.from('id'),value:Buffer.from(value.id),index:true}]}]};
    } catch (error) { return {code:1,codespace:'ciphertrail',log:error.message}; }
  }
  commit() {
    assert(this.pending,'No pending block');
    const previous = this.state;
    this.state = this.pending;
    try { this.persist(); } catch (error) { this.state = previous; throw error; }
    this.pending = undefined;
    return {data:appHash(this.state),retainHeight:0};
  }
  persist() {
    const temp = this.file + '.tmp';
    const fd = openSync(temp,'w',0o600);
    try { writeFileSync(fd,canonical(this.state)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp,this.file);
  }
  query(request) {
    try {
      assert(this.state,'Not initialized');
      assert(!request.prove,'ABCI state proofs are not implemented; use Tendermint transaction proofs');
      assert(!Number(request.height) || Number(request.height) === this.state.height,'Historical state queries are unsupported');
      const key = Buffer.from(request.data || []).toString('utf8');
      let value;
      if (request.path === '/state') value = this.state;
      else if (request.path === '/session') value = Object.hasOwn(this.state.sessions,key) && this.state.sessions[key];
      else throw new Error('Unknown query path');
      assert(value,'Not found');
      return {code:0,key:Buffer.from(key),value:canonical(value),height:this.state.height};
    } catch (error) { return {code:1,log:error.message,height:this.state?.height || 0}; }
  }
}
