import net from 'node:net';
import protobuf from 'protobufjs';
import { fileURLToPath } from 'node:url';
import { LedgerApplication } from './application.mjs';

const schema = protobuf.loadSync(fileURLToPath(new URL('./abci.proto',import.meta.url)));
export const Request = schema.lookupType('ciphertrail.Request');
export const Response = schema.lookupType('ciphertrail.Response');
// ABCI v0.34 uses Go binary.PutVarint (signed/zigzag), not protobuf's
// unsigned encodeDelimited length prefix. Positive sizes are multiplied by 2.
export function frame(type,value) {
  const payload = type.encode(value).finish();
  return Buffer.concat([Buffer.from(protobuf.Writer.create().uint32(payload.length * 2).finish()),Buffer.from(payload)]);
}
export function createAbciServer(app) {
  function dispatch(r) {
    if (r.echo) return {echo:r.echo};
    if (r.flush) return {flush:{}};
    if (r.info) return {info:app.info()};
    if (r.initChain) return {initChain:app.init(r.initChain)};
    if (r.beginBlock) return {beginBlock:app.begin(r.beginBlock)};
    if (r.checkTx) return {checkTx:app.check(r.checkTx.tx)};
    if (r.deliverTx) return {deliverTx:app.deliver(r.deliverTx.tx)};
    if (r.endBlock) return {endBlock:{}};
    if (r.commit) return {commit:app.commit()};
    if (r.query) return {query:app.query(r.query)};
    if (r.listSnapshots) return {listSnapshots:{}};
    if (r.offerSnapshot) return {offerSnapshot:{result:3}};
    if (r.loadSnapshotChunk) return {loadSnapshotChunk:{}};
    if (r.applySnapshotChunk) return {applySnapshotChunk:{result:2}};
    throw new Error('Unsupported ABCI request');
  }
  return net.createServer(socket => {
    let pending = Buffer.alloc(0);
    socket.on('error',() => {});
    socket.on('data',chunk => {
      pending = Buffer.concat([pending,chunk]);
      try {
        while (pending.length) {
          let size = 0, prefix = 0, complete = false;
          for (; prefix < Math.min(pending.length,4); prefix++) {
            const b = pending[prefix]; size += (b & 127) * 2 ** (7 * prefix);
            if (!(b & 128)) { prefix++; complete = true; break; }
          }
          if (!complete) { if (pending.length >= 4) throw new Error('Invalid frame length'); return; }
          if (size & 1) throw new Error('Negative frame length');
          size /= 2;
          if (size > 4 * 1024 * 1024) throw new Error('ABCI frame too large');
          if (pending.length < prefix + size) return;
          const request = Request.decode(pending.subarray(prefix,prefix + size));
          if (process.env.ABCI_TRACE === '1') console.log('ABCI request',request.value);
          pending = pending.subarray(prefix + size);
          const result = dispatch(request);
          socket.write(frame(Response,result));
        }
      } catch (error) {
        console.error('ABCI error:',error.message);
        // Fail closed: consensus cannot continue after a state/persistence error.
        socket.end(frame(Response,{exception:{error:error.message}}));
      }
    });
  });
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const directory = process.argv[2];
  const port = Number(process.argv[3] || 26658);
  if (!directory) throw new Error('Usage: node ledger/abci-server.mjs STATE_DIRECTORY [PORT]');
  createAbciServer(new LedgerApplication(directory)).listen(port,'127.0.0.1',() => console.log(`ABCI listening on 127.0.0.1:${port}`));
}
