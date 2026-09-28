import { Router } from 'express';
import { parseCanonical } from '../ledger/application.mjs';
import { TendermintLedger } from './ledger-client.mjs';

// Mount AFTER authentication. SQLite is used only to bind the HTTP login;
// validators independently authorize against committed governance state.
export function ledgerRoutes(ledger = new TendermintLedger()) {
  const router = Router();
  router.post('/events',async (req,res) => {
    try {
      const read = (s,max) => {
        if (typeof s !== 'string' || s.length > max) throw new Error('Invalid base64 data');
        const b = Buffer.from(s,'base64');
        if (b.toString('base64') !== s) throw new Error('Noncanonical base64 data');
        return b;
      };
      const bytes = read(req.body.eventBytes,20000), signature = read(req.body.signature,5000);
      const event = parseCanonical(bytes);
      if (event.domain !== 'CipherTrail/client-issuance/v1' || event.recipientId !== req.user.id || event.keyId !== req.user.key_id) return res.status(403).json({error:'Signed event must belong to the signed-in recipient.'});
      const receipt = await ledger.broadcast(bytes,signature);
      res.json(receipt);
    } catch (error) { res.status(503).json({error:error.message}); }
  });
  return router;
}
