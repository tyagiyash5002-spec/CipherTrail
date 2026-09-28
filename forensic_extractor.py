"""Offline DCT-footer extraction. Requires Node 24.7+ for native ML-DSA.
Exit 0: signed record match; 2: inconclusive; 3: invalid input/evidence.
This verifies a signed issuance association, not who caused a leak.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import cv2
import numpy as np
import pymupdf

ROOT = Path(__file__).resolve().parent


def decode_tile(gray):
    carrier = cv2.resize(gray[12:268, 12:268], (128, 128), interpolation=cv2.INTER_AREA)
    bits, margins = [], []
    for y in range(16):
        for x in range(16):
            coeff = cv2.dct(carrier[y*8:y*8+8, x*8:x*8+8].astype(np.float32))
            difference = float(coeff[3, 2] - coeff[2, 3])
            bits.append(int(difference > 0))
            margins.append(abs(difference))
    payload = np.packbits(bits).tobytes()
    if payload[:4] != b'CTV1' or payload[20:24] != hashlib.sha256(payload[:20]).digest()[:4] or payload[24:] != payload[:8]:
        return None
    return {"token": payload[4:20].hex(), "minimum_dct_margin": round(min(margins), 2)}


def extract(gray):
    # Registration border supplies geometry, DCT AC coefficients supply bits.
    # Try modest border thresholds; report only exact checksum-valid payloads.
    matches = {}
    for threshold in (70, 130, 180):
        mask = cv2.threshold(gray, threshold, 255, cv2.THRESH_BINARY_INV)[1]
        contours, _ = cv2.findContours(mask, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
        for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:500]:
            if cv2.contourArea(contour) < 2500:
                continue
            poly = cv2.approxPolyDP(contour, 0.025*cv2.arcLength(contour, True), True)
            if len(poly) != 4 or not cv2.isContourConvex(poly):
                continue
            points = poly.reshape(4, 2).astype(np.float32)
            center = points.mean(axis=0)
            points = points[np.argsort(np.arctan2(points[:, 1]-center[1], points[:, 0]-center[0]))]
            lengths = np.linalg.norm(points - np.roll(points, 1, axis=0), axis=1)
            if max(lengths)/min(lengths) > 2.5:
                continue
            destination = np.float32([[0, 0], [279, 0], [279, 279], [0, 279]])
            tile = cv2.warpPerspective(gray, cv2.getPerspectiveTransform(points, destination), (280, 280))
            for rotation in range(4):
                result = decode_tile(np.rot90(tile, rotation).copy())
                if result:
                    matches[result['token']] = result
    return list(matches.values())


def images(filename):
    if filename.stat().st_size > 50*1024*1024:
        raise ValueError('Input exceeds 50 MiB')
    if filename.suffix.lower() == '.pdf':
        with pymupdf.open(filename) as doc:
            if doc.needs_pass or len(doc) > 100:
                raise ValueError('Encrypted PDFs or more than 100 pages are unsupported')
            for index, page in enumerate(doc):
                if page.rect.width*page.rect.height*4 > 30_000_000:
                    raise ValueError('Rendered page exceeds 30 megapixels')
                pix = page.get_pixmap(dpi=144, colorspace=pymupdf.csGRAY, alpha=False)
                yield index+1, np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width)
    else:
        gray = cv2.imread(str(filename), cv2.IMREAD_GRAYSCALE)
        if gray is None or gray.size > 30_000_000:
            raise ValueError('Unreadable image or more than 30 megapixels')
        yield 1, gray


def token(network, session):
    return hashlib.sha256(f'CipherTrail/visual/v1\0{network}\0{session}'.encode()).digest()[:16].hex()


def node_json(script, payload=None, env=None):
    result = subprocess.run(['node', str(ROOT / 'forensics' / script)], input=json.dumps(payload) if payload else None,
                            text=True, capture_output=True, timeout=30, cwd=ROOT, env=env)
    if result.returncode:
        raise ValueError(result.stderr.strip()[:500] or 'Native verification failed')
    return json.loads(result.stdout)


def report(args):
    detected = {}
    for page, gray in images(args.input):
        for match in extract(gray):
            detected.setdefault(match['token'], []).append({"page": page, **match})
    result = {"title": "Forensic Attribution Report", "status": "INCONCLUSIVE", "input": str(args.input),
              "profile": "dct-footer-v1", "detected_tokens": list(detected), "matches": [],
              "ledger_finality": "NOT_INDEPENDENTLY_VERIFIED",
              "interpretation": "A matching visual token associates pixels with a signed issuance. It does not prove who leaked the file; tokens can be copied."}
    if not detected:
        result['reason'] = 'No intact checksum-valid DCT watermark recovered.'
        return result, 2
    trust = json.loads(args.trust.read_text(encoding='utf-8'))
    if args.snapshot:
        snapshot = json.loads(args.snapshot.read_text(encoding='utf-8'))
    else:
        env = {**os.environ, 'TENDERMINT_RPC': args.ledger}
        snapshot = node_json('export-ledger.mjs', env=env)
    if snapshot.get('networkId') != trust.get('networkId') or snapshot.get('format') != 'CipherTrail/forensic-snapshot/v1':
        raise ValueError('Snapshot network/schema does not match independently trusted registry')
    records = snapshot.get('records', [])
    if len(records) > 10000:
        raise ValueError('Snapshot exceeds demo limit of 10000 records')
    # Verify against explicitly pinned keys, never against keys supplied in records.
    # Native helper decodes canonical CBOR; Python never reserializes signed bytes.
    failures = 0
    for record in records:
        verified = None
        for identity in trust.get('identities', []):
            try:
                event = node_json('verify-record.mjs', {**record, 'trustedPublicKey': identity['publicKey']})
                if event['networkId'] == trust['networkId'] and event['recipientId'] == identity['recipientId'] and event['keyId'] == identity['keyId']:
                    verified = event
                    break
            except ValueError:
                continue
        if not verified:
            failures += 1
            continue
        event = verified
        recovered = token(event['networkId'], event['sessionId'])
        if recovered in detected:
            exact = hashlib.sha384(b'CipherTrail/artifact/v1\0'+args.input.read_bytes()).hexdigest() == event['outputDigest']
            result['matches'].append({"sessionId": event['sessionId'], "recipientId": event['recipientId'], "keyId": event['keyId'],
                                     "documentId": event['documentId'], "networkId": event['networkId'], "signature": "ML-DSA-65 VERIFIED AGAINST PINNED KEY",
                                     "exact_issued_pdf": exact, "detections": detected[recovered]})
    result['unverified_records'] = failures
    if len(result['matches']) == 1:
        result['status'] = 'SIGNED_ISSUANCE_MATCH'
        return result, 0
    result['reason'] = 'No trusted matching signature, or multiple matching records; attribution is inconclusive.'
    return result, 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--snapshot', type=Path, help='Offline JSON export or mock signed-record file')
    source.add_argument('--ledger', help='Explicit Tendermint RPC URL; only this mode uses networking')
    parser.add_argument('--trust', type=Path, required=True, help='Independently pinned network and recipient public keys')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result, code = report(args)
    except Exception as error:
        result, code = {"title": "Forensic Attribution Report", "status": "ERROR", "reason": str(error)}, 3
    text = json.dumps(result, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    return code


if __name__ == '__main__':
    sys.exit(main())
