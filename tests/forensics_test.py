import json
from pathlib import Path
import subprocess
import sys
import unittest
import cv2
import numpy as np
import pymupdf

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from forensic_extractor import extract


class ForensicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = ROOT / 'samples/forensics'
        cls.output = ROOT / '.test-runs/forensics'
        cls.output.mkdir(parents=True, exist_ok=True)
        with pymupdf.open(cls.folder / 'marked.pdf') as pdf:
            pix = pdf[0].get_pixmap(dpi=144, colorspace=pymupdf.csGRAY)
            cls.image = np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.width).copy()
        cv2.imwrite(str(cls.output / 'screenshot.png'), cls.image)

    def test_pdf_png_jpeg_resize_rotation_perspective(self):
        image = self.image
        h, w = image.shape
        variants = {
            'screenshot': image,
            'jpeg-quality-65': cv2.imdecode(cv2.imencode('.jpg', image, [cv2.IMWRITE_JPEG_QUALITY, 65])[1], 0),
            'resize-75-percent': cv2.resize(image, None, fx=.75, fy=.75, interpolation=cv2.INTER_AREA),
            'rotation-90': np.rot90(image).copy(),
            'perspective': cv2.warpPerspective(image, cv2.getPerspectiveTransform(np.float32([[0,0],[w-1,0],[w-1,h-1],[0,h-1]]), np.float32([[45,30],[w-70,0],[w-1,h-50],[0,h-1]])), (w,h), borderValue=255),
        }
        for name, value in variants.items():
            with self.subTest(name=name):
                cv2.imwrite(str(self.output / (name+'.png')), value)
                self.assertEqual(len(extract(value)), 1)

    def test_cropped_footer_and_unmarked_are_inconclusive(self):
        self.assertEqual(extract(self.image[:-330]), [])
        self.assertEqual(extract(np.full((600,600), 255, np.uint8)), [])

    def run_cli(self, filename, trust=None, snapshot=None):
        result = subprocess.run([sys.executable, str(ROOT/'forensic_extractor.py'), str(filename), '--snapshot', str(snapshot or self.folder/'snapshot.json'), '--trust', str(trust or self.folder/'trusted-identities.json')], capture_output=True, text=True)
        return result.returncode, json.loads(result.stdout)

    def test_offline_pdf_and_screenshot_native_signature(self):
        code, report = self.run_cli(self.folder/'marked.pdf')
        self.assertEqual(code, 0, report)
        self.assertTrue(report['matches'][0]['exact_issued_pdf'])
        code, report = self.run_cli(self.output/'screenshot.png')
        self.assertEqual(code, 0, report)
        self.assertFalse(report['matches'][0]['exact_issued_pdf'])

    def test_signature_tamper_and_wrong_trusted_identity(self):
        data = json.loads((self.folder/'snapshot.json').read_text())
        sig = data['records'][0]['signature']
        data['records'][0]['signature'] = ('A' if sig[0]!='A' else 'B')+sig[1:]
        file = self.output/'tampered.json';file.write_text(json.dumps(data))
        self.assertEqual(self.run_cli(self.folder/'marked.pdf', snapshot=file)[0], 2)
        trust = json.loads((self.folder/'trusted-identities.json').read_text())
        trust['identities'][0]['recipientId'] = 'mallory'
        file = self.output/'wrong-trust.json';file.write_text(json.dumps(trust))
        self.assertEqual(self.run_cli(self.folder/'marked.pdf', trust=file)[0], 2)

    def test_raster_only_pdf_without_structural_metadata(self):
        file = self.output/'raster-only.pdf'
        with pymupdf.open() as pdf:
            page=pdf.new_page(width=self.image.shape[1]/2, height=self.image.shape[0]/2)
            page.insert_image(page.rect, filename=str(self.output/'screenshot.png'))
            pdf.save(file)
        code, report = self.run_cli(file)
        self.assertEqual(code, 0, report)
        self.assertFalse(report['matches'][0]['exact_issued_pdf'])


if __name__ == '__main__':
    unittest.main()
