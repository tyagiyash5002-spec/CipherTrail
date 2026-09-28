import { PDFDocument, PDFName, PDFHexString } from 'pdf-lib';

const markerKey = PDFName.of('CipherTrailIssuance');
export async function loadPdf(bytes) {
  if (bytes.subarray(0, 5).toString() !== '%PDF-') throw new Error('Upload a valid, unencrypted PDF.');
  let pdf;
  try { pdf = await PDFDocument.load(bytes, { updateMetadata: false }); }
  catch { throw new Error('This PDF is damaged or password-protected. Use an unencrypted PDF.'); }
  if (!pdf.getPageCount() || pdf.getPageCount() > 100) throw new Error('PDFs must contain between 1 and 100 pages.');
  return pdf;
}
// Structural metadata only: deliberately makes no screenshot/print/scan claims.
export async function markedCopy(bytes, token, createdAt) {
  const pdf = await loadPdf(bytes);
  pdf.catalog.set(markerKey, PDFHexString.fromText(token));
  pdf.setModificationDate(new Date(createdAt));
  const output = Buffer.from(await pdf.save({ useObjectStreams: false }));
  if (await extractMarker(output) !== token) throw new Error('PDF marker self-check failed.');
  return output;
}
export async function extractMarker(bytes) {
  const pdf = await loadPdf(bytes);
  const value = pdf.catalog.get(markerKey);
  return value instanceof PDFHexString ? value.decodeText() : null;
}
