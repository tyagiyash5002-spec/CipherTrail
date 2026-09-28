import {parentPort,workerData} from 'node:worker_threads';
import {loadPdf,markedCopy,extractMarker} from './pdf.mjs';
try {
  const {task,bytes,token,createdAt}=workerData;
  const data=Buffer.from(bytes);
  let value;
  if(task==='inspect')value={pages:(await loadPdf(data)).getPageCount()};
  else if(task==='mark')value=await markedCopy(data,token,createdAt);
  else if(task==='extract')value=await extractMarker(data);
  else throw new Error('Unsupported PDF operation.');
  parentPort.postMessage({value});
}catch(error){parentPort.postMessage({error:error.message});}
