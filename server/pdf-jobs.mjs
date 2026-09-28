import {Worker} from 'node:worker_threads';
let running=0;
// Bound parser CPU time and isolate it from the HTTP event loop.
export function pdfJob(task,bytes,extra={}) {
  if(running>=2) return Promise.reject(Object.assign(new Error('PDF processor is busy. Please try again shortly.'),{status:503}));
  running++;
  return new Promise((resolve,reject)=>{
    const worker=new Worker(new URL('./pdf-worker.mjs',import.meta.url),{workerData:{task,bytes,...extra},resourceLimits:{maxOldGenerationSizeMb:128}});
    let settled=false;
    const done=(error,value)=>{
      if(settled)return;settled=true;clearTimeout(timer);running--;
      worker.terminate();if(error)reject(error);else resolve(value);
    };
    const timer=setTimeout(()=>done(Object.assign(new Error('PDF processing timed out. Use a smaller, simpler PDF.'),{status:422})),15000);
    worker.once('message',message=>message.error?done(Object.assign(new Error(message.error),{status:422})):done(null,message.value));
    worker.once('error',()=>done(Object.assign(new Error('PDF could not be processed within the demo resource limits.'),{status:422})));
    worker.once('exit',()=>{if(!settled)done(Object.assign(new Error('PDF processing ended unexpectedly.'),{status:422}));});
  });
}
export const inspectPdf=bytes=>pdfJob('inspect',bytes);
export const markedCopy=async(bytes,token,createdAt)=>Buffer.from(await pdfJob('mark',bytes,{token,createdAt}));
export const extractMarker=bytes=>pdfJob('extract',bytes);
