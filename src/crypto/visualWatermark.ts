import { PDFDocument, rgb } from 'pdf-lib';

export const VISUAL_PROFILE = 'dct-footer-v1' as const;
const concat = (...arrays: Uint8Array[]) => {
  const out = new Uint8Array(arrays.reduce((n,a)=>n+a.length,0));
  let at=0; for(const a of arrays){out.set(a,at);at+=a.length;} return out;
};
const u32 = (n:number) => new Uint8Array([(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255]);
function crc(bytes:Uint8Array):number {
  let c=0xffffffff;
  for(const b of bytes){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0);}
  return (c^0xffffffff)>>>0;
}
async function sha(bytes:Uint8Array):Promise<Uint8Array> {
  const input=new ArrayBuffer(bytes.length);new Uint8Array(input).set(bytes);
  return new Uint8Array(await crypto.subtle.digest('SHA-256',input));
}
export async function sessionToken(networkId:string,sessionId:string):Promise<Uint8Array> {
  return (await sha(new TextEncoder().encode(`CipherTrail/visual/v1\0${networkId}\0${sessionId}`))).slice(0,16);
}
/** Portable grayscale PNG encoder: stored DEFLATE blocks, no DOM or network. */
function png(gray:Uint8Array,size:number):Uint8Array {
  const raw=new Uint8Array((size+1)*size);
  for(let y=0;y<size;y++)raw.set(gray.subarray(y*size,(y+1)*size),y*(size+1)+1);
  const blocks:Uint8Array[]=[new Uint8Array([0x78,0x01])];
  for(let at=0;at<raw.length;at+=65535){const data=raw.slice(at,at+65535),n=data.length;
    blocks.push(new Uint8Array([at+n===raw.length?1:0,n&255,n>>>8,(~n)&255,((~n)>>>8)&255]),data);}
  let a=1,b=0;for(const v of raw){a=(a+v)%65521;b=(b+a)%65521;}
  blocks.push(u32((b*65536+a)>>>0));
  const chunk=(type:string,data:Uint8Array)=>{const body=concat(new TextEncoder().encode(type),data);return concat(u32(data.length),body,u32(crc(body)));};
  return concat(new Uint8Array([137,80,78,71,13,10,26,10]),chunk('IHDR',concat(u32(size),u32(size),new Uint8Array([8,0,0,0,0]))),chunk('IDAT',concat(...blocks)),chunk('IEND',new Uint8Array()));
}
export async function visualTile(networkId:string,sessionId:string):Promise<Uint8Array> {
  const body=concat(new TextEncoder().encode('CTV1'),await sessionToken(networkId,sessionId));
  const payload=concat(body,(await sha(body)).slice(0,4),body.slice(0,8));
  const size=280,gray=new Uint8Array(size*size).fill(255);
  // Dark registration border supports perspective alignment. The session bits
  // are encoded in AC coefficients inside the pale carrier, not in this border.
  for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(x<4||y<4||x>=276||y>=276)gray[y*size+x]=0;
  for(let bit=0;bit<256;bit++) {
    const sign=(payload[bit>>>3]>>>(7-bit%8))&1?1:-1;
    for(let y=0;y<8;y++)for(let x=0;x<8;x++) {
      const basis=(u:number,v:number)=>0.25*Math.cos((2*y+1)*u*Math.PI/16)*Math.cos((2*x+1)*v*Math.PI/16);
      gray[(12+(bit>>>4)*8+y)*size+12+(bit%16)*8+x]=Math.round(225+sign*45*(basis(3,2)-basis(2,3)));
    }
  }
  // 16 blocks * 8px is 128px; enlarge the carrier 2x to 256px. This makes
  // the payload recoverable at common PDF screen sizes without changing bits.
  const small=gray.slice();
  for(let y=0;y<256;y++)for(let x=0;x<256;x++)gray[(12+y)*size+12+x]=small[(12+(y>>>1))*size+12+(x>>>1)];
  return png(gray,size);
}
/** Adds an explicit forensic footer without covering existing page content.
 * This profile requires unrotated, uncropped pages and changes page dimensions.
 */
export async function addVisualWatermark(pdf:PDFDocument,networkId:string,sessionId:string):Promise<void> {
  const tile=await pdf.embedPng(await visualTile(networkId,sessionId));
  for(const page of pdf.getPages()) {
    const media=page.getMediaBox(),crop=page.getCropBox();
    if(page.getRotation().angle!==0 || media.x!==0 || media.y!==0 || JSON.stringify(media)!==JSON.stringify(crop) || media.width<310)
      throw new Error('Visual demo requires unrotated, uncropped pages at least 310pt wide.');
    if(page.node.Annots()?.size()) throw new Error('Visual footer does not support annotated/form PDFs.');
    page.setSize(media.width,media.height+160);page.translateContent(0,160);page.resetPosition();
    page.drawImage(tile,{x:10,y:10,width:140,height:140});
    page.drawImage(tile,{x:media.width-150,y:10,width:140,height:140});
    page.drawLine({start:{x:0,y:159},end:{x:media.width,y:159},color:rgb(.8,.8,.8),thickness:.5});
  }
}
