// Apple "CgBI" PNG -> standard PNG (for display only; originals are never modified).
import { Crc32 } from './crc32.js';
import { inflateRaw } from './inflate.js';
import { concatBytes, latin1 } from './util.js';

const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const be32 = (u, o) => ((u[o] << 24) | (u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]) >>> 0;
function chunk(type, data) {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length); for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  dv.setUint32(8 + data.length, new Crc32().update(out.subarray(4, 8 + data.length)).value);
  return out;
}
async function zlibDeflate(u8) {
  const cs = new CompressionStream('deflate');
  const w = cs.writable.getWriter(); w.write(u8); w.close();
  const parts = []; const r = cs.readable.getReader();
  for (;;) { const { done, value } = await r.read(); if (done) break; parts.push(value); }
  return concatBytes(parts);
}
export function isCgBI(u8) { return u8.length > 16 && SIG.every((v, i) => u8[i] === v) && latin1(u8, 12, 16) === 'CgBI'; }

export async function cgbiToPng(u8) {
  if (!isCgBI(u8)) return u8;
  let p = 8, ihdr = null; const idat = []; const keep = [];
  while (p + 12 <= u8.length) {
    const len = be32(u8, p), type = latin1(u8, p + 4, p + 8), data = u8.subarray(p + 8, p + 8 + len);
    if (type === 'IHDR') ihdr = data; else if (type === 'IDAT') idat.push(data); else if (type !== 'CgBI' && type !== 'IEND') keep.push([type, data]);
    p += 12 + len;
  }
  if (!ihdr) throw new Error('PNG has no IHDR');
  const w = be32(ihdr, 0), h = be32(ihdr, 4), bitDepth = ihdr[8], colorType = ihdr[9];
  if (bitDepth !== 8 || (colorType !== 6 && colorType !== 2)) { // unusual: just drop CgBI chunk, keep raw stream
    throw new Error('Unsupported CgBI layout');
  }
  const raw = inflateRaw(concatBytes(idat), (w * 4 + 1) * h);
  const bpp = colorType === 6 ? 4 : 3, stride = w * bpp + 1;
  // Undo PNG filters, swap B<->R, un-premultiply alpha, then store with filter 0.
  const out = new Uint8Array(stride * h); const prev = new Uint8Array(stride - 1); const cur = new Uint8Array(stride - 1);
  for (let y = 0; y < h; y++) {
    const f = raw[y * stride]; const row = raw.subarray(y * stride + 1, (y + 1) * stride);
    for (let i = 0; i < row.length; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
      let v = row[i];
      if (f === 1) v += a; else if (f === 2) v += b; else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const pp = a + b - c, pa = Math.abs(pp - a), pb = Math.abs(pp - b), pc = Math.abs(pp - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      cur[i] = v & 255;
    }
    prev.set(cur);
    const o = y * stride + 1;
    for (let x = 0; x < w; x++) {
      const i = x * bpp; let r = cur[i + 2], g = cur[i + 1], bl = cur[i];
      if (bpp === 4) { const al = cur[i + 3]; if (al > 0 && al < 255) { r = Math.min(255, Math.round(r * 255 / al)); g = Math.min(255, Math.round(g * 255 / al)); bl = Math.min(255, Math.round(bl * 255 / al)); } out[o + i + 3] = al; }
      out[o + i] = r; out[o + i + 1] = g; out[o + i + 2] = bl;
    }
  }
  const parts = [new Uint8Array(SIG), chunk('IHDR', ihdr)];
  for (const [t, d] of keep) parts.push(chunk(t, d));
  parts.push(chunk('IDAT', await zlibDeflate(out)), chunk('IEND', new Uint8Array(0)));
  return concatBytes(parts);
}
