// Pure-JS raw DEFLATE decoder (puff-style). Used only as a fallback when DecompressionStream('deflate-raw') is unavailable
// (older Safari) and for PNG (CgBI) previews.
import { AppError } from './util.js';

const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

function build(lengths, n) {
  const count = new Uint16Array(16);
  const symbol = new Uint16Array(n);
  for (let i = 0; i < n; i++) count[lengths[i]]++;
  const offs = new Uint16Array(16);
  for (let l = 1; l < 15; l++) offs[l + 1] = offs[l] + count[l];
  for (let s = 0; s < n; s++) if (lengths[s]) symbol[offs[lengths[s]]++] = s;
  return { count, symbol };
}

let fixedLit = null, fixedDist = null;
function fixed() {
  if (!fixedLit) {
    const l = new Uint8Array(288);
    for (let i = 0; i < 144; i++) l[i] = 8;
    for (let i = 144; i < 256; i++) l[i] = 9;
    for (let i = 256; i < 280; i++) l[i] = 7;
    for (let i = 280; i < 288; i++) l[i] = 8;
    fixedLit = build(l, 288);
    fixedDist = build(new Uint8Array(30).fill(5), 30);
  }
}

export function inflateRaw(src, sizeHint = 0) {
  let pos = 0, bitBuf = 0, bitCnt = 0;
  let out = new Uint8Array(Math.max(sizeHint, src.length * 3, 1024));
  let op = 0;
  const bits = (n) => {
    let v = bitBuf;
    while (bitCnt < n) {
      if (pos >= src.length) throw new AppError('inflate', 'Unexpected end of compressed data.');
      v |= src[pos++] << bitCnt;
      bitCnt += 8;
    }
    bitBuf = v >>> n;
    bitCnt -= n;
    return v & ((1 << n) - 1);
  };
  const decode = (h) => {
    let code = 0, first = 0, index = 0;
    for (let len = 1; len <= 15; len++) {
      code |= bits(1);
      const count = h.count[len];
      if (code - count < first) return h.symbol[index + (code - first)];
      index += count; first += count; first <<= 1; code <<= 1;
    }
    throw new AppError('inflate', 'Invalid Huffman code.');
  };
  const ensure = (n) => {
    if (op + n > out.length) {
      const bigger = new Uint8Array(Math.max(out.length * 2, op + n));
      bigger.set(out.subarray(0, op));
      out = bigger;
    }
  };
  const codes = (lit, dist) => {
    for (;;) {
      let sym = decode(lit);
      if (sym < 256) { ensure(1); out[op++] = sym; }
      else if (sym === 256) return;
      else {
        sym -= 257;
        if (sym >= 29) throw new AppError('inflate', 'Invalid length symbol.');
        const len = LBASE[sym] + bits(LEXT[sym]);
        const ds = decode(dist);
        if (ds >= 30) throw new AppError('inflate', 'Invalid distance symbol.');
        const d = DBASE[ds] + bits(DEXT[ds]);
        if (d > op) throw new AppError('inflate', 'Distance too far back.');
        ensure(len);
        for (let i = 0; i < len; i++) { out[op] = out[op - d]; op++; }
      }
    }
  };
  let last;
  do {
    last = bits(1);
    const type = bits(2);
    if (type === 0) {
      bitBuf = 0; bitCnt = 0;
      if (pos + 4 > src.length) throw new AppError('inflate', 'Truncated stored block.');
      const len = src[pos] | (src[pos + 1] << 8);
      const nlen = src[pos + 2] | (src[pos + 3] << 8);
      if ((len ^ 0xffff) !== nlen) throw new AppError('inflate', 'Stored block length mismatch.');
      pos += 4;
      if (pos + len > src.length) throw new AppError('inflate', 'Truncated stored block.');
      ensure(len);
      out.set(src.subarray(pos, pos + len), op);
      op += len; pos += len;
    } else if (type === 1) {
      fixed();
      codes(fixedLit, fixedDist);
    } else if (type === 2) {
      const nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
      if (nlen > 286 || ndist > 30) throw new AppError('inflate', 'Bad dynamic block counts.');
      const lengths = new Uint8Array(320);
      for (let i = 0; i < ncode; i++) lengths[ORDER[i]] = bits(3);
      const lencode = build(lengths.subarray(0, 19), 19);
      const ll = new Uint8Array(320);
      let idx = 0;
      while (idx < nlen + ndist) {
        let sym = decode(lencode);
        if (sym < 16) ll[idx++] = sym;
        else {
          let prev = 0, rep;
          if (sym === 16) { if (idx === 0) throw new AppError('inflate', 'Bad repeat.'); prev = ll[idx - 1]; rep = 3 + bits(2); }
          else if (sym === 17) rep = 3 + bits(3);
          else rep = 11 + bits(7);
          if (idx + rep > nlen + ndist) throw new AppError('inflate', 'Too many code lengths.');
          while (rep--) ll[idx++] = prev;
        }
      }
      codes(build(ll.subarray(0, nlen), nlen), build(ll.subarray(nlen, nlen + ndist), ndist));
    } else throw new AppError('inflate', 'Invalid block type.');
  } while (!last);
  return out.subarray(0, op);
}
