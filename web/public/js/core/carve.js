// Best-effort recovery of complete embedded images (PNG / Apple CgBI PNG / JPEG)
// from opaque compiled containers — asset catalogs (Assets.car), nib archives, font
// and data files. Purely additive inspection:
//   - originals are never modified,
//   - nothing is fabricated: a carved image must parse fully and consistently from
//     its own bytes (signature + complete structure) before it is reported,
//   - no source code is reconstructed (compiled code is untouched, as everywhere
//     else in Cairn).
// Streams the input, so peak memory stays low on phones. No dependencies beyond util.js.
import { AppError, concatBytes, latin1 } from './util.js';

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export const CARVE_LIMITS = {
  minSize: 1024,             // streams smaller than this are noise (thumbnails, fragments)
  maxImages: 300,            // stop after this many recovered images
  maxCarvedBytes: 128 << 20, // stop after this many recovered bytes in total
  maxImageBytes: 32 << 20,   // a single candidate larger than this is abandoned
  maxScanBytes: 512 << 20,   // stop scanning a file after this many input bytes
};

const be32 = (u, o) => ((u[o] << 24) | (u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]) >>> 0;
const alpha4 = (u, o) => {
  for (let i = 0; i < 4; i++) { const c = u[o + i]; if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return false; }
  return true;
};

/** FIFO byte queue with absolute offsets. Consumed bytes are dropped from the front. */
class ByteQ {
  constructor() { this.ch = []; this.len = 0; this.start = 0; }
  push(u8, base) { if (!this.len) this.start = base; this.ch.push(u8); this.len += u8.length; }
  peek(n) {
    if (n > this.len) n = this.len;
    if (!n) return new Uint8Array(0);
    const first = this.ch[0];
    if (first.length >= n) return first.subarray(0, n);
    const out = new Uint8Array(n); let o = 0;
    for (const c of this.ch) { if (o >= n) break; const t = Math.min(c.length, n - o); out.set(c.subarray(0, t), o); o += t; }
    return out;
  }
  drop(n) {
    n = Math.min(n, this.len);
    while (n > 0 && this.ch.length) {
      const f = this.ch[0];
      if (f.length <= n) { n -= f.length; this.len -= f.length; this.start += f.length; this.ch.shift(); }
      else { this.ch[0] = f.subarray(n); this.len -= n; this.start += n; n = 0; }
    }
  }
  read(n) { const out = this.peek(n); this.drop(out.length); return out; }
}

/**
 * Incremental carver. feed(u8, base) as many times as needed, then end().
 * Result: { images: [{ index, offset, size, kind, bytes }], limitReached, scanned }.
 * kind is 'png' | 'cgbi' | 'jpeg'.
 */
export class ImageCarver {
  constructor(opts = {}) {
    this.o = { ...CARVE_LIMITS, ...opts };
    this.q = new ByteQ();
    this.images = [];
    this.carved = 0;
    this.scanned = 0;
    this.limitReached = null;
    this.stopped = false;
    this.cand = null;
  }

  feed(u8, base) {
    if (this.stopped) return;
    this.q.push(u8, base);
    this._pump(false);
  }

  end() {
    if (this.stopped) { this._release(); return; }
    this._pump(true);
    this._release();
  }

  _release() { this.cand = null; this.q.drop(this.q.len); }

  _pump(isEnd) {
    for (;;) {
      if (this.stopped) return;
      if (this.cand) {
        const r = this.cand.kind === 'png' ? this._stepPng(isEnd) : this._stepJpeg(isEnd);
        if (r === 'wait') return;
        continue; // 'progress' or candidate completed/abandoned
      }
      const hold = isEnd ? 0 : 8;
      if (this.q.len <= hold) { if (isEnd) this.q.drop(this.q.len); return; }
      const buf = this.q.peek(this.q.len - hold);
      const hit = this._findSig(buf);
      if (!hit) { this.q.drop(buf.length); if (isEnd) this.q.drop(this.q.len); return; }
      this.q.drop(hit.rel);
      const startAbs = this.q.start;
      if (hit.kind === 'png') {
        const sig = this.q.read(8);
        this.cand = { kind: 'png', start: startAbs, parts: [sig], size: 8, phase: 'head', need: 8, ihdr: false, cgbi: false, idat: false, first: null };
      } else {
        const soi = this.q.read(2); // FF D8 (the third sig byte belongs to the next marker)
        this.cand = { kind: 'jpeg', start: startAbs, parts: [soi], size: 2, phase: 'marker', sos: false, sof: false, segMarker: 0 };
      }
    }
  }

  _findSig(buf) {
    const n = buf.length;
    for (let j = 0; j + 3 <= n;) {
      const a = buf.indexOf(0x89, j), b = buf.indexOf(0xff, j);
      if (a === -1 && b === -1) return null;
      const k = a === -1 ? b : b === -1 ? a : Math.min(a, b);
      if (k === a && k + 8 <= n && PNG_SIG.every((v, t) => buf[k + t] === v)) return { rel: k, kind: 'png' };
      if (k === b && buf[k + 1] === 0xd8 && buf[k + 2] === 0xff) return { rel: k, kind: 'jpeg' };
      j = k + 1;
    }
    return null;
  }

  _abandon() { this.cand = null; return 'progress'; }

  _emit(c, kindOverride) {
    this.cand = null;
    const bytes = c.parts.length === 1 ? c.parts[0] : concatBytes(c.parts);
    if (bytes.length >= this.o.minSize) {
      const img = { index: this.images.length, offset: c.start, size: bytes.length, kind: kindOverride || c.kind, bytes };
      this.images.push(img);
      this.carved += bytes.length;
      if (this.o.onFound) { try { this.o.onFound(img); } catch { /* listener errors must not break scanning */ } }
    }
    if (this.images.length >= this.o.maxImages) this._stop('maxImages');
    else if (this.carved >= this.o.maxCarvedBytes) this._stop('maxCarvedBytes');
    return 'progress';
  }

  _stop(reason) { this.limitReached = reason; this.stopped = true; this.cand = null; this.q.drop(this.q.len); }

  _stepPng(isEnd) {
    const c = this.cand;
    for (;;) {
      if (c.phase === 'head') {
        if (this.q.len < c.need) return isEnd ? this._abandon() : 'wait';
        const head = this.q.read(c.need);
        c.parts.push(head); c.size += c.need;
        const len = be32(head, 0), type = latin1(head, 4, 8);
        if (!alpha4(head, 4)) return this._abandon();
        if (!c.first) {
          c.first = type;
          if (type === 'CgBI') c.cgbi = true;
          else if (type !== 'IHDR') return this._abandon();
        } else if (type === 'CgBI') return this._abandon(); // CgBI only right after the signature
        if (type === 'IHDR') { if (c.ihdr || len !== 13) return this._abandon(); c.ihdr = true; }
        if (type === 'IDAT' && !c.ihdr) return this._abandon();
        if (type === 'IDAT') c.idat = true;
        if (type === 'IEND') {
          if (len !== 0 || !c.ihdr || !c.idat) return this._abandon();
          c.phase = 'tail'; c.need = 4; // trailing CRC of IEND — carved image must be byte-exact
        } else {
          if (len > this.o.maxImageBytes || c.size + len > this.o.maxImageBytes) return this._abandon();
          c.phase = 'body'; c.need = len + 4; // data + CRC
        }
      } else { // body or tail
        if (this.q.len < c.need) return isEnd ? this._abandon() : 'wait';
        while (c.need > 0) {
          const body = this.q.read(Math.min(c.need, 1 << 22));
          c.parts.push(body); c.size += body.length; c.need -= body.length;
        }
        if (c.phase === 'tail') return this._emit(c, c.cgbi ? 'cgbi' : 'png');
        c.phase = 'head'; c.need = 8;
        return 'progress';
      }
    }
  }

  _stepJpeg(isEnd) {
    const c = this.cand;
    for (;;) {
      if (c.phase === 'marker') {
        if (this.q.len < 2) return isEnd ? this._abandon() : 'wait';
        const p = this.q.peek(2);
        if (p[0] !== 0xff) return this._abandon();
        let m = p[1], skip = 2;
        while (m === 0xff) { if (this.q.len < skip + 1) return isEnd ? this._abandon() : 'wait'; m = this.q.peek(skip + 1)[skip]; skip++; }
        c.parts.push(this.q.read(skip)); c.size += skip;
        if (m === 0xd9) { if (!c.sos || !c.sof) return this._abandon(); return this._emit(c); } // EOI
        if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) continue; // standalone markers
        if (m === 0xd8) return this._abandon(); // nested SOI before SOS = noise
        if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) c.sof = true;
        c.segMarker = m; c.phase = 'segl';
      } else if (c.phase === 'segl') {
        if (this.q.len < 2) return isEnd ? this._abandon() : 'wait';
        const l = this.q.read(2);
        c.parts.push(l); c.size += 2;
        const L = (l[0] << 8) | l[1];
        if (L < 2 || c.size + L > this.o.maxImageBytes) return this._abandon();
        if (c.segMarker === 0xda) { c.sos = true; c.afterSegp = 'entropy'; } else c.afterSegp = 'marker';
        c.phase = 'segp'; c.need = L - 2;
      } else if (c.phase === 'segp') {
        if (this.q.len < c.need) return isEnd ? this._abandon() : 'wait';
        while (c.need > 0) {
          const t = this.q.read(Math.min(c.need, 1 << 20));
          c.parts.push(t); c.size += t.length; c.need -= t.length;
        }
        c.phase = c.afterSegp;
        return 'progress';
      } else { // entropy
        const hold = isEnd ? 0 : 2;
        if (this.q.len <= hold) { if (isEnd) return this._abandon(); return 'wait'; }
        const buf = this.q.peek(this.q.len - hold);
        let e = -1;
        for (let j = buf.indexOf(0xd9); j !== -1; j = buf.indexOf(0xd9, j + 1)) {
          if (j > 0 && buf[j - 1] === 0xff) { e = j; break; }
        }
        if (e === -1) {
          c.parts.push(this.q.read(buf.length)); c.size += buf.length;
          if (c.size > this.o.maxImageBytes) return this._abandon();
          return 'progress';
        }
        c.parts.push(this.q.read(e - 1)); c.size += e - 1; // bytes before the EOI pair (FF sits at e-1)
        c.parts.push(this.q.read(2)); c.size += 2;         // FF D9
        if (!c.sos || !c.sof) return this._abandon();
        return this._emit(c);
      }
    }
  }
}

/** Carve from an in-memory buffer. */
export async function carveBytes(u8, opts = {}) {
  const cv = new ImageCarver(opts);
  const CH = 1 << 22;
  for (let i = 0; i < u8.length; i += CH) {
    if (cv.stopped) break;
    cv.feed(u8.subarray(i, Math.min(u8.length, i + CH)), i);
    cv.scanned = Math.min(u8.length, i + CH);
    if (opts.signal && opts.signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
  }
  if (!cv.stopped) cv.end();
  cv.scanned = u8.length;
  return { images: cv.images, limitReached: cv.limitReached, scanned: cv.scanned };
}

/** Carve from one ZIP/IPA entry without loading it fully into memory. */
export async function carveEntry(srcBlob, entry, opts = {}) {
  const { entryStream } = await import('./zip-reader.js');
  const cv = new ImageCarver(opts);
  const reader = entryStream(srcBlob, entry).getReader();
  let base = 0;
  try {
    for (;;) {
      if (opts.signal && opts.signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
      if (cv.stopped || (opts.maxScanBytes && base >= opts.maxScanBytes)) { try { await reader.cancel(); } catch { /* already closed */ } break; }
      const { done, value } = await reader.read();
      if (done) break;
      base += value.length;
      cv.scanned = base;
      cv.feed(value, base - value.length);
      if (opts.onProgress) opts.onProgress({ scanned: base, total: entry.usize, found: cv.images.length });
    }
  } catch (err) {
    try { await reader.cancel(); } catch { /* ignore */ }
    throw err;
  }
  if (!cv.stopped) cv.end();
  return { images: cv.images, limitReached: cv.limitReached, scanned: cv.scanned, truncated: cv.stopped && base < entry.usize };
}
