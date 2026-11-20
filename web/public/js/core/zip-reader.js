// Dependency-free ZIP reader: ZIP64, data descriptors, prefixed archives, UTF-8 / CP437 names, streamed decompression.
// Every central-directory record is kept (duplicates, unsafe paths, unsupported methods are FLAGGED, never dropped).
import { AppError, readRange, isUnsafePath, readStream } from './util.js';
import { Crc32 } from './crc32.js';
import { inflateRaw } from './inflate.js';

const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';
function decodeCp437(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i] < 128 ? String.fromCharCode(b[i]) : CP437[b[i] - 128];
  return s;
}
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

function decodeName(raw, flags, extra) {
  // Info-ZIP Unicode Path Extra Field (0x7075) wins if its CRC matches the raw name.
  const up = findExtra(extra, 0x7075);
  if (up && up.length > 5 && up[0] === 1) {
    const want = new DataView(up.buffer, up.byteOffset, up.byteLength).getUint32(1, true);
    if (new Crc32().update(raw).value === want) {
      try { return strictUtf8.decode(up.subarray(5)); } catch { /* fall through */ }
    }
  }
  if (flags & 0x800) { try { return strictUtf8.decode(raw); } catch { /* fall through */ } }
  try { return strictUtf8.decode(raw); } catch { return decodeCp437(raw); }
}

function findExtra(extra, id) {
  let p = 0;
  while (p + 4 <= extra.length) {
    const dv = new DataView(extra.buffer, extra.byteOffset + p, 4);
    const eid = dv.getUint16(0, true), len = dv.getUint16(2, true);
    if (p + 4 + len > extra.length) break;
    if (eid === id) return extra.subarray(p + 4, p + 4 + len);
    p += 4 + len;
  }
  return null;
}

const u64 = (dv, o) => dv.getUint32(o, true) + dv.getUint32(o + 4, true) * 4294967296;

export const METHOD_NAMES = { 0: 'stored', 1: 'shrunk', 6: 'imploded', 8: 'deflate', 9: 'deflate64', 12: 'bzip2', 14: 'lzma', 93: 'zstd', 95: 'xz', 98: 'ppmd', 99: 'aes' };

export async function openZip(blob, { signal } = {}) {
  const size = blob.size;
  if (size < 22) throw new AppError('not-zip', 'The file is too small to be a ZIP/IPA archive.');
  const tailLen = Math.min(size, 65535 + 22 + 64);
  const tailStart = size - tailLen;
  const tail = await readRange(blob, tailStart, size);
  let eocd = -1, loose = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 5 && tail[i + 3] === 6) {
      const cl = tail[i + 20] | (tail[i + 21] << 8);
      if (i + 22 + cl === tail.length) { eocd = i; break; }
      if (loose < 0) loose = i;
    }
  }
  const warnings = [];
  if (eocd < 0 && loose >= 0) { eocd = loose; warnings.push('Trailing bytes after the end-of-central-directory record.'); }
  if (eocd < 0) throw new AppError('not-zip', 'No ZIP end-of-central-directory record found. The file is not a ZIP/IPA archive, or it is truncated/damaged.');
  const eocdAbs = tailStart + eocd;
  let dv = new DataView(tail.buffer, tail.byteOffset + eocd, 22);
  const diskNo = dv.getUint16(4, true), cdDisk = dv.getUint16(6, true);
  let total = dv.getUint16(10, true), cdSize = dv.getUint32(12, true), cdOff = dv.getUint32(16, true);
  const commentLen = dv.getUint16(20, true);
  const comment = commentLen ? new TextDecoder().decode(tail.subarray(eocd + 22, eocd + 22 + commentLen)) : '';
  let cdEndAbs = eocdAbs; // absolute position where the central directory must end
  let zip64 = false;
  if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
    const locAbs = eocdAbs - 20;
    if (locAbs >= 0) {
      const loc = await readRange(blob, locAbs, locAbs + 20);
      const ldv = new DataView(loc.buffer, loc.byteOffset, 20);
      if (ldv.getUint32(0, true) === 0x07064b50) {
        const z64Off = u64(ldv, 8);
        let z64Abs = z64Off;
        let rec = await readRange(blob, z64Abs, z64Abs + 56);
        if (rec.length < 56 || new DataView(rec.buffer, rec.byteOffset).getUint32(0, true) !== 0x06064b50) {
          // archive may carry a prefix; locate by scanning backwards from the locator
          z64Abs = locAbs - 56;
          rec = await readRange(blob, z64Abs, z64Abs + 56);
        }
        const zdv = new DataView(rec.buffer, rec.byteOffset, rec.length);
        if (rec.length === 56 && zdv.getUint32(0, true) === 0x06064b50) {
          total = u64(zdv, 32); cdSize = u64(zdv, 40); cdOff = u64(zdv, 48);
          cdEndAbs = z64Abs; zip64 = true;
        } else throw new AppError('bad-zip64', 'ZIP64 end-of-central-directory record is damaged.');
      } else throw new AppError('bad-zip64', 'ZIP64 locator not found although the archive requires ZIP64.');
    }
  }
  if (diskNo !== 0 || cdDisk !== 0) throw new AppError('multi-disk', 'Multi-part (split) ZIP archives are not supported. Combine the parts first.');
  const cdStartAbs = cdEndAbs - cdSize;
  const delta = cdStartAbs - cdOff; // non-zero when bytes were prepended to the archive
  if (cdStartAbs < 0 || cdStartAbs + cdSize > size) throw new AppError('bad-cd', 'The central directory points outside the file (truncated or damaged archive).');
  if (delta !== 0) warnings.push(`Archive has ${delta} extra byte(s) before the ZIP data; offsets were adjusted.`);
  const cd = await readRange(blob, cdStartAbs, cdStartAbs + cdSize);
  if (cd.length !== cdSize) throw new AppError('bad-cd', 'Could not read the whole central directory (truncated file).');
  const cdv = new DataView(cd.buffer, cd.byteOffset, cd.byteLength);
  const entries = [];
  let p = 0;
  while (p + 46 <= cd.length && cdv.getUint32(p, true) === 0x02014b50) {
    const madeBy = cdv.getUint16(p + 4, true), needed = cdv.getUint16(p + 6, true), flags = cdv.getUint16(p + 8, true);
    const method = cdv.getUint16(p + 10, true), time = cdv.getUint16(p + 12, true), date = cdv.getUint16(p + 14, true);
    const crc = cdv.getUint32(p + 16, true);
    let csize = cdv.getUint32(p + 20, true), usize = cdv.getUint32(p + 24, true);
    const nl = cdv.getUint16(p + 28, true), el = cdv.getUint16(p + 30, true), cl = cdv.getUint16(p + 32, true);
    const intAttr = cdv.getUint16(p + 36, true), extAttr = cdv.getUint32(p + 38, true);
    let lho = cdv.getUint32(p + 42, true);
    if (p + 46 + nl + el + cl > cd.length) throw new AppError('bad-cd', 'Central directory entry runs past the end of the directory (damaged archive).');
    const nameRaw = cd.slice(p + 46, p + 46 + nl);
    const extra = cd.subarray(p + 46 + nl, p + 46 + nl + el);
    if (csize === 0xffffffff || usize === 0xffffffff || lho === 0xffffffff) {
      const z = findExtra(extra, 0x0001);
      if (z) {
        const zd = new DataView(z.buffer, z.byteOffset, z.byteLength);
        let q = 0;
        if (usize === 0xffffffff && q + 8 <= z.length) { usize = u64(zd, q); q += 8; }
        if (csize === 0xffffffff && q + 8 <= z.length) { csize = u64(zd, q); q += 8; }
        if (lho === 0xffffffff && q + 8 <= z.length) { lho = u64(zd, q); q += 8; }
      }
    }
    const name = decodeName(nameRaw, flags, extra);
    const unixMode = (madeBy >> 8) === 3 ? (extAttr >>> 16) : 0;
    const isDir = name.endsWith('/') || ((extAttr & 0x10) !== 0 && usize === 0) || (unixMode & 0o170000) === 0o040000;
    entries.push({
      index: entries.length, name, nameRaw, flags, method, time, date, crc, csize, usize,
      madeBy, needed, intAttr, extAttr, mode: unixMode, localOffset: lho + delta,
      isDir, isSymlink: (unixMode & 0o170000) === 0o120000,
      encrypted: (flags & 1) !== 0, unsafePath: isUnsafePath(name.replace(/\/$/, '')),
      dataOffset: -1, problems: [],
    });
    p += 46 + nl + el + cl;
  }
  if (entries.length !== total) {
    warnings.push(`Central directory declares ${total} entries but ${entries.length} were parsed.`);
  }
  if (p < cd.length) warnings.push(`${cd.length - p} unparsed byte(s) at the end of the central directory.`);
  // Read local headers (data offsets), sorted by position for locality.
  const order = entries.slice().sort((a, b) => a.localOffset - b.localOffset);
  const B = 64;
  for (let i = 0; i < order.length; i += B) {
    if (signal && signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
    await Promise.all(order.slice(i, i + B).map(async (e) => {
      const want = 30 + e.nameRaw.length + 512;
      const h = await readRange(blob, e.localOffset, e.localOffset + want);
      if (h.length < 30) { e.problems.push('local-header-truncated'); return; }
      const hv = new DataView(h.buffer, h.byteOffset, h.length);
      if (hv.getUint32(0, true) !== 0x04034b50) { e.problems.push('local-header-missing'); return; }
      const lnl = hv.getUint16(26, true), lel = hv.getUint16(28, true);
      e.dataOffset = e.localOffset + 30 + lnl + lel;
      const ln = h.subarray(30, 30 + lnl);
      if (ln.length === lnl && (lnl !== e.nameRaw.length || ln.some((v, k) => v !== e.nameRaw[k]))) e.problems.push('local-name-differs');
      if (e.dataOffset + e.csize > cdStartAbs) e.problems.push('data-overlaps-directory');
    }));
  }
  const names = new Map();
  for (const e of entries) {
    const key = e.name;
    if (names.has(key)) { e.duplicate = true; names.get(key).duplicate = true; } else names.set(key, e);
    if (e.encrypted) e.problems.push('encrypted-entry');
    if (e.method !== 0 && e.method !== 8) e.problems.push('unsupported-method');
    if (e.unsafePath) e.problems.push('unsafe-path');
    if (e.duplicate && !e.problems.includes('duplicate-name')) e.problems.push('duplicate-name');
  }
  for (const e of entries) if (e.duplicate && !e.problems.includes('duplicate-name')) e.problems.push('duplicate-name');
  return { entries, comment, zip64, warnings, size, totalDeclared: total, centralDirOffset: cdStartAbs, centralDirSize: cdSize, prefixBytes: Math.max(0, delta) };
}

let deflateRawOK = null;
function nativeInflateAvailable() {
  if (deflateRawOK === null) {
    try { new DecompressionStream('deflate-raw'); deflateRawOK = true; } catch { deflateRawOK = false; }
  }
  return deflateRawOK;
}

/** Stream of an entry's decompressed bytes. */
export function entryStream(blob, e) {
  if (e.encrypted) throw new AppError('encrypted', `"${e.name}" is password-encrypted inside the archive and cannot be read.`);
  if (e.dataOffset < 0) throw new AppError('bad-entry', `"${e.name}" has a damaged local header.`);
  const slice = blob.slice(e.dataOffset, e.dataOffset + e.csize);
  if (e.method === 0) return slice.stream();
  if (e.method === 8) {
    if (nativeInflateAvailable()) return slice.stream().pipeThrough(new DecompressionStream('deflate-raw'));
    let done = false;
    return new ReadableStream({
      async pull(ctrl) {
        if (done) return;
        done = true;
        const out = inflateRaw(new Uint8Array(await slice.arrayBuffer()), e.usize);
        for (let o = 0; o < out.length; o += 1 << 20) ctrl.enqueue(out.subarray(o, Math.min(out.length, o + (1 << 20))));
        ctrl.close();
      },
    });
  }
  throw new AppError('unsupported-method', `"${e.name}" uses compression method ${e.method} (${METHOD_NAMES[e.method] || 'unknown'}), which this tool cannot decompress. The raw bytes are still preserved in ZIP exports.`);
}

/** Decompress an entry, calling onChunk for each piece; returns { size, crc, truncated }. */
export async function readEntry(blob, e, { onChunk, maxBytes, signal } = {}) {
  const crc = new Crc32();
  const r = await readStream(entryStream(blob, e), {
    signal, maxBytes,
    onChunk: async (c) => { crc.update(c); if (onChunk) await onChunk(c); },
  });
  return { size: r.total, crc: crc.value, truncated: r.truncated };
}

/** Collect an entry (or its first maxBytes) into a Blob without needing contiguous memory. */
export async function entryToBlob(blob, e, { maxBytes, signal, type = '' } = {}) {
  const parts = [];
  const r = await readEntry(blob, e, { maxBytes, signal, onChunk: (c) => { parts.push(c); } });
  return { blob: new Blob(parts, { type }), truncated: r.truncated, size: r.size };
}

export async function entryBytes(blob, e, maxBytes = 1 << 20, signal) {
  const chunks = [];
  let n = 0;
  const r = await readEntry(blob, e, { maxBytes, signal, onChunk: (c) => { chunks.push(c); n += c.length; } });
  const out = new Uint8Array(Math.min(n, maxBytes ?? n));
  let o = 0;
  for (const c of chunks) { const take = Math.min(c.length, out.length - o); out.set(c.subarray(0, take), o); o += take; if (o >= out.length) break; }
  return { bytes: out, truncated: r.truncated || n > out.length, size: r.size };
}
