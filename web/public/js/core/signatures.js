// Binary signature scanner (binwalk-style): scans raw bytes for known file
// signatures ("magic" markers) and reports each hit with its offset — the
// same core function binwalk performs on firmware images. Carving out the
// recoverable ones is done by carve.js; this module only reports.
const MAGICS = [
  { name: 'PNG image', sig: [0x89, 0x50, 0x4e, 0x47], off: 0 },
  { name: 'JPEG image', sig: [0xff, 0xd8, 0xff], off: 0 },
  { name: 'GIF image', sig: [0x47, 0x49, 0x46, 0x38], off: 0 },
  { name: 'gzip stream', sig: [0x1f, 0x8b], off: 0 },
  { name: 'bzip2 stream', sig: [0x42, 0x5a, 0x68], off: 0 },
  { name: 'xz stream', sig: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], off: 0 },
  { name: '7-Zip archive', sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], off: 0 },
  { name: 'ZIP archive / OOXML', sig: [0x50, 0x4b, 0x03, 0x04], off: 0 },
  { name: 'RAR archive', sig: [0x52, 0x61, 0x72, 0x21], off: 0 },
  { name: 'SQLite database', sig: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65], off: 0 },
  { name: 'ELF executable', sig: [0x7f, 0x45, 0x4c, 0x46], off: 0 },
  { name: 'Mach-O 64-bit', sig: [0xcf, 0xfa, 0xed, 0xfe], off: 0 },
  { name: 'Mach-O 32-bit', sig: [0xce, 0xfa, 0xed, 0xfe], off: 0 },
  { name: 'Mach-O fat/universal', sig: [0xca, 0xfe, 0xba, 0xbe], off: 0 },
  { name: 'dyld shared cache', sig: [0x64, 0x79, 0x6c, 0x64, 0x5f, 0x76, 0x31], off: 0 }, // "dyld_v1"
  { name: 'Apple CMS structure (IMG4/IM4P/IM4M/IM4C)', sig: [0x00, 0x00, 0x00], off: 0, custom: 'img4' },
  { name: 'DER certificate / CMS blob', sig: [0x30, 0x82], off: 0 },
  { name: 'OpenSSL-style private key header', sig: [0x2d, 0x2d, 0x2d, 0x2d], off: 0, custom: 'pem' },
  { name: 'LZMA / raw LZMA block', sig: [0x5d, 0x00, 0x00], off: 0, skip: 1 },
];

const IMG4_TAGS = ['IMG4', 'IM4P', 'IM4M', 'IM4C', 'IM4R'];

export const SCAN_LIMITS = { maxFileBytes: 64 << 20, maxFiles: 400, maxHitsPerFile: 400, minGap: 16 };

function findImg4Tags(u8, limit) {
  const hits = [];
  const tdTag = new TextDecoder('latin1');
  // IMG4/IM4P tags appear as 4 ASCII bytes right after an ASN.1 length; scan coarsely.
  const text = tdTag.decode(u8.subarray(0, Math.min(u8.length, limit)));
  for (const tag of IMG4_TAGS) {
    let idx = 0;
    while ((idx = text.indexOf(tag, idx)) !== -1 && hits.length < limit) {
      hits.push({ offset: idx, name: `Apple CMS structure (${tag})` });
      idx += tag.length;
    }
  }
  return hits;
}

function findPem(u8, limit) {
  const hits = [];
  const t = new TextDecoder('latin1').decode(u8.subarray(0, Math.min(u8.length, limit)));
  const re = /-----BEGIN ([A-Z0-9 ]{2,40})-----/g;
  let m2;
  while ((m2 = re.exec(t)) && hits.length < 40) {
    hits.push({ offset: m2.index, name: `PEM block: ${m2[1]}` });
  }
  return hits;
}
export { findPem };

/** Scan one buffer. Returns hits: [{offset, name}]. */
export function scanBuffer(u8, { maxHits = SCAN_LIMITS.maxHitsPerFile } = {}) {
  const hits = [];
  const n = u8.length;
  for (let i = 0; i < n; i++) {
    for (const m of MAGICS) {
      if (m.custom) continue;
      const s = m.sig;
      let ok = true;
      for (let k = 0; k < s.length; k++) {
        if (u8[i + k] !== s[k]) { ok = false; break; }
      }
      if (ok) {
        // gzip inside PNG IDAT etc. — keep every genuine hit; minGap filters jitter
        const last = hits[hits.length - 1];
        if (m.skip && (u8[i + 1] !== 0x00 || u8[i + 2] !== 0x00)) { continue; } // LZMA needs 0x5d0000xx
        if (!last || last.name !== m.name || i - last.offset > SCAN_LIMITS.minGap) {
          if (hits.length < maxHits) hits.push({ offset: i, name: m.name });
          else return { hits, truncated: true };
        }
        i += s.length - 1;
        break;
      }
    }
  }
  return { hits, truncated: false };
}

/** Scan a set of files through a bounded getBytes(). */
export async function scanFiles(files, getBytes, { perFileLimit = SCAN_LIMITS.maxFileBytes } = {}) {
  const out = [];
  let scanned = 0;
  for (const f of files) {
    if (out.length >= SCAN_LIMITS.maxFiles) break;
    if (f.isDir || f.size < 16 || f.size > perFileLimit) continue;
    if (!/\.(bin|dat|zip|ipa|7z|gz|bz2|xz|lzma|dylib|ipa|deb|tar|cache|img4|im4p|raw|store|db|sqlite|car|pak|blob|data|so|o|a|framework|)/i.test(f.path) && f.size < 4096) continue;
    try {
      const { bytes } = await getBytes(f, perFileLimit);
      if (!bytes || bytes.length < 16) continue;
      let { hits, truncated } = scanBuffer(bytes);
      const img4 = findImg4Tags(bytes, 64);
      const pem = findPem(bytes, perFileLimit);
      hits = hits.concat(img4, pem);
      if (hits.length || truncated) { out.push({ path: f.path, size: f.size, hits, truncated, scanned: bytes.length }); scanned++; }
    } catch { /* unreadable entries are reported elsewhere */ }
  }
  return { ok: true, files: out, filesScanned: scanned };
}
