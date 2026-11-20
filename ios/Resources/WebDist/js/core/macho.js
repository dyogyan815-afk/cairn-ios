// Mach-O inspector (thin + fat). Reads only metadata; never claims to recover source code.
import { latin1, cstr, td } from './util.js';

const CPU = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32' };
const ARM_SUB = { 0: 'all', 6: 'v6', 9: 'v7', 11: 'v7s', 12: 'v7k', 1: 'v4t', 2: 'v5' };
const FILETYPE = { 1: 'object', 2: 'executable', 3: 'fvmlib', 4: 'core', 5: 'preload', 6: 'dylib', 7: 'dylinker', 8: 'bundle', 9: 'dylib stub', 10: 'dSYM companion', 11: 'kext bundle' };
const PLATFORM = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 11: 'visionOS', 12: 'visionOS Simulator' };
const LC = { 0x1: 'LC_SEGMENT', 0x2: 'LC_SYMTAB', 0xb: 'LC_DYSYMTAB', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB', 0xe: 'LC_LOAD_DYLINKER', 0x19: 'LC_SEGMENT_64', 0x1b: 'LC_UUID', 0x1d: 'LC_CODE_SIGNATURE', 0x1e: 'LC_SEGMENT_SPLIT_INFO', 0x21: 'LC_ENCRYPTION_INFO', 0x24: 'LC_VERSION_MIN_MACOSX', 0x25: 'LC_VERSION_MIN_IPHONEOS', 0x26: 'LC_FUNCTION_STARTS', 0x29: 'LC_DATA_IN_CODE', 0x2a: 'LC_SOURCE_VERSION', 0x2c: 'LC_ENCRYPTION_INFO_64', 0x32: 'LC_BUILD_VERSION', 0x80000018: 'LC_LOAD_WEAK_DYLIB', 0x8000001c: 'LC_RPATH', 0x8000001f: 'LC_REEXPORT_DYLIB', 0x80000022: 'LC_DYLD_INFO_ONLY', 0x80000028: 'LC_MAIN', 0x80000033: 'LC_DYLD_EXPORTS_TRIE', 0x80000034: 'LC_DYLD_CHAINED_FIXUPS' };

export const MAGICS = { 0xfeedface: 'Mach-O 32-bit', 0xfeedfacf: 'Mach-O 64-bit', 0xcefaedfe: 'Mach-O 32-bit (byte-swapped)', 0xcffaedfe: 'Mach-O 64-bit (byte-swapped)', 0xcafebabe: 'Fat/universal Mach-O', 0xbebafeca: 'Fat/universal Mach-O (byte-swapped)', 0xcafebabf: 'Fat64 Mach-O' };

export function isMachO(u8) {
  if (u8.length < 8) return false;
  const m = ((u8[0] << 24) | (u8[1] << 16) | (u8[2] << 8) | u8[3]) >>> 0;
  if (m === 0xcafebabe) { const n = (u8[4] << 24) | (u8[5] << 16) | (u8[6] << 8) | u8[7]; return n > 0 && n < 32; } // Java class files share cafebabe
  return m in MAGICS;
}
const ver = (v) => `${v >>> 16}.${(v >>> 8) & 0xff}.${v & 0xff}`;

export function parseMachO(u8) {
  if (!isMachO(u8)) return { ok: false, error: 'Not a Mach-O file.' };
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const magic = dv.getUint32(0, false);
  if (magic === 0xcafebabe || magic === 0xcafebabf) {
    const n = dv.getUint32(4, false); const slices = [];
    const is64 = magic === 0xcafebabf, sz = is64 ? 32 : 20;
    for (let i = 0; i < n; i++) {
      const o = 8 + i * sz;
      const off = is64 ? Number(dv.getBigUint64(o + 8)) : dv.getUint32(o + 8), size = is64 ? Number(dv.getBigUint64(o + 16)) : dv.getUint32(o + 12);
      if (off + 4 > u8.length) { slices.push({ ok: false, error: 'Slice lies beyond the bytes inspected (file was read partially).', offset: off, size }); continue; }
      slices.push({ ...parseThin(u8.subarray(off, Math.min(u8.length, off + size))), offset: off, size });
    }
    return { ok: true, kind: 'fat', slices };
  }
  return { ok: true, kind: 'thin', slices: [{ ...parseThin(u8), offset: 0, size: u8.length }] };
}

function parseThin(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const magic = dv.getUint32(0, true);
  if (magic !== 0xfeedface && magic !== 0xfeedfacf) return { ok: false, error: 'Big-endian or unknown Mach-O slice (not inspected).' };
  const is64 = magic === 0xfeedfacf;
  const cputype = dv.getUint32(4, true) >>> 0, cpusub = dv.getUint32(8, true) & 0xffffff;
  const filetype = dv.getUint32(12, true), ncmds = dv.getUint32(16, true), sizeofcmds = dv.getUint32(20, true), flags = dv.getUint32(24, true);
  let arch = CPU[cputype] || `cpu 0x${cputype.toString(16)}`;
  if (arch === 'arm') arch += ARM_SUB[cpusub] ? ARM_SUB[cpusub] : '';
  if (arch === 'arm64' && cpusub === 2) arch = 'arm64e';
  const r = { ok: true, is64, arch, filetype: FILETYPE[filetype] || String(filetype), flags, pie: !!(flags & 0x200000), cmds: [], dylibs: [], weakDylibs: [], rpaths: [], segments: [], sections: [], encryption: null, uuid: null, platform: null, minOS: null, sdk: null, codeSignature: null, entitlements: null, symtab: null, signals: {} };
  let p = is64 ? 32 : 28;
  const end = Math.min(u8.length, p + sizeofcmds);
  const counts = {};
  for (let i = 0; i < ncmds && p + 8 <= end; i++) {
    const cmd = dv.getUint32(p, true), size = dv.getUint32(p + 4, true);
    if (size < 8 || p + size > u8.length) { r.warning = 'Load commands run past the bytes inspected.'; break; }
    const name = LC[cmd] || `0x${cmd.toString(16)}`;
    counts[name] = (counts[name] || 0) + 1;
    if (cmd === 0xc || cmd === 0x80000018 || cmd === 0xd || cmd === 0x8000001f) {
      const so = dv.getUint32(p + 8, true); const nm = cstr(u8, p + so, size - so);
      const compat = dv.getUint32(p + 20, true), cur = dv.getUint32(p + 16, true);
      if (cmd !== 0xd) (cmd === 0x80000018 ? r.weakDylibs : r.dylibs).push({ name: nm, current: ver(cur), compat: ver(compat) });
    } else if (cmd === 0x8000001c) r.rpaths.push(cstr(u8, p + dv.getUint32(p + 8, true), size));
    else if (cmd === 0x19 || cmd === 0x1) {
      const o = p + 8, segname = cstr(u8, o, 16);
      const g = is64 ? { vmaddr: Number(dv.getBigUint64(o + 16, true)), vmsize: Number(dv.getBigUint64(o + 24, true)), fileoff: Number(dv.getBigUint64(o + 32, true)), filesize: Number(dv.getBigUint64(o + 40, true)), nsects: dv.getUint32(o + 56, true) } : { vmaddr: dv.getUint32(o + 16, true), vmsize: dv.getUint32(o + 20, true), fileoff: dv.getUint32(o + 24, true), filesize: dv.getUint32(o + 28, true), nsects: dv.getUint32(o + 48, true) };
      r.segments.push({ name: segname, ...g });
      // Section headers (metadata only): segment_64 body after cmd/size is 64 bytes, segment_32 is 48.
      const hdr = o + (is64 ? 64 : 48), shSz = is64 ? 80 : 68, offAt = is64 ? 48 : 40, sizeAt = is64 ? 40 : 36;
      for (let s = 0; s < g.nsects; s++) {
        const q = hdr + s * shSz;
        if (q + shSz > u8.length) break;
        const sect = cstr(u8, q, 16), sseg = cstr(u8, q + 16, 16);
        const ssize = is64 ? Number(dv.getBigUint64(q + sizeAt, true)) : dv.getUint32(q + sizeAt, true);
        const soff = dv.getUint32(q + offAt, true);
        r.sections.push({ sect, seg: sseg, size: ssize, offset: soff });
      }
    } else if (cmd === 0x21 || cmd === 0x2c) {
      r.encryption = { cryptoff: dv.getUint32(p + 8, true), cryptsize: dv.getUint32(p + 12, true), cryptid: dv.getUint32(p + 16, true) };
    } else if (cmd === 0x1b) r.uuid = [...u8.subarray(p + 8, p + 24)].map((b) => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5').toUpperCase();
    else if (cmd === 0x32) { r.platform = PLATFORM[dv.getUint32(p + 8, true)] || String(dv.getUint32(p + 8, true)); r.minOS = ver(dv.getUint32(p + 12, true)); r.sdk = ver(dv.getUint32(p + 16, true)); }
    else if (cmd === 0x25 || cmd === 0x24) { r.platform = r.platform || (cmd === 0x25 ? 'iOS' : 'macOS'); r.minOS = r.minOS || ver(dv.getUint32(p + 8, true)); r.sdk = r.sdk || ver(dv.getUint32(p + 12, true)); }
    else if (cmd === 0x1d) r.codeSignature = { dataoff: dv.getUint32(p + 8, true), datasize: dv.getUint32(p + 12, true) };
    else if (cmd === 0x2) r.symtab = { symoff: dv.getUint32(p + 8, true), nsyms: dv.getUint32(p + 12, true), stroff: dv.getUint32(p + 16, true), strsize: dv.getUint32(p + 20, true) };
    p += size;
  }
  r.cmdCounts = counts;
  r.encrypted = !!(r.encryption && r.encryption.cryptid !== 0);
  if (r.codeSignature) Object.assign(r, parseSignature(u8, r.codeSignature));
  // Heuristic indicators from the string/symbol tables (only when readable).
  if (r.symtab && r.symtab.stroff + r.symtab.strsize <= u8.length && r.symtab.strsize > 0) {
    const strs = latin1(u8, r.symtab.stroff, r.symtab.stroff + Math.min(r.symtab.strsize, 8 << 20));
    r.signals.stackCanary = strs.includes('___stack_chk_guard') || strs.includes('___stack_chk_fail');
    r.signals.arc = strs.includes('_objc_release') || strs.includes('_objc_autoreleaseReturnValue') || strs.includes('_objc_storeStrong');
    r.signals.swift = strs.includes('swift_') || strs.includes('_$s') || r.dylibs.some((d) => /libswift/i.test(d.name));
    r.signals.objc = strs.includes('_objc_msgSend');
    r.symbolsReadable = !r.encrypted;
    const names = [];
    if (!r.encrypted) {
      for (let i = 0, so = r.symtab.symoff, st = is64 ? 16 : 12; i < Math.min(r.symtab.nsyms, 400) && so + (i + 1) * st <= u8.length; i++) {
        const strx = dv.getUint32(so + i * st, true); const type = u8[so + i * st + 4];
        if (type & 0xe0) continue; // debugging (stab) entry
        if (strx && strx < r.symtab.strsize) names.push(cstr(u8, r.symtab.stroff + strx, 200));
      }
    }
    r.sampleSymbols = names.slice(0, 100);
  }
  r.signals.swift = r.signals.swift || r.dylibs.some((d) => /libswift/i.test(d.name));
  r.hasDebugSymbols = r.segments.some((s) => s.name === '__DWARF');
  return r;
}

function parseSignature(u8, cs) {
  const out = { signature: null, entitlementsXml: null };
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const o = cs.dataoff;
  if (o + 12 > u8.length || dv.getUint32(o, false) !== 0xfade0cc0) return out;
  const count = dv.getUint32(o + 8, false);
  out.signature = { blobs: [] };
  for (let i = 0; i < count && o + 12 + i * 8 + 8 <= u8.length; i++) {
    const type = dv.getUint32(o + 12 + i * 8, false), off = o + dv.getUint32(o + 16 + i * 8, false);
    if (off + 8 > u8.length) continue;
    const magic = dv.getUint32(off, false), len = dv.getUint32(off + 4, false);
    out.signature.blobs.push({ type, magic: '0x' + magic.toString(16) });
    if (magic === 0xfade7171 && off + len <= u8.length) out.entitlementsXml = td.decode(u8.subarray(off + 8, off + len));
    if (magic === 0xfade0c02 && off + 44 <= u8.length) { // CodeDirectory
      const identOff = dv.getUint32(off + 20, false), flags = dv.getUint32(off + 12, false);
      out.signature.identifier = cstr(u8, off + identOff, 256); out.signature.cdFlags = flags;
      const teamOff = off + 8 < u8.length && dv.getUint32(off + 8, false) >= 0x20200 ? dv.getUint32(off + 48, false) : 0;
      if (teamOff) out.signature.teamId = cstr(u8, off + teamOff, 32);
    }
  }
  return out;
}

// ---------- Name tables left inside the binary ----------
// Compilers store human-readable identifiers (ObjC class/method names, C strings)
// as plain data sections. Listing them is standard binary inspection (like otool -s);
// it is NOT decompilation and never claims to recover original source code.
const OBJC_SECTIONS = { __objc_classname: 'classes', __objc_methname: 'methods', __objc_methtype: 'methodTypes' };
export const OBJC_NAME_CAPS = { perSectionBytes: 4 << 20, maxNames: 300000, maxNameLen: 2000, cstringSample: 20000 };

function cstrings(u8, start, size, cap, out) {
  const end = Math.min(start + Math.min(size, cap), u8.length);
  let s = start;
  while (s < end && out.length < OBJC_NAME_CAPS.maxNames) {
    let e = s;
    while (e < end && u8[e] !== 0) e++;
    if (e > s && e - s <= OBJC_NAME_CAPS.maxNameLen) out.push(String.fromCharCode(...u8.subarray(s, Math.min(e, s + 400))));
    s = e + 1;
  }
}

/** Pull the identifier tables from one parsed slice. slice = parsedMachO.slices[i]. */
export function objcNames(u8, slice) {
  if (!slice || !slice.ok) return { ok: false, error: 'Slice not readable.' };
  if (slice.encrypted) return { ok: false, encrypted: true, error: 'Executable is FairPlay-encrypted: names are not readable.' };
  const res = { ok: true, classes: [], methods: [], methodTypes: [], strings: [], truncated: false };
  for (const sec of slice.sections || []) {
    const kind = OBJC_SECTIONS[sec.sect];
    if (kind && sec.size > 0) {
      cstrings(u8, sec.offset, sec.size, OBJC_NAME_CAPS.perSectionBytes, res[kind]);
      if (res[kind].length >= OBJC_NAME_CAPS.maxNames) res.truncated = true;
    }
  }
  const cs = (slice.sections || []).find((x) => x.sect === '__cstring' && x.seg === '__TEXT');
  if (cs && cs.size > 0) {
    const tmp = [];
    cstrings(u8, cs.offset, cs.size, OBJC_NAME_CAPS.perSectionBytes, tmp);
    res.stringsTotal = tmp.length;
    res.strings = tmp.slice(0, OBJC_NAME_CAPS.cstringSample);
    if (tmp.length > OBJC_NAME_CAPS.cstringSample) res.truncated = true;
  }
  const uniq = (a) => (a.length > 400 ? [...new Set(a)] : a);
  res.classes = uniq(res.classes); res.methods = uniq(res.methods);
  res.classCount = res.classes.length; res.methodCount = res.methods.length;
  return res;
}

export function summariseMachO(m) {
  if (!m.ok) return m;
  return m.slices.map((s) => s.ok ? `${s.arch} ${s.filetype}${s.encrypted ? ' (FairPlay-encrypted)' : ''}` : s.error).join(' + ');
}
