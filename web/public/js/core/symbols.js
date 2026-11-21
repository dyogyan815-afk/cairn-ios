// Symbol table reader (nm engine): walks the LC_SYMTAB nlist entries of every
// Mach-O slice, classifies each symbol, and demangles Swift / C++ names.
// Read-only; symbols already ship inside the binary — nothing is recovered
// from beyond what the file itself contains.
import { cstr } from './util.js';
import { demangle } from './demangle.js';

export const SYM_LIMITS = { maxSymbols: 250000, maxNameLen: 300, maxStringsBytes: 16 << 20 };

const N_TYPE_MASK = 0x0e, N_EXT = 0x01, N_PEXT = 0x10;
const N_UNDF = 0x0, N_ABS = 0x2, N_SECT = 0xe, N_PBUD = 0xc, N_INDR = 0xa;

function classify(typeByte, sectionIndex, sections) {
  const ext = !!(typeByte & N_EXT);
  const priv = !!(typeByte & N_PEXT);
  const def = typeByte & N_TYPE_MASK;
  let kind = 'other';
  let sect = null;
  if (def === N_UNDF) kind = ext ? 'import (undefined, external)' : 'import';
  else if (def === N_ABS) kind = 'absolute';
  else if (def === N_SECT) {
    sect = sections[sectionIndex - 1] || null;
    kind = sect ? `defined (${sect.seg}.${sect.sect})` : 'defined';
  } else if (def === N_PBUD) kind = 'import (weak)';
  else if (def === N_INDR) kind = 'indirect';
  return { ext, priv, kind, sect };
}

/** Parse the complete symbol table of one parsed slice.
 * u8: the full binary bytes; slice: a slice object from parseMachO. */
export function readSymbols(u8, slice, { limit = SYM_LIMITS.maxSymbols, demangleNames = true } = {}) {
  const st = slice.symtab;
  if (!st) return { ok: false, error: 'No symbol table (stripped binary).', symbols: [], count: 0, truncated: false };
  if (slice.encrypted) return { ok: false, encrypted: true, error: 'FairPlay-encrypted binary: symbol names are not readable.', symbols: [], count: 0, truncated: false };
  const is64 = slice.is64;
  const step = is64 ? 16 : 12;
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  if (st.stroff + st.strsize > u8.length || st.symoff + st.nsyms * step > u8.length) {
    return { ok: false, error: 'Symbol table lies outside the readable bytes.', symbols: [], count: 0, truncated: false };
  }
  const sections = slice.sections || [];
  const symbols = [];
  let skipped = 0;
  for (let i = 0; i < st.nsyms; i++) {
    if (symbols.length >= limit) { skipped = st.nsyms - limit; break; }
    const o = st.symoff + i * step;
    const strx = dv.getUint32(o, true);
    const type = u8[o + 4], sectIdx = u8[o + 5];
    const value = is64 ? Number(dv.getBigUint64(o + 8, true)) : dv.getUint32(o + 8, true);
    if (type & 0xe0) { skipped++; continue; } // stab/debug entries
    let name = '';
    if (strx && strx < st.strsize) {
      name = cstr(u8, st.stroff + strx, SYM_LIMITS.maxNameLen);
    }
    const c = classify(type, sectIdx, sections);
    let dem = null;
    if (demangleNames && name) dem = demangle(name);
    symbols.push({
      name,
      value,
      kind: c.kind,
      section: c.sect ? `${c.sect.seg}.${c.sect.sect}` : null,
      external: c.ext,
      demangled: dem ? dem.demangled : null,
      family: dem ? dem.family : null,
    });
  }
  // tally by kind
  const byKind = {};
  for (const s of symbols) byKind[s.kind] = (byKind[s.kind] || 0) + 1;
  const byFamily = { swift: 0, cxx: 0, objc: 0, other: 0 };
  for (const s of symbols) {
    if (s.family === 'swift-s' || s.family === 'swift-tt') byFamily.swift++;
    else if (s.family === 'cxx') byFamily.cxx++;
    else if (/^_\$s|_Tt|OBJC_CLASS|OBJC_METACLASS|OBJC_IVAR/.test(s.name)) byFamily.objc++;
    else byFamily.other++;
  }
  return {
    ok: true, symbols, count: symbols.length,
    totalInTable: st.nsyms, skipped, truncated: skipped > 0 || symbols.length >= limit,
    byKind, byFamily,
  };
}
