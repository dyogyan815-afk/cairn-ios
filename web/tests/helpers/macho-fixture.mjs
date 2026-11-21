// Builds a REAL, well-formed 64-bit ARM64 Mach-O for engine tests: load
// commands (LC_SEGMENT_64 with true __text/__cstring/__objc sections,
// LC_LOAD_DYLIB entries, LC_SYMTAB with named symbols) and genuine ARM64
// machine code in __text. Every byte is constructed; nothing is random.
const enc = new TextEncoder();

const ARM64 = {
  stpPrologue: [0xfd, 0x7b, 0xbf, 0xa9], // stp x29, x30, [sp, #-16]!
  movFpSp: [0xfd, 0x03, 0x00, 0x91], // mov x29, sp
  movzX0_32: [0x00, 0x04, 0x80, 0xd2], // mov x0, #0x20
  addX0X1X2: [0x20, 0x00, 0x21, 0x8b], // add x0, x1, x2
  ldpEpilogue: [0xfd, 0x7b, 0xc1, 0xa8], // ldp x29, x30, [sp], #16
  ret: [0xc0, 0x03, 0x5f, 0xd6], // ret
  nop: [0x1f, 0x20, 0x03, 0xd5], // nop
};

function lc(cmd, body) {
  const pad = (8 - (body.length % 8)) % 8; // Python-style positive modulo
  const full = new Uint8Array(8 + body.length + pad);
  const d = new DataView(full.buffer);
  d.setUint32(0, cmd, true);
  d.setUint32(4, full.length, true);
  full.set(body, 8);
  return full;
}

function sectionHeader(sect, seg, addr, size, offset, flags) {
  const b = new Uint8Array(80);
  b.set(enc.encode(sect).subarray(0, 16), 0);
  b.set(enc.encode(seg).subarray(0, 16), 16);
  const d = new DataView(b.buffer);
  d.setUint32(32, addr, true);
  d.setBigUint64(40, BigInt(size), true);
  d.setUint32(48, offset, true);
  d.setUint32(56, 2, true);
  d.setUint32(64, flags, true);
  return b;
}

function dylibCmdBytes(name) {
  const d = enc.encode(name + '\0');
  const b = new Uint8Array(24 + d.length);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 32, true); // name.offset is relative to the START of the load command (8 + 24)
  dv.setUint32(4, 2, true); // timestamp
  dv.setUint32(8, 0x10000, true); // current_version
  dv.setUint32(12, 0x10000, true); // compatibility_version
  dv.setUint32(16, 0, true); // reserved
  b.set(d, 24);
  return b;
}

export const DEFAULT_SYMBOLS = [
  { name: '_$s4main11ContentViewAACfc', value: 0x100000000 + 32, type: 0x0f, sect: 1 },
  { name: '_$s4main12usesNetwork33_ABCDEFG0123456789abcdefyyycfz_', value: 0x100000000 + 40, type: 0x0f, sect: 1 },
  { name: '_OBJC_CLASS_$_MyWorker', value: 0x100000000 + 48, type: 0x0f, sect: 1 },
  { name: '_main', value: 0x100000000 + 56, type: 0x0f, sect: 1 },
  { name: '_externalImport', value: 0, type: 0x01, sect: 0 },
];

/** Build the binary. opts: { codeBytes, cstrings: string[], dylibs: string[],
 * weakDylibs: string[], symbols: [{name, value, type, sect}] } */
export function buildMachO(opts = {}) {
  const code = opts.codeBytes || buildCode(128);
  const cstrings = enc.encode([].concat(opts.cstrings || ['hello world']).join('\0') + '\0');
  const objcMethods = enc.encode([].concat(opts.objcMethods || ['startEngine', 'stopEngine']).join('\0') + '\0');
  const symbols = opts.symbols !== undefined ? opts.symbols : DEFAULT_SYMBOLS;
  const dylibs = opts.dylibs || ['/usr/lib/libSystem.B.dylib'];
  const weakDylibs = opts.weakDylibs || [];

  const headerSize = 32;
  const textAddr = 0x100000000;

  const sects = [
    sectionHeader('__text', '__TEXT', 0, code.length, 0, 0x80000400),
    sectionHeader('__cstring', '__TEXT', 0, cstrings.length, 0, 0),
    sectionHeader('__objc_methname', '__TEXT', 0, objcMethods.length, 0, 0),
  ];
  // segment_64 layout: segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8)
  // maxprot(4) initprot(4) nsects(4) flags(4) → section headers start at 64.
  const SECT0 = 64;
  const segBody = new Uint8Array(SECT0 + sects.length * 80);
  segBody.set(enc.encode('__TEXT').subarray(0, 16), 0);
  const sd = new DataView(segBody.buffer);
  sd.setBigUint64(16, BigInt(textAddr), true);
  sd.setBigUint64(24, BigInt(0x4000), true);
  sd.setBigUint64(32, BigInt(0), true);
  sd.setBigUint64(40, BigInt(0x4000), true);
  sd.setUint32(48, 7, true);
  sd.setUint32(52, 5, true);
  sd.setUint32(56, sects.length, true);
  sects.forEach((s, i) => segBody.set(s, SECT0 + i * 80));

  const cmds = [];
  // Sizes are deterministic, so compute every offset BEFORE wrapping bodies
  // in lc() (lc copies bytes, later edits would be invisible).
  const segCmdLen = 8 + segBody.length + ((8 - (segBody.length % 8)) % 8);
  const dylibCmdLens = dylibs.map((n) => 8 + 24 + n.length + 1 + ((8 - ((24 + n.length + 1) % 8)) % 8));
  const weakCmdLens = weakDylibs.map((n) => 8 + 24 + n.length + 1 + ((8 - ((24 + n.length + 1) % 8)) % 8));
  const symCmdLen = 8 + 16;
  const symEntrySize = 16;
  const strTab = enc.encode('\0' + symbols.map((s) => s.name).join('\0') + '\0'); // offset 0 reserved (empty name)
  const sizeofcmds = segCmdLen + dylibCmdLens.reduce((a, b) => a + b, 0) + weakCmdLens.reduce((a, b) => a + b, 0) + symCmdLen;
  const headerPlusCmds = headerSize + sizeofcmds;

  const codeOff = headerPlusCmds;
  const cstrOff = codeOff + code.length;
  const objcOff = cstrOff + cstrings.length;
  const symOff = objcOff + objcMethods.length;
  const strOff = symOff + symbols.length * symEntrySize;
  const fileSize = strOff + strTab.length;

  // patch segment filesize + section offsets + addr while the body is still standalone
  sd.setBigUint64(40, BigInt(fileSize), true);
  const offFor = [codeOff, cstrOff, objcOff];
  const sizeFor = [code.length, cstrings.length, objcMethods.length];
  for (let i = 0; i < sects.length; i++) {
    const q = SECT0 + i * 80;
    sd.setUint32(q + 32, textAddr + offFor[i], true);
    sd.setBigUint64(q + 40, BigInt(sizeFor[i]), true);
    sd.setUint32(q + 48, offFor[i], true);
  }
  // patch symtab body
  const symtabBody = new Uint8Array(16);
  {
    const dv = new DataView(symtabBody.buffer);
    dv.setUint32(0, symOff, true);
    dv.setUint32(4, symbols.length, true);
    dv.setUint32(8, strOff, true);
    dv.setUint32(12, strTab.length, true);
  }

  cmds.push(lc(0x19, segBody));
  for (const name of dylibs) cmds.push(lc(0xc, dylibCmdBytes(name)));
  for (const name of weakDylibs) cmds.push(lc(0x80000018, dylibCmdBytes(name)));
  cmds.push(lc(0x2, symtabBody));
  const ncmds = cmds.length;
  if (cmds.reduce((s, c) => s + c.length, 0) !== sizeofcmds) throw new Error('fixture size bookkeeping mismatch');

  const hdr = new Uint8Array(headerSize);
  const hd = new DataView(hdr.buffer);
  hd.setUint32(0, 0xfeedfacf, true);
  hd.setUint32(4, 0x0100000c, true);
  hd.setUint32(8, 0, true);
  hd.setUint32(12, 2, true);
  hd.setUint32(16, ncmds, true);
  hd.setUint32(20, sizeofcmds, true);
  hd.setUint32(24, 0x00200085, true);

  const out = new Uint8Array(fileSize);
  out.set(hdr, 0);
  let p = headerSize;
  for (const c of cmds) { out.set(c, p); p += c.length; }
  out.set(code, codeOff);
  out.set(cstrings, cstrOff);
  out.set(objcMethods, objcOff);
  const symOffF = symOff;
  const strOffF = strOff;
  const symDv = new DataView(out.buffer, out.byteOffset);
  for (let i = 0; i < symbols.length; i++) {
    const s = symbols[i];
    const o = symOffF + i * symEntrySize;
    symDv.setUint32(o, strOffOf(strTab, i), true);
    out[o + 4] = s.type !== undefined ? s.type : 0x0f;
    out[o + 5] = s.sect !== undefined ? s.sect : 1;
    out[o + 6] = 0;
    symDv.setUint16(o + 6, 0, true);
    symDv.setBigUint64(o + 8, BigInt(s.value !== undefined ? s.value : textAddr + codeOffF), true);
  }
  out.set(strTab, strOffF);
  return out;
}

function strOffOf(strTab, i) {
  let off = 1; // offset 0 reserved for the empty name
  for (let k = 0; k < i; k++) {
    while (strTab[off] !== 0) off++;
    off++;
  }
  return off;
}

/** ~len bytes of valid ARM64 code: repeating prologue/mov/add/epilogue/ret/nops. */
export function buildCode(len = 512) {
  const seq = [...ARM64.stpPrologue, ...ARM64.movFpSp, ...ARM64.movzX0_32, ...ARM64.addX0X1X2, ...ARM64.ldpEpilogue, ...ARM64.ret, ...ARM64.nop, ...ARM64.nop];
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i += 4) out.set(seq.slice(0, 4), i);
  return out;
}
