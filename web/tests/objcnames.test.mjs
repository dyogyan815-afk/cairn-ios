// Tests for the ObjC name-table extractor (macho.js objcNames).
// Builds synthetic Mach-O binaries; no external fixtures needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseMachO, objcNames } from '../public/js/core/macho.js';

const u32 = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return b; };
const u64 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); return b; };
const nul16 = (s) => { const b = new Uint8Array(16); for (let i = 0; i < Math.min(16, s.length); i++) b[i] = s.charCodeAt(i); return b; };
const strz = (s) => { const a = [...s].map((c) => c.charCodeAt(0)); a.push(0); return new Uint8Array(a); };
const cat = (...arrs) => { const t = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0)); let o = 0; for (const a of arrs) { t.set(a, o); o += a.length; } return t; };

/** Thin 64-bit Mach-O: one LC_SEGMENT_64 (__TEXT) + optional LC_ENCRYPTION_INFO_64, then data. */
function buildMacho({ classes = [], methods = [], strings = [], cryptid = 0 }) {
  const clsData = classes.length ? cat(...classes.map(strz)) : new Uint8Array(0);
  const mthData = methods.length ? cat(...methods.map(strz)) : new Uint8Array(0);
  const strData = strings.length ? cat(...strings.map(strz)) : new Uint8Array(0);
  const ncmds = cryptid ? 2 : 1;
  const segCmdSize = 72 + 3 * 80;
  const encSize = 24;
  const sizeofcmds = segCmdSize + (cryptid ? encSize : 0);
  const header = cat(u32(0xfeedfacf), u32(0x0100000c), u32(0), u32(2), u32(ncmds), u32(sizeofcmds), u32(0), u32(0));
  const dataStart = 32 + sizeofcmds;
  const clsOff = dataStart, mthOff = clsOff + clsData.length, strOff = mthOff + mthData.length;
  const seg = cat(u32(0x19), u32(segCmdSize), nul16('__TEXT'), u64(0), u64(0x1000), u64(0), u64(dataStart + clsData.length + mthData.length + strData.length), u32(7), u32(5), u32(3), u32(0));
  const sh1 = cat(nul16('__objc_classname'), nul16('__TEXT'), u64(clsOff), u64(clsData.length), u32(clsOff), u32(3), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0));
  const sh2 = cat(nul16('__objc_methname'), nul16('__TEXT'), u64(mthOff), u64(mthData.length), u32(mthOff), u32(3), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0));
  const sh3 = cat(nul16('__cstring'), nul16('__TEXT'), u64(strOff), u64(strData.length), u32(strOff), u32(3), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0));
  const enc = cryptid ? cat(u32(0x2c), u32(encSize), u32(dataStart), u32(4096), u32(cryptid)) : new Uint8Array(0);
  return cat(header, seg, sh1, sh2, sh3, enc, clsData, mthData, strData);
}

test('sections are parsed from LC_SEGMENT_64', () => {
  const m = parseMachO(buildMacho({ classes: ['A'], strings: ['x'] }));
  assert.equal(m.ok, true);
  const s = m.slices[0];
  assert.equal(s.sections.length, 3);
  assert.deepEqual(s.sections.map((x) => x.sect), ['__objc_classname', '__objc_methname', '__cstring']);
});

test('objcNames extracts classes, methods and strings', () => {
  const bytes = buildMacho({
    classes: ['AppDelegate', 'MyViewController'],
    methods: ['viewDidLoad', 'applicationDidFinishLaunching:'],
    strings: ['https://example.com', 'kNotificationName'],
  });
  const m = parseMachO(bytes);
  const r = objcNames(bytes, m.slices[0]);
  assert.equal(r.ok, true);
  assert.deepEqual(r.classes, ['AppDelegate', 'MyViewController']);
  assert.deepEqual(r.methods, ['viewDidLoad', 'applicationDidFinishLaunching:']);
  assert.deepEqual(r.strings, ['https://example.com', 'kNotificationName']);
  assert.equal(r.classCount, 2); assert.equal(r.methodCount, 2);
});

test('objcNames refuses encrypted executables', () => {
  const bytes = buildMacho({ classes: ['Secret'], cryptid: 1 });
  const m = parseMachO(bytes);
  assert.equal(m.slices[0].encrypted, true);
  const r = objcNames(bytes, m.slices[0]);
  assert.equal(r.ok, false);
  assert.equal(r.encrypted, true);
});

test('objcNames handles binaries without ObjC sections', () => {
  const bytes = buildMacho({ strings: ['plain'] });
  const m = parseMachO(bytes);
  const r = objcNames(bytes, m.slices[0]);
  assert.equal(r.ok, true);
  assert.equal(r.classCount, 0); assert.equal(r.methodCount, 0);
  assert.deepEqual(r.strings, ['plain']);
});
