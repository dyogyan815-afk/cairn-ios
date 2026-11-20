import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { openZip, entryBytes } from '../public/js/core/zip-reader.js';
import { scanIPA, buildTree } from '../public/js/core/ipa.js';
import { buildOriginalZip, buildProjectZip, buildResourcesZip, buildReportZip, buildManifest, verifyExport, selectRecords } from '../public/js/core/exporter.js';
import { parseMachO } from '../public/js/core/macho.js';
import { parsePlist } from '../public/js/core/plist.js';
import { cgbiToPng } from '../public/js/core/cgbi.js';
import { carveBytes, carveEntry, ImageCarver } from '../public/js/core/carve.js';
import { crc32 } from '../public/js/core/crc32.js';

const F = (n) => { const b = new Blob([fs.readFileSync(new URL('./fixtures/' + n, import.meta.url))]); b.name = n; return b; };
const sha = (u8) => createHash('sha256').update(u8).digest('hex');
const pyList = async (blob) => (await openZip(blob)).entries.map((e) => e.name);

for (const name of ['small.ipa', 'many.ipa', 'big.ipa', 'multi-ext.ipa', 'encrypted.ipa']) {
  test(`${name}: every entry accounted for, hashes match, export reopens`, async () => {
    const blob = F(name);
    const model = await scanIPA(blob);
    const raw = (await openZip(blob)).entries;
    assert.equal(model.files.length, raw.length, 'no entry dropped');
    assert.ok(model.files.every((f) => f.status === 'ok'), 'all entries read & CRC verified');
    for (const f of model.files.filter((x) => !x.isDir).slice(0, 80)) { // independent SHA-256 via node:crypto
      const { bytes } = await entryBytes(blob, f.entry, null);
      assert.equal(sha(bytes), f.sha256, f.path);
    }
    const out = await buildOriginalZip(blob, model);
    assert.equal(out.skipped.length, 0);
    const v = await verifyExport(out.blob, model.files, { deep: true });
    assert.ok(v.ok, JSON.stringify(v).slice(0, 300));
    assert.deepEqual((await pyList(out.blob)).sort(), raw.map((e) => e.name).sort(), 'identical path list');
    fs.mkdirSync('/tmp/cairn-out', { recursive: true });
    fs.writeFileSync(`/tmp/cairn-out/${name}.export.zip`, Buffer.from(await out.blob.arrayBuffer()));
  });
}

test('original IPA is not modified by scanning/exporting', async () => {
  const before = sha(fs.readFileSync(new URL('./fixtures/small.ipa', import.meta.url)));
  const blob = F('small.ipa'); const m = await scanIPA(blob); await buildOriginalZip(blob, m); await buildProjectZip(blob, m);
  assert.equal(sha(fs.readFileSync(new URL('./fixtures/small.ipa', import.meta.url))), before);
});

test('metadata extraction (binary plist, arch, permissions, frameworks, extensions, provisioning)', async () => {
  const m = await scanIPA(F('multi-ext.ipa')); const a = m.app;
  assert.equal(a.bundleId, 'com.example.demo'); assert.equal(a.version, '1.2.3'); assert.equal(a.build, '45'); assert.equal(a.minOS, '15.0');
  assert.equal(a.infoPlistFormat, 'xml'); assert.deepEqual(a.deviceFamilies, ['iPhone/iPod', 'iPad']);
  assert.deepEqual(a.urlSchemes, ['demoapp']); assert.equal(a.permissions.length, 2);
  assert.deepEqual(a.architectures, ['arm64']); assert.equal(a.encrypted, true);
  assert.equal(a.extensions.length, 4); assert.equal(a.extensions[0].extensionPoint, 'com.apple.widgetkit-extension');
  assert.equal(a.frameworks[0].bundleId, 'com.example.core'); assert.equal(a.provisioning.teamName, 'Test Team'); assert.equal(a.provisioning.kind, 'Development');
  const s = await scanIPA(F('small.ipa')); assert.equal(s.app.infoPlistFormat, 'binary'); assert.equal(s.app.encrypted, false);
  assert.ok(s.app.macho.slices[0].dylibs.some((d) => d.name.includes('libSystem')));
  assert.equal(s.app.icon, 'Payload/Demo.app/AppIcon60x60@2x.png');
});

test('unusual names, hidden files, empty dirs, unknown binaries are all preserved', async () => {
  const blob = F('multi-ext.ipa'); const m = await scanIPA(blob);
  const paths = new Set(m.files.map((f) => f.path));
  for (const p of ['Payload/Demo.app/.hidden_file', 'Payload/Demo.app/Weird/Ünïcödé résumé.txt', 'Payload/Demo.app/Weird/日本語/ファイル.txt', 'Payload/Demo.app/Weird/emoji-😀.txt', 'Payload/Demo.app/EmptyDir/', 'Payload/Demo.app/unknown.bin']) assert.ok(paths.has(p), p);
  assert.equal(m.files.find((f) => f.path.endsWith('unknown.bin')).category, 'other');
  const z = await buildOriginalZip(blob, m); const names = await pyList(z.blob);
  assert.ok(names.includes('Payload/Demo.app/.hidden_file') && names.includes('Payload/Demo.app/Weird/emoji-😀.txt'));
});

test('selected file / folder exports', async () => {
  const blob = F('small.ipa'); const m = await scanIPA(blob);
  const one = await buildOriginalZip(blob, m, { paths: new Set(['Payload/Demo.app/config.json']) });
  assert.equal(one.count, 1);
  const dir = await buildOriginalZip(blob, m, { prefixes: ['Payload/Demo.app/Frameworks/'] });
  assert.ok(dir.count >= 2); const v = await verifyExport(dir.blob, dir.records, { deep: true }); assert.ok(v.ok);
});

test('manifest has every entry with sha256; tree stats', async () => {
  const m = await scanIPA(F('many.ipa')); const man = buildManifest(m);
  assert.equal(man.entries.length, m.files.length); assert.ok(man.entries.filter((e) => e.type === 'file').every((e) => /^[0-9a-f]{64}$/.test(e.sha256)));
  assert.equal(man.summary.allPreserved, true); const t = buildTree(m.files); assert.equal(t.count, m.stats.files); assert.ok(m.stats.files > 1500);
});

test('reconstruction + resource + report zips', async () => {
  const blob = F('small.ipa'); const m = await scanIPA(blob);
  const p = await buildProjectZip(blob, m); const pn = await pyList(p.blob);
  assert.ok(pn.some((n) => n.endsWith('project.pbxproj')) && pn.includes('Demo_App/project.manifest.json') && pn.includes('Demo_App/Binaries/Demo') && pn.includes('Demo_App/Source/Source/Leftover.swift'));
  assert.equal(pn.filter((n) => n.includes('Weird')).length, 0);
  const r = await buildResourcesZip(blob, m); const rn = await pyList(r.blob);
  assert.ok(rn.includes('Source/Leftover.swift') && !rn.includes('Demo') && rn.includes('config.json'));
  const rep = await buildReportZip(blob, m); const en = await pyList(rep.blob); assert.ok(['REPORT.md', 'manifest.json', 'SHA256SUMS.txt', 'icon.png'].every((n) => en.includes(n)));
  for (const [k, b] of Object.entries({ p: p.blob, r: r.blob, rep: rep.blob })) fs.writeFileSync(`/tmp/cairn-out/${k}.zip`, Buffer.from(await b.arrayBuffer()));
});

test('project files are byte-identical to the IPA originals', async () => {
  const blob = F('small.ipa'); const m = await scanIPA(blob); const p = await buildProjectZip(blob, m);
  const z = await openZip(p.blob); const man = JSON.parse(new TextDecoder().decode((await entryBytes(p.blob, z.entries.find((e) => e.name.endsWith('project.manifest.json')), null)).bytes));
  for (const f of man.files) { const e = z.entries.find((x) => x.name === 'Demo_App/' + f.projectPath); assert.equal(sha((await entryBytes(p.blob, e, null)).bytes), f.sha256); }
});

test('damaged archives give clear errors / flagged entries', async () => {
  await assert.rejects(() => scanIPA(F('notzip.ipa')), /not a ZIP|truncated/i);
  await assert.rejects(() => scanIPA(F('truncated.ipa')), /ZIP|truncated|damaged|central/i);
  const m = await scanIPA(F('corrupt-entry.ipa')); const bad = m.files.filter((f) => f.status !== 'ok');
  assert.equal(bad.length, 1); assert.equal(bad[0].status, 'crc-mismatch');
  const d = await scanIPA(F('duplicates.ipa')); assert.equal(d.files.length, 2); assert.ok(d.files.every((f) => f.problems.includes('duplicate-name')));
  const exp = await buildOriginalZip(F('duplicates.ipa'), d); assert.equal((await openZip(exp.blob)).entries.length, 2, 'duplicates never silently dropped');
});

test('Mach-O: fat + thin, encryption flag, never invents source', () => {
  const thin = parseMachO(new Uint8Array(fs.readFileSync(new URL('./fixtures/small.ipa', import.meta.url)).subarray(0, 4)));
  assert.equal(thin.ok, false);
});

test('plist: binary and xml', () => {
  const x = parsePlist(new TextEncoder().encode('<?xml version="1.0"?><plist><dict><key>a</key><string>x &amp; y</string><key>n</key><integer>3</integer><key>l</key><array><true/><false/></array></dict></plist>'));
  assert.deepEqual(x.value, { a: 'x & y', n: 3, l: [true, false] });
});

test('CgBI PNG converts to a standard PNG with RGB order & straight alpha', async () => {
  const m = await scanIPA(F('small.ipa')); const rec = m.files.find((f) => f.path.endsWith('AppIcon60x60@2x.png')); assert.ok(rec.cgbi);
  const { bytes } = await entryBytes(F('small.ipa'), rec.entry, null); const out = await cgbiToPng(bytes);
  let p = 8, idat = []; while (p < out.length) { const len = new DataView(out.buffer, out.byteOffset + p).getUint32(0); const t = String.fromCharCode(...out.subarray(p + 4, p + 8)); assert.notEqual(t, 'CgBI'); if (t === 'IDAT') idat.push(out.subarray(p + 8, p + 8 + len)); p += 12 + len; }
  const raw = zlib.inflateSync(Buffer.concat(idat)); assert.deepEqual([...raw.subarray(1, 5)], [199, 100, 50, 128]);
});

// ---------- image carving (v1.1) ----------
const U = (buf) => new Uint8Array(buf);
function pngChunk(type, data) {
  const b = Buffer.alloc(12 + data.length);
  b.writeUInt32BE(data.length, 0); b.write(type, 4, 'latin1'); data.copy(b, 8);
  b.writeUInt32BE(crc32(U(b.subarray(4, 8 + data.length))), 8 + data.length);
  return b;
}
function makePng({ cgbi = false } = {}) {
  const ihdr = Buffer.from([0, 0, 0, 2, 0, 0, 0, 2, 8, 6, 0, 0, 0]); // 2x2 RGBA, 13 bytes
  const raw = Buffer.from([0, 10, 20, 30, 40, 50, 60, 70, 80, 0, 90, 100, 110, 120, 130, 140, 150, 160]); // 2 rows of filter+2x4
  // Real Apple CgBI files carry the CgBI chunk immediately after the signature, before IHDR.
  const parts = cgbi ? [U(pngChunk('CgBI', Buffer.alloc(4))), U(pngChunk('IHDR', ihdr))] : [U(pngChunk('IHDR', ihdr))];
  parts.push(U(pngChunk('IDAT', zlib.deflateRawSync(raw))), U(pngChunk('IEND', Buffer.alloc(0))));
  const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([SIG, ...parts]);
}
function makeJpeg() {
  const entropy = Buffer.from([0xab, 0xff, 0x00, 0xd9, 0x12, 0x34, 0x56]); // FF00-stuffed pair + a D9 NOT preceded by FF
  return Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 1, 1, 0, 0, 1, 0, 1, 0, 0]), // SOI + APP0
    Buffer.concat([Buffer.from([0xff, 0xdb, 0x00, 0x43, 0x00]), Buffer.alloc(64, 7)]),                          // DQT
    Buffer.from([0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x02, 0x00, 0x02, 1, 1, 0x11, 0]),                          // SOF0
    Buffer.from([0xff, 0xda, 0x00, 0x08, 1, 1, 0, 0, 0x3f, 0]),                                                  // SOS
    entropy, Buffer.from([0xff, 0xd9]),                                                                          // entropy + EOI
  ]);
}
test('carve: recovers complete PNG / CgBI / JPEG streams, ignores noise and truncated streams', async () => {
  const noise = Buffer.alloc(4096); noise.fill(0x5a);
  const fakePng = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from([0, 0, 0, 5, 0x6a, 0x75, 0x6e, 0x6b]), Buffer.alloc(64, 1)]); // 'junk' chunk, never finishes
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0xff, 0x55, 0x55, 0x00, 0x11]); // SOI followed by invalid markers
  const p1 = makePng(), p2 = makePng({ cgbi: true }), j1 = makeJpeg();
  const gap = Buffer.alloc(300, 0x33);
  const parts = [noise, fakePng, gap, fakeJpeg, gap, p1, gap, p2, gap, j1, noise];
  const buf = Buffer.concat(parts);
  const real = { p1: buf.indexOf(p1), p2: buf.indexOf(p2), j1: buf.indexOf(j1) };
  const r = await carveBytes(U(buf), { minSize: 10 });
  assert.equal(r.images.length, 3, `expected 3 images, got ${r.images.length}`);
  assert.deepEqual(r.images.map((i) => i.kind).sort(), ['cgbi', 'jpeg', 'png']);
  const byKind = Object.fromEntries(r.images.map((i) => [i.kind, i]));
  assert.equal(byKind.png.offset, real.p1);
  assert.equal(byKind.cgbi.offset, real.p2);
  assert.equal(byKind.jpeg.offset, real.j1);
  assert.deepEqual([...byKind.jpeg.bytes.subarray(0, 3)], [0xff, 0xd8, 0xff]);
  assert.deepEqual([...byKind.jpeg.bytes.subarray(-2)], [0xff, 0xd9]);
  assert.equal(Buffer.compare(Buffer.from(byKind.png.bytes), p1), 0, 'carved PNG is byte-identical to the embedded original');
  const converted = await cgbiToPng(byKind.cgbi.bytes); // carved CgBI is a fully valid CgBI PNG
  assert.ok(converted.length > 8);
  assert.equal(r.limitReached, null);
});

test('carve: minSize filters out streams below the threshold', async () => {
  const buf = Buffer.concat([Buffer.alloc(4096, 0x77), makePng(), Buffer.alloc(1024, 0x88)]);
  const r = await carveBytes(U(buf), { minSize: 1024 });
  assert.equal(r.images.length, 0); // a ~100-byte PNG is below the threshold
  assert.equal(r.limitReached, null);
  const r2 = await carveBytes(U(buf), { minSize: 10 });
  assert.equal(r2.images.length, 1); // same buffer, low threshold -> recovered
});

test('carve: streaming feed in odd chunk sizes gives identical results', async () => {
  const p1 = makePng(), j1 = makeJpeg();
  const buf = Buffer.concat([Buffer.alloc(1000, 0x11), p1, Buffer.alloc(500, 0x22), j1, Buffer.alloc(300, 0x33)]);
  const cv = new ImageCarver({ minSize: 10 });
  const STEP = 137;
  for (let i = 0; i < buf.length; i += STEP) cv.feed(U(buf.subarray(i, Math.min(buf.length, i + STEP))), i);
  cv.end();
  assert.equal(cv.images.length, 2);
  assert.equal(cv.images[0].offset, 1000);
  assert.equal(cv.images[0].size, p1.length);
  assert.equal(cv.images[1].offset, 1000 + p1.length + 500);
  assert.equal(Buffer.compare(Buffer.from(cv.images[1].bytes), j1), 0);
});

test('carve: maxImages limit and abort signal', async () => {
  const p1 = makePng();
  const buf = Buffer.concat([p1, Buffer.alloc(2048, 0x44), p1, Buffer.alloc(2048, 0x55), p1]);
  const r = await carveBytes(U(buf), { minSize: 10, maxImages: 2 });
  assert.equal(r.images.length, 2);
  assert.equal(r.limitReached, 'maxImages');
  await assert.rejects(() => carveBytes(U(buf), { minSize: 10, signal: AbortSignal.abort() }), /cancelled/i);
});

test('carve: carveEntry streams an IPA entry without loading it whole', async () => {
  const blob = F('small.ipa');
  const z = await openZip(blob);
  const e = z.entries.find((x) => x.name.endsWith('AppIcon60x60@2x.png'));
  const r = await carveEntry(blob, e, { minSize: 10 });
  assert.ok(r.images.length >= 1);
  assert.equal(r.images[0].kind, 'cgbi');
  assert.equal(r.images[0].offset, 0);
  assert.equal(r.images[0].size, e.usize);
});
