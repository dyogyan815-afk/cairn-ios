// Tests for the ALL-IN-ONE export (one special file per app that carries the
// whole scan). Runs the REAL pipeline on the same REAL synthetic IPA the
// toolchain tests use — no mocks anywhere in the path under test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAllInOneZip } from '../public/js/core/allinone.js';
import { runToolchain } from '../public/js/core/toolchain.js';
import { scanIPA } from '../public/js/core/ipa.js';
import { ZipWriter } from '../public/js/core/zip-writer.js';
import { openZip, entryBytes } from '../public/js/core/zip-reader.js';
import { buildMachO, buildCode } from './helpers/macho-fixture.mjs';

async function buildSyntheticIPA() {
  const enc = new TextEncoder();
  const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Demo</string>
<key>CFBundleDisplayName</key><string>Demo App</string>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>MinimumOSVersion</key><string>15.0</string>
<key>CFBundleExecutable</key><string>Demo</string>
<key>NSCameraUsageDescription</key><string></string>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>demoapp</string></array></dict></array>
</dict></plist>`;
  const podlock = ['PODS:', '  - Alamofire (5.8.1)', '  - SnapKit (5.7.1)', 'DEPENDENCIES:', '  - Alamofire'].join('\n');
  const macho = buildMachO({ codeBytes: buildCode(512), dylibs: ['/usr/lib/libSystem.B.dylib', '@rpath/ThirdParty.framework/ThirdParty'] });
  const w = new ZipWriter();
  w.addBytes('Payload/Demo.app/Info.plist', enc.encode(infoPlist));
  w.addBytes('Payload/Demo.app/Demo', macho);
  w.addBytes('Podfile.lock', enc.encode(podlock));
  const blob = w.finish();
  blob.name = 'synthetic.ipa';
  const model = await scanIPA(blob, { hash: false });
  return { blob, model, infoPlist };
}

const decoder = new TextDecoder();
const findBytes = async (z, blob, name) => {
  const e = z.entries.find((x) => x.name === name);
  if (!e) return null;
  return decoder.decode((await entryBytes(blob, e, 64 << 20)).bytes);
};

test('allinone: one zip carries info + every original file + xcode project + the 45-tool workspace', async () => {
  const { blob, model, infoPlist } = await buildSyntheticIPA();
  const tc = await runToolchain(blob, model, {});
  const r = await buildAllInOneZip(blob, model, { state: 'done', result: tc }, {});
  assert.equal(r.toolchainState, 'included');
  assert.ok(r.root === 'Demo_App_ALL-IN-ONE/', `root named after the app: ${r.root}`);
  const z = await openZip(r.blob, {});
  const names = z.entries.map((e) => e.name);
  const has = (n) => names.includes(r.root + n);
  // info section = the complete report + the real project checklist
  for (const must of ['README-FIRST.txt', 'info/REPORT.md', 'info/analysis.json', 'info/manifest.json', 'info/manifest.csv', 'info/SHA256SUMS.txt', 'info/PROJECT-CHECKLIST.txt']) {
    assert.ok(has(must), `contains ${must}`);
  }
  // files section = every original path, original structure
  for (const must of ['files/Payload/Demo.app/Info.plist', 'files/Payload/Demo.app/Demo', 'files/Podfile.lock']) {
    assert.ok(has(must), `contains ${must}`);
  }
  // xcode section = the reconstructed project for THIS app
  for (const must of ['xcode/Demo_App.xcodeproj/project.pbxproj', 'xcode/Supporting/Info.plist', 'xcode/Supporting/Info.plist.readable.xml', 'xcode/README_RECONSTRUCTION.md', 'xcode/project.manifest.json', 'xcode/Binaries/Demo']) {
    assert.ok(has(must), `contains ${must}`);
  }
  assert.ok(!names.some((n) => n.includes('TOOLCHAIN_WORKSPACE')), 'inner toolchain root folder is stripped, not nested');
  // checklist tells the truth about this fixture: Podfile.lock present, no .swift sources
  const ck = await findBytes(z, r.blob, r.root + 'info/PROJECT-CHECKLIST.txt');
  assert.match(ck, /Podfile \/ Podfile\.lock\s+1 found/, 'Podfile.lock really detected');
  assert.match(ck, /source files\s+0 found/, 'absent source honestly reported as 0');
  assert.match(ck, /Info\.plist\s+yes/, 'Info.plist present');
  // byte-for-byte: the merged Info.plist is identical to the IPA's original
  const merged = await findBytes(z, r.blob, r.root + 'files/Payload/Demo.app/Info.plist');
  assert.equal(merged, infoPlist, 'merged file bytes are identical to the original');
  // tool-status.csv carries one row per registered tool
  const csv = await findBytes(z, r.blob, r.root + 'toolchain/tool-status.csv');
  assert.ok(csv.trim().split('\n').length - 1 >= 45, 'one CSV row per registered tool');
  // count matches reality
  const fileCount = z.entries.filter((e) => !e.name.endsWith('/')).length;
  assert.equal(r.count, fileCount, `reported count matches the zip (${r.count} vs ${fileCount})`);
});

test('allinone: without the pipeline the toolchain section is an honest NOT-RUN, nothing faked', async () => {
  const { blob, model } = await buildSyntheticIPA();
  const r = await buildAllInOneZip(blob, model, null, {});
  assert.equal(r.toolchainState, 'not-run');
  const z = await openZip(r.blob, {});
  const names = z.entries.map((e) => e.name);
  assert.ok(names.includes(r.root + 'toolchain/NOT-RUN.txt'), 'NOT-RUN.txt present');
  assert.ok(!names.some((n) => n.startsWith(r.root + 'toolchain/toolchain.json')), 'no fabricated toolchain output');
  const note = await findBytes(z, r.blob, r.root + 'toolchain/NOT-RUN.txt');
  assert.match(note, /pipeline has not finished/, 'the note explains itself');
  const readme = await findBytes(z, r.blob, r.root + 'README-FIRST.txt');
  assert.match(readme, /NOT RUN YET/, 'README records the absence');
  assert.match(readme, /ئەم فایلە هەموو شتێکی ئەپەکە لەیەک فایلدا کۆدەکاتەوە/, 'README speaks Kurdish too');
  // info + files + xcode still fully present
  assert.ok(names.includes(r.root + 'info/manifest.json'), 'info section present');
  assert.ok(names.includes(r.root + 'files/Payload/Demo.app/Demo'), 'files section present');
  assert.ok(names.includes(r.root + 'xcode/Demo_App.xcodeproj/project.pbxproj'), 'xcode section present');
});

test('allinone: aborted build refuses honestly (aborted code)', async () => {
  const { blob, model } = await buildSyntheticIPA();
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(
    () => buildAllInOneZip(blob, model, null, { signal: ctl.signal }),
    (e) => e.code === 'aborted',
  );
});
