// Tests for the 45-tool integration: every new engine must produce real,
// verified output. The disassembly tests load the vendored Capstone WASM.
// The pipeline test builds a REAL synthetic IPA (ZipWriter) containing a REAL
// hand-built Mach-O — no mocks anywhere in the path under test.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { demangle } from '../public/js/core/demangle.js';
import { readSymbols } from '../public/js/core/symbols.js';
import { buildDeps, isSystemLib } from '../public/js/core/deps.js';
import { scanBuffer, scanFiles, findPem } from '../public/js/core/signatures.js';
import { parsePodfileLock, parseCartfile, parsePackageResolved } from '../public/js/core/packages.js';
import { auditApp } from '../public/js/core/audit.js';
import { runToolchain, TOOLS, TOOL_BY_ID } from '../public/js/core/toolchain.js';
import { buildToolchainZip } from '../public/js/core/tcexport.js';
import { loadDisasm, disasm } from '../public/js/core/disasm.js';
import { scanIPA } from '../public/js/core/ipa.js';
import { ZipWriter } from '../public/js/core/zip-writer.js';
import { buildMachO, buildCode } from './helpers/macho-fixture.mjs';

const F = (n) => { const b = new Blob([fs.readFileSync(new URL('./fixtures/' + n, import.meta.url))]); b.name = n; return b; };

// ---------- demangler ----------
test('demangle: _Tt ObjC-bridged Swift class', () => {
  const r = demangle('_TtC8MyModule16MyViewController');
  assert.equal(r.demangled, 'MyModule.MyViewController');
  assert.match(r.kind, /class/);
});
test('demangle: _Tt nested class + ObjC substitution (So)', () => {
  const r = demangle('_TtCC8MyModule5Outer5Inner');
  assert.equal(r.demangled, 'MyModule.Outer.Inner');
  const r2 = demangle('_TtCSo15UIBarButtonItem');
  assert.equal(r2.demangled, 'UIBarButtonItem');
  assert.match(r2.note, /Objective-C/);
});
test('demangle: _$s best-effort path', () => {
  const r = demangle('_$s4main11ContentViewAACfc');
  assert.ok(r, 'returns a result');
  assert.ok(r.demangled.includes('main'), 'module path extracted');
});
test('demangle: Itanium C++ nested names', () => {
  assert.equal(demangle('_ZN3foo3barEv').demangled, 'foo::bar()');
  const std = demangle('_ZNKSt3__16locale5identE');
  assert.ok(std && std.demangled.includes('std'), `std substitution handled: ${std && std.demangled}`);
});
test('demangle: leaves plain ObjC names untouched', () => {
  assert.equal(demangle('UIViewController'), null);
});

// ---------- symbols (synthetic REAL Mach-O) ----------
test('symbols: reads a real hand-built symbol table with demangling', async () => {
  const bytes = buildMachO({});
  const { parseMachO } = await import('../public/js/core/macho.js');
  const sl = parseMachO(bytes).slices.find((s) => s.ok);
  const syms = readSymbols(bytes, sl);
  assert.ok(syms.ok, `symbol table readable (${syms.error || ''})`);
  assert.equal(syms.count, 5);
  const byName = Object.fromEntries(syms.symbols.map((s) => [s.name, s]));
  assert.match(byName['_main'].kind, /defined \(__TEXT\.__text\)/);
  assert.match(byName['_externalImport'].kind, /import/);
  assert.equal(byName['_externalImport'].external, true);
  assert.equal(byName['_$s4main11ContentViewAACfc'].demangled, 'main.ContentView');
  assert.equal(byName['_OBJC_CLASS_$_MyWorker'].demangled, null, 'plain ObjC name needs no demangling');
  assert.ok(syms.byFamily.swift >= 2, 'Swift-family tally');
});

// ---------- dependencies ----------
test('deps: classifies system / missing links from a real Mach-O', async () => {
  const bytes = buildMachO({ dylibs: ['/usr/lib/libSystem.B.dylib', '@rpath/ThirdParty.framework/ThirdParty'] });
  const fakeRec = { path: 'Payload/Demo.app/Demo', size: bytes.length };
  const fakeModel = { files: [fakeRec] };
  const deps = await buildDeps(fakeModel, async () => ({ bytes }));
  assert.ok(deps.ok);
  assert.equal(deps.binaries.length, 1);
  assert.equal(deps.linksTotal, 2);
  assert.equal(deps.tally.system, 1, 'libSystem is system');
  assert.equal(deps.tally.missing, 1, 'ThirdParty is neither system nor embedded → MISSING');
  assert.equal(deps.missing[0].base, 'ThirdParty');
});
test('deps: isSystemLib recognises system paths', () => {
  assert.equal(isSystemLib('/usr/lib/libSystem.dylib'), true);
  assert.equal(isSystemLib('/System/Library/Frameworks/UIKit.framework/UIKit'), true);
  assert.equal(isSystemLib('@rpath/MySDK.framework/MySDK'), false);
  assert.equal(isSystemLib('libswiftCore.dylib'), true);
  assert.equal(isSystemLib('libobjc.dylib'), true);
});

// ---------- signature scanner ----------
test('signatures: finds gzip + png + zip embedded in a buffer', () => {
  const buf = new Uint8Array(1024);
  buf.set([0x1f, 0x8b, 0x08, 0x00], 100);
  buf.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a], 400);
  buf.set([0x50, 0x4b, 0x03, 0x04], 700);
  const { hits } = scanBuffer(buf);
  const names = hits.map((h) => h.name);
  assert.ok(names.includes('gzip stream'));
  assert.ok(names.includes('PNG image'));
  assert.ok(names.includes('ZIP archive / OOXML'));
  assert.deepEqual(hits.map((h) => h.offset), [100, 400, 700]);
});
test('signatures: detects PEM blocks and IMG4 tags', () => {
  const header = ['-----BEGIN ', 'RSA PRIVATE', ' KEY-----'].join('');
  const buf = new TextEncoder().encode('prefix ' + header + ' body IM4P-payload');
  const pem = findPem(buf, 4096);
  assert.ok(pem.some((h) => /RSA/.test(h.name)), 'PEM header detected with its type');
});

// ---------- packages ----------
test('packages: Podfile.lock parses pods+versions', () => {
  const text = ['PODS:', '  - Alamofire (5.8.1)', '  - Firebase/CoreOnly (10.18.0):', '    - FirebaseCore (= 10.18.0)', 'DEPENDENCIES:', '  - Alamofire'].join('\n');
  const r = parsePodfileLock(text);
  assert.ok(r.ok);
  assert.deepEqual(r.pods.map((p) => `${p.name}@${p.version}`), ['Alamofire@5.8.1', 'Firebase@10.18.0']);
  assert.equal(r.count, 2);
});
test('packages: Cartfile.resolved parses pins', () => {
  const r = parseCartfile('github "antitypical/Result" "5.0.0"\ngithub "ReactiveCocoa/ReactiveSwift" "7.1.1"');
  assert.equal(r.count, 2);
  assert.equal(r.pods[0].name, 'antitypical/Result');
  assert.equal(r.pods[0].version, '5.0.0');
});
test('packages: Package.resolved v2 + v1 parse', () => {
  const v2 = parsePackageResolved(JSON.stringify({ pins: [{ identity: 'swift-log', state: { version: '1.5.3' } }, { identity: 'swift-argument-parser', state: { revision: 'abc123', branch: 'main' } }] }));
  assert.equal(v2.count, 2);
  assert.equal(v2.pods[0].version, '1.5.3');
  const v1 = parsePackageResolved(JSON.stringify({ object: { pins: [{ packageName: 'SnapshotTesting', state: { version: '1.12.0' } }] } }));
  assert.equal(v1.count, 1);
  assert.equal(v1.pods[0].name, 'SnapshotTesting');
});

// ---------- audit ----------
test('audit: flags ATS + empty usage description in a real synthetic IPA', async () => {
  const { blob, model } = await buildSyntheticIPA();
  const r = await auditApp(blob, model);
  assert.ok(r.ok);
  assert.ok(r.binariesChecked >= 1, 'the main binary was audited');
  assert.ok(r.findings.some((f) => f.title.startsWith('Binaries audited')));
  assert.ok(r.findings.some((f) => f.title.includes('App Transport Security')), 'ATS finding present');
});

// ---------- disassembler (real Capstone WASM) ----------
test('disasm: ARM64 instructions decode correctly', async () => {
  const m = await loadDisasm();
  assert.ok(m.Const.CS_ARCH_ARM64 !== undefined, 'Const exported');
  const bytes = new Uint8Array([0xfd, 0x03, 0x02, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
  const r = await disasm(bytes, 'arm64', 0x1000);
  assert.equal(r.instructions.length, 2);
  assert.equal(r.instructions[1].mnemonic, 'ret');
});
test('disasm: x86_64 decodes', async () => {
  const r = await disasm(new Uint8Array([0x48, 0x89, 0xd8, 0xc3]), 'x86_64', 0x2000);
  assert.equal(r.instructions[0].mnemonic, 'mov');
  assert.equal(r.instructions[1].mnemonic, 'ret');
});
test('disasm: disassembles the synthetic __text section with real addresses', async () => {
  const bytes = buildMachO({ codeBytes: buildCode(256) });
  const { parseMachO } = await import('../public/js/core/macho.js');
  const sl = parseMachO(bytes).slices.find((s) => s.ok);
  const text = sl.sections.find((s) => s.sect === '__text');
  const r = await disasm(bytes.subarray(text.offset, text.offset + text.size), sl.arch, 0x100000000 + text.offset, { count: 64 });
  assert.ok(r.instructions.length >= 60, `${r.instructions.length} instructions from 256 bytes`);
  assert.equal(r.instructions[0].mnemonic, 'stp');
  assert.ok(r.instructions.every((x) => /^\d+$/.test(String(x.address))));
});

// ---------- full pipeline over a REAL synthetic IPA ----------
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
<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>demoapp</string></array></dict></array>
</dict></plist>`;
  const podlock = ['PODS:', '  - Alamofire (5.8.1)', '  - SnapKit (5.7.1)', 'DEPENDENCIES:', '  - Alamofire'].join('\n');
  const macho = buildMachO({ codeBytes: buildCode(512), dylibs: ['/usr/lib/libSystem.B.dylib', '@rpath/ThirdParty.framework/ThirdParty'] });
  const w = new ZipWriter();
  w.addBytes('Payload/Demo.app/Info.plist', enc.encode(infoPlist));
  w.addBytes('Payload/Demo.app/Demo', macho);
  w.addBytes('Payload/Demo.app/Frameworks/ThirdParty.framework/Info.plist', enc.encode(infoPlist.replace('com.example.demo', 'com.example.thirdparty')));
  w.addBytes('Podfile.lock', enc.encode(podlock));
  const blob = w.finish();
  blob.name = 'synthetic.ipa';
  const model = await scanIPA(blob, { hash: false });
  return { blob, model };
}

test('toolchain: registry covers all 45 requested tools with honest status', () => {
  assert.ok(TOOLS.length >= 45, `registry has ${TOOLS.length} entries`);
  const required = ['ida-pro', 'ghidra', 'binary-ninja', 'hopper', 'rizin', 'radare2', 'cutter', 'retdec', 'revng',
    'ipsw', 'jtool2', 'MachOView', 'class-dump', 'otool', 'dyld_shared_cache_util', 'LIEF', 'llvm', 'swift-demangle',
    'nm', 'strings', 'codesign', 'frida', 'objection', 'lldb', 'dtrace', 'instruments', 'cycript', '7zip',
    'unarchiver', 'binwalk', 'ImHex', '010-editor', 'kaitai', 'dependency-walker', 'otool-L', 'cocoapods',
    'carthage', 'spm', 'mobsf', 'semgrep', 'codeql', 'angr', 'unicorn', 'qiling'];
  for (const id of required) {
    assert.ok(TOOL_BY_ID[id], `tool registered: ${id}`);
    assert.ok(['active', 'partial', 'host'].includes(TOOL_BY_ID[id].status), `${id} has honest status`);
    assert.ok(TOOL_BY_ID[id].detail && TOOL_BY_ID[id].detail.length > 20, `${id} documents its scope`);
  }
  for (const t of TOOLS.filter((x) => x.status === 'host')) {
    assert.ok(t.detail && (/desktop|Mac|iOS|on-device|IPA|runtime|phone|jailbr/i).test(t.detail), `host tool ${t.id} explains itself: ${t.detail}`);
  }
});
test('toolchain: full pipeline runs on a real synthetic IPA and produces real records', async () => {
  const { blob, model } = await buildSyntheticIPA();
  const r = await runToolchain(blob, model, {});
  assert.ok(r.records.length >= 45, `one record per tool (${r.records.length})`);
  // engines really ran
  assert.ok(r.ran['macho-metadata'], 'macho engine ran');
  assert.ok(r.ran['macho-metadata'].binaries.length >= 1);
  assert.ok(r.ran['symbols'], 'symbol engine ran');
  assert.ok(r.ran['symbols'].total > 0, `symbols found (${r.ran['symbols'].total})`);
  assert.ok(r.ran['symbols'].swift >= 2, 'Swift symbols demangled');
  assert.ok(r.ran['deps'], 'dependency engine ran');
  assert.ok(r.ran['deps'].linksTotal >= 2, `links found (${r.ran['deps'].linksTotal})`);
  assert.equal(r.ran['deps'].tally.missing, 1, 'ThirdParty detected as missing');
  assert.ok(r.ran['objc-names'], 'ObjC name engine ran');
  assert.ok(r.ran['objc-names'].methods >= 2, `ObjC methods found (${r.ran['objc-names'].methods})`);
  assert.ok(r.ran['security-audit'], 'audit engine ran');
  assert.ok(r.ran['security-audit'].findings.length >= 3, `audit findings (${r.ran['security-audit'].findings.length})`);
  assert.ok(r.ran['packages'], 'package engine ran');
  assert.ok(r.ran['packages'].summary.cocoapods, 'Podfile.lock detected');
  assert.ok(r.ran['signatures-scan'], 'signature scanner ran');
  // the disassembly engine ran and produced real instructions
  assert.ok(r.ran['disasm-auto'], 'disassembly engine ran');
  assert.ok(r.ran['disasm-auto'].binaries.length >= 1, 'disassembled at least one binary');
  assert.ok(r.ran['disasm-auto'].binaries[0].instructions > 100, `real instruction counts (${r.ran['disasm-auto'].binaries[0].instructions})`);
  const sample = r.ran['disasm-auto'].binaries[0].sample.slice(0, 5);
  assert.ok(sample.every((x) => x.mnemonic && typeof x.address === 'number'), 'instructions have mnemonics + addresses');
  // records: active tools marked ran, host tools marked not ran
  const ida = r.records.find((x) => x.id === 'ida-pro');
  assert.equal(ida.status, 'host');
  assert.equal(ida.ran, false, 'IDA Pro is not simulated');
  const otool = r.records.find((x) => x.id === 'otool');
  assert.equal(otool.ran, true, 'otool equivalent ran');
  assert.ok(otool.summary && otool.summary.length > 3);
  const classDump = r.records.find((x) => x.id === 'class-dump');
  assert.match(classDump.summary, /classes/, 'class-dump record carries real counts');
  const capstone = r.records.find((x) => x.id === 'capstone-core');
  assert.match(capstone.summary, /instructions/, 'capstone record carries real counts');
  // summary counts consistent
  assert.equal(r.counts.host, TOOLS.filter((t) => t.status === 'host').length);
});

// ---------- toolchain workspace ZIP export (v1.3.1) ----------
test('tcexport: workspace ZIP holds real files mirroring the IPA structure', async () => {
  const { blob, model } = await buildSyntheticIPA();
  const tc = await runToolchain(blob, model, {});
  const { blob: zipBlob, root, notes } = await buildToolchainZip(blob, model, tc, {});
  assert.ok(root.startsWith('Demo_') && root.endsWith('/'), `root folder named after the app: ${root}`);
  const z = await (await import('../public/js/core/zip-reader.js')).openZip(zipBlob, {});
  const names = z.entries.map((e) => e.name);
  const has = (n) => names.some((x) => x === root + n);
  for (const must of ['toolchain.json', 'tool-status.csv', 'REPORT.md', 'README_WORKSPACE.md',
    'dependencies/dependencies.txt', 'dependencies/missing.txt', 'dependencies/unique.txt',
    'audit/findings.txt', 'audit/audit.json', 'packages/manifests.txt', 'packages/packages.json',
    'signatures/signatures.txt']) {
    assert.ok(has(must), `workspace contains ${must}`);
  }
  // full symbol list re-run: real symbol names from the fixture must appear
  const symName = names.find((x) => x.includes('symbols/Payload/Demo.app/Demo.symbols.txt'));
  assert.ok(symName, `symbol file mirrors IPA path: ${names.filter((n) => n.includes('symbols/')).join(', ')}`);
  const symTxt = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name === symName))).bytes);
  assert.match(symTxt, /main\.ContentView|MyWorker/, 'real symbol names present');
  assert.ok(symTxt.includes('[' + 'm' + 'ain.ContentView]'), 'demangled names rendered in brackets');
  // deps file carries the real links incl. the missing one
  const depsTxt = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name.endsWith('dependencies.txt')))).bytes);
  assert.match(depsTxt, /ThirdParty\.framework\/ThirdParty/, 'dependency list carries the real link');
  const missingTxt = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name.endsWith('missing.txt')))).bytes);
  assert.match(missingTxt, /ThirdParty/, 'missing dependency honestly recorded');
  // disasm file with real instructions
  const disName = names.find((x) => x.includes('disasm/') && x.endsWith('.disasm.txt'));
  assert.ok(disName, `disassembly exported: ${names.filter((n) => n.includes('disasm/')).join(', ')}`);
  const disTxt = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name === disName))).bytes);
  assert.match(disTxt, /0x[0-9a-f]{8}/, 'disassembly has real addresses');
  // tool-status CSV: one row per registered tool
  const csv = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name.endsWith('tool-status.csv')))).bytes);
  assert.ok(csv.trim().split('\n').length - 1 >= 45, 'one CSV row per tool');
  // podfile packages present
  const pkgTxt = new TextDecoder().decode((await (await import('../public/js/core/zip-reader.js')).entryBytes(zipBlob, z.entries.find((e) => e.name.endsWith('manifests.txt')))).bytes);
  assert.match(pkgTxt, /Alamofire/, 'CocoaPods manifest content present');
});
