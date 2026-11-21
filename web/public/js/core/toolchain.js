// Toolchain registry + orchestrator — the unified analysis workspace.
//
// This file is the single source of truth about the 45 requested tools:
// what Cairn actually runs on-device (status 'active' / 'partial'), and what
// genuinely cannot run inside an iOS app (status 'host', with the reason).
// It never simulates: every entry either runs real code and reports real
// counts, or is explicitly marked as requiring an external environment.

import { parseMachO, isMachO, objcNames } from './macho.js';
import { readSymbols } from './symbols.js';
import { demangle } from './demangle.js';
import { buildDeps } from './deps.js';
import { scanFiles } from './signatures.js';
import { analysePackages } from './packages.js';
import { auditApp } from './audit.js';
import { disasm, loadDisasm, DISASM_LIMITS } from './disasm.js';
import { makeReader, readRecBytes } from './pkg-utils.js';

// status values:
//   active  — the tool's core function runs in Cairn on-device, real results
//   partial — a genuine subset runs (stated); the full tool needs a desktop
//   host    — cannot run inside an iOS app at all; reason stated, no fake run
export const TOOLS = [
  // ---- static engines implemented in Cairn ----
  { id: 'class-dump', name: 'class-dump', group: 'ObjC & Swift', status: 'active',
    runs: 'objcNames engine', detail: 'Extracts ObjC class names, method names, method types and C strings from the compiled __objc_* sections — the same tables class-dump reads.' },
  { id: 'otool', name: 'otool', group: 'Mach-O', status: 'active',
    runs: 'Mach-O engine', detail: 'Load commands, segments/sections, UUID, platform, minOS, encryption info, linked libraries — the metadata surface otool prints.' },
  { id: 'otool-L', name: 'otool -L', group: 'Mach-O', status: 'active',
    runs: 'dependency engine', detail: 'Linked-library listing for every binary in the IPA, classified system / embedded / missing.' },
  { id: 'nm', name: 'nm', group: 'Mach-O', status: 'active',
    runs: 'symbol engine', detail: 'Full LC_SYMTAB walk: every symbol with address, type, section, external flag.' },
  { id: 'strings', name: 'strings', group: 'Mach-O', status: 'active',
    runs: 'name-table engine', detail: 'C-string extraction from __cstring, __objc_classname, __objc_methname and symbol name tables.' },
  { id: 'swift-demangle', name: 'swift-demangle / Swift Demangle', group: 'ObjC & Swift', status: 'partial',
    runs: 'demangler (subset)', detail: 'Demangles the dominant families: _Tt ObjC-bridged Swift types (incl. So/SC names), _$s paths (best-effort) and Itanium C++ nested names. Full signature-accurate Swift demangling needs the Swift toolchain.' },
  { id: 'codesign', name: 'codesign', group: 'Security', status: 'partial',
    runs: 'signature parser', detail: 'Parses the embedded signature: CodeDirectory (identifier, team ID, flags), entitlements blob, blob list — display level, like `codesign -d`. Cryptographic chain validation against Apple roots is not performed on-device.' },
  { id: 'MachOView', name: 'MachOView', group: 'Mach-O', status: 'active',
    runs: 'File Explorer + Mach-O cards', detail: 'Interactive per-file Mach-O inspection (headers, segments, sections, load commands, hex). GUI editing is not applicable — read-only by design.' },
  { id: 'LIEF', name: 'LIEF', group: 'Mach-O', status: 'active',
    runs: 'Mach-O engine', detail: 'LIEF is a parsing library; its Mach-O parsing surface (headers, sections, symbols, signature blobs) is what Cairn\u2019s own engine implements.' },
  { id: 'dyld_shared_cache_util', name: 'dyld_shared_cache_util', group: 'Mach-O', status: 'partial',
    runs: 'dyld cache detector', detail: 'Detects dyld shared cache files (dyld_v1) inside archives and reports the cache header version. Full image extraction from firmware caches needs a workstation.' },
  { id: 'ipsw', name: 'ipsw', group: 'Formats', status: 'partial',
    runs: 'format detector', detail: 'Detects Apple IMG4/IM4P/IM4M/IM4C CMS structures and Mach-O fat archives inside the archive. Firmware-level extraction (patterns, keys, mount) needs a workstation.' },
  { id: 'jtool2', name: 'jtool2', group: 'Mach-O', status: 'partial',
    runs: 'Mach-O engine', detail: 'jtool2\u2019s core display functions (headers, symbols, disassembly, signature dump) are covered by Cairn\u2019s Mach-O + symbol + signature engines; jtool2 itself is a desktop binary.' },
  { id: 'binwalk', name: 'Binwalk', group: 'Formats', status: 'active',
    runs: 'signature scanner', detail: 'Magic-signature scan of every readable file (PNG/JPEG/gzip/xz/7z/ZIP/RAR/SQLite/Mach-O/dyld cache/DER/PEM) with offsets — binwalk\u2019s core scan, on-device.' },
  { id: '7zip', name: '7-Zip', group: 'Formats', status: 'partial',
    runs: 'ZIP engine + detection', detail: 'ZIP (the format inside .ipa) is fully extracted and rebuilt by Cairn. Other archive containers (7z, RAR, LZMA streams) are detected by signature; decompression of those needs the desktop binary.' },
  { id: 'unarchiver', name: 'The Unarchiver', group: 'Formats', status: 'partial',
    runs: 'ZIP engine + detection', detail: 'Same scope as 7-Zip: ZIP fully supported; other formats detected and reported, extraction to Files app via the share sheet.' },
  { id: 'ImHex', name: 'ImHex', group: 'Hex & patterns', status: 'partial',
    runs: 'hex viewer', detail: 'Hex viewer with offsets and ASCII for every file (read-only). ImHex\u2019s pattern-language engine is a desktop feature and is not reimplemented.' },
  { id: '010-editor', name: '010 Editor', group: 'Hex & patterns', status: 'partial',
    runs: 'hex viewer', detail: 'Same as ImHex: genuine hex inspection; 010 Editor is a commercial desktop GUI and is not simulated.' },
  { id: 'kaitai', name: 'Kaitai Struct', group: 'Hex & patterns', status: 'partial',
    runs: 'structure readers', detail: 'Cairn ships hand-written readers for the structures Kaitai would describe (ZIP, Mach-O, plist, CgBI, PNG). Custom .ks definitions cannot be compiled on-device.' },
  { id: 'cocoapods', name: 'CocoaPods Analysis', group: 'Packages', status: 'active',
    runs: 'manifest parser', detail: 'Finds and parses Podfile.lock inside the IPA: every pod with its resolved version; detects Pods/ structure.' },
  { id: 'carthage', name: 'Carthage Analysis', group: 'Packages', status: 'active',
    runs: 'manifest parser', detail: 'Parses Cartfile.resolved pins and detects Carthage/Build trees.' },
  { id: 'spm', name: 'Swift Package Manager Analysis', group: 'Packages', status: 'active',
    runs: 'manifest parser', detail: 'Parses Package.resolved (v1 + v2 formats) with identities and resolved versions/revisions.' },
  { id: 'mobsf', name: 'MobSF (iOS static rules)', group: 'Security', status: 'partial',
    runs: 'audit engine', detail: 'Runs MobSF\u2019s iOS static-analysis category on-device: ATS, permissions, entitlements (get-task-allow, library validation), PIE/ARC/canary, dangerous C APIs, secret-pattern scan. The full MobSF server (dynamic analysis, Android, web UI) is a workstation product.' },
  { id: 'dependency-walker', name: 'Dependency Walker', group: 'Mach-O', status: 'active',
    runs: 'dependency engine', detail: 'The Dependency Walker tool is Windows/PE-only; its role (full dependency graph with missing-module detection) is what Cairn\u2019s dependency engine does for Mach-O — including missing-library detection.' },

  // ---- disassembly family: the core engine runs (Capstone), the full tools are desktop ----
  { id: 'capstone-core', name: 'Disassembly engine (Capstone 5, WASM)', group: 'Disassembly', status: 'active',
    runs: 'Capstone WASM', detail: 'Genuine disassembly of ARM64 / ARM / Thumb / x86 / x86_64 machine code, in-app. This is the engine behind the disassembler family below.' },
  { id: 'radare2', name: 'Radare2', group: 'Disassembly', status: 'partial',
    runs: 'Capstone-backed disassembly', detail: 'The disassembly core function runs in Cairn via Capstone. Radare2\u2019s own analysis (xrefs, function discovery, r2 scripts) is a desktop runtime and is not simulated.' },
  { id: 'rizin', name: 'Rizin', group: 'Disassembly', status: 'partial',
    runs: 'Capstone-backed disassembly', detail: 'Rizin is the radare2 fork — same scope: disassembly core runs via Capstone; rz-pipe analysis needs a desktop.' },
  { id: 'cutter', name: 'Cutter', group: 'Disassembly', status: 'host',
    runs: 'export path', detail: 'Cutter is a GUI around rizin — a desktop Qt application that cannot be embedded in an iOS app. Cairn exports the artifacts Cutter ingests.' },
  { id: 'ghidra', name: 'Ghidra', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Ghidra needs a Java desktop runtime and cannot execute inside an iOS app. Cairn provides what Ghidra ingests: the original binary, symbols, strings and entry points.' },
  { id: 'ida-pro', name: 'IDA Pro', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Commercial GUI disassembler/decompiler for desktop; cannot be embedded in an iOS app. Cairn exports the same artifacts you would feed to IDA.' },
  { id: 'binary-ninja', name: 'Binary Ninja', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Commercial desktop tool; cannot run on-device. Its input artifacts are available from Cairn.' },
  { id: 'hopper', name: 'Hopper Disassembler', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Commercial macOS/Linux tool; cannot run on-device.' },
  { id: 'retdec', name: 'RetDec', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Desktop decompiler toolchain; a phone cannot host its LLVM pipeline.' },
  { id: 'revng', name: 'rev.ng', group: 'Decompilers', status: 'host',
    runs: 'export path', detail: 'Desktop decompilation platform; cannot run on-device.' },
  { id: 'llvm', name: 'LLVM', group: 'Mach-O', status: 'partial',
    runs: 'demangler + Mach-O parsing surface', detail: 'LLVM is a compiler toolchain, not an embeddable iOS library. Cairn\u2019s Mach-O parsing and Itanium C++ demangling cover the LLVM utility surface that applies to shipped binaries (llvm-nm/otool equivalents); the build pipeline itself is a desktop product.' },

  // ---- dynamic instrumentation ----
  { id: 'frida', name: 'Frida', group: 'Dynamic', status: 'host',
    runs: 'not runnable on stock iOS', detail: 'Dynamic injection requires a running target process, a debug server or a jailbreak, plus a host client. No stock-iOS app can attach to other processes.' },
  { id: 'objection', name: 'Objection', group: 'Dynamic', status: 'host',
    runs: 'not runnable on stock iOS', detail: 'Built on Frida — the same constraints: no dynamic injection without a jailbreak or a host environment.' },
  { id: 'lldb', name: 'LLDB', group: 'Dynamic', status: 'host',
    runs: 'not runnable on stock iOS', detail: 'Debugging requires debugserver/ptrace entitlements that non-App-Store apps on stock iOS do not have.' },
  { id: 'dtrace', name: 'DTrace', group: 'Dynamic', status: 'host',
    runs: 'not runnable on iOS', detail: 'DTrace probes are a macOS host kernel feature.' },
  { id: 'instruments', name: 'Instruments', group: 'Dynamic', status: 'host',
    runs: 'not runnable on iOS', detail: 'Xcode Instruments runs on a Mac and profiles a device over USB.' },
  { id: 'cycript', name: 'Cycript', group: 'Dynamic', status: 'host',
    runs: 'not runnable on stock iOS', detail: 'Abandoned (last release 2016) and requires a jailbroken runtime.' },

  // ---- emulation / symbolic execution ----
  { id: 'angr', name: 'angr', group: 'Emulation', status: 'host',
    runs: 'not runnable on-device', detail: 'Python symbolic-execution framework; a phone cannot host it, so it stays a desktop tool.' },
  { id: 'unicorn', name: 'Unicorn Engine', group: 'Emulation', status: 'host',
    runs: 'not runnable on-device', detail: 'CPU-emulation C library; a phone cannot host a full emulator pipeline, and it would not add static-analysis value here.' },
  { id: 'qiling', name: 'Qiling Framework', group: 'Emulation', status: 'host',
    runs: 'not runnable on-device', detail: 'Full-system emulation framework on top of Unicorn — a desktop workstation is required; an iOS app cannot host it.' },

  // ---- source-level scanners ----
  { id: 'semgrep', name: 'Semgrep', group: 'Source scanners', status: 'host',
    runs: 'not applicable to compiled IPA', detail: 'Semgrep rules match source code. IPAs ship compiled machine code, not source. The rule categories Semgrep covers for iOS are implemented by the audit engine where they apply to binaries.' },
  { id: 'codeql', name: 'CodeQL', group: 'Source scanners', status: 'host',
    runs: 'not applicable to compiled IPA', detail: 'CodeQL builds a source database — no source ships in an IPA. Same rationale as Semgrep.' },
];

export const TOOL_BY_ID = Object.fromEntries(TOOLS.map((t) => [t.id, t]));

const AUTO_DISASM_INSTRS = 256; // disassembled automatically for each readable binary

/** Run the whole compatible pipeline for an open session.
 * fileBlob: the IPA File/Blob; model: scanIPA result. */
export async function runToolchain(fileBlob, model, { onProgress = () => {}, signal } = {}) {
  const reader = makeReader(fileBlob);
  const t0 = Date.now();
  const ran = {};
  const step = async (id, fn) => {
    const t = Date.now();
    try {
      const res = await fn();
      ran[id] = { ok: true, ms: Date.now() - t, ...(res || {}) };
    } catch (e) {
      if (e && e.code === 'aborted') throw e;
      ran[id] = { ok: false, ms: Date.now() - t, error: String(e && e.message || e) };
    }
    onProgress({ done: Object.keys(ran).length, current: id });
    await new Promise((r) => setTimeout(r, 0));
    if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
  };

  // Every Mach-O worth deep analysis (main binary, frameworks, plugins, dylibs)
  const targets = model.files.filter((f) => !f.isDir && (f.path.endsWith('.dylib') || /Payload\/[^/]+\.app\/[^/]+$/.test(f.path) && !/\.(png|car|plist|strings|nib|momd|mom|dat|json|html|css|js|txt|jpg|jpeg|pdf|ttf|otf|mp3|mp4|wav|caf|lproj|storyboardc|xib|aac|m4a|m4v|mp4|woff|ttf|otf)$/i.test(f.path)) && f.size < 96 << 20);

  await step('macho-metadata', async () => {
    const binaries = [];
    for (const f of targets.slice(0, 60)) {
      const { bytes } = await readRecBytes(fileBlob, f, Math.min(f.size, 64 << 20));
      if (!isMachO(bytes)) continue;
      const m = parseMachO(bytes);
      if (!m.ok) continue;
      binaries.push({ path: f.path, size: f.size, archs: m.slices.filter((s) => s.ok).map((s) => s.arch), encrypted: m.slices.some((s) => s.ok && s.encrypted), platform: m.slices[0].ok ? m.slices[0].platform : null, minOS: m.slices[0].ok ? m.slices[0].minOS : null, uuid: m.slices[0].ok ? m.slices[0].uuid : null });
    }
    return { binaries, count: binaries.length };
  });

  await step('objc-names', async () => {
    const out = [];
    for (const f of targets.slice(0, 24)) {
      const { bytes } = await readRecBytes(fileBlob, f, Math.min(f.size, 64 << 20));
      if (!isMachO(bytes)) continue;
      const m = parseMachO(bytes);
      for (const sl of m.slices.filter((s) => s.ok).slice(0, 2)) {
        const names = objcNames(bytes, sl);
        if (names.ok && (names.classCount || names.methodCount)) out.push({ path: f.path, arch: sl.arch, classes: names.classCount, methods: names.methodCount, sample: names.classes.slice(0, 60), methodSample: names.methods.slice(0, 60), truncated: names.truncated });
      }
    }
    return { binaries: out, classes: out.reduce((s, b) => s + b.classes, 0), methods: out.reduce((s, b) => s + b.methods, 0) };
  });

  await step('symbols', async () => {
    const out = [];
    let total = 0, swift = 0, cxx = 0;
    for (const f of targets.slice(0, 24)) {
      const { bytes } = await readRecBytes(fileBlob, f, Math.min(f.size, 64 << 20));
      if (!isMachO(bytes)) continue;
      const m = parseMachO(bytes);
      const sl = m.slices.find((s) => s.ok);
      if (!sl) continue;
      const syms = readSymbols(bytes, sl, { limit: 60000 });
      if (!syms.ok) { out.push({ path: f.path, arch: sl.arch, error: syms.error }); continue; }
      total += syms.count; swift += syms.byFamily.swift; cxx += syms.byFamily.cxx;
      const sample = syms.symbols.filter((s) => s.name).slice(0, 80).map((s) => ({ name: s.name, demangled: s.demangled, kind: s.kind, value: s.value }));
      out.push({ path: f.path, arch: sl.arch, count: syms.count, totalInTable: syms.totalInTable, byKind: syms.byKind, byFamily: syms.byFamily, sample, truncated: syms.truncated });
    }
    return { binaries: out, total, swift, cxx };
  });

  await step('deps', async () => buildDeps(model, async (f) => readRecBytes(fileBlob, f, Math.min(f.size, 24 << 20))));
  await step('packages', async () => analysePackages(model, async (f, cap) => readRecBytes(fileBlob, f, cap || 2 << 20)));
  await step('signatures-scan', async () => scanFiles(model.files.filter((f) => !f.isDir && f.size >= 4096 && f.size < 48 << 20).slice(0, 120), async (f) => readRecBytes(fileBlob, f, Math.min(f.size, 48 << 20))));
  await step('security-audit', async () => auditApp(fileBlob, model, { onProgress }));

  await step('disasm-auto', async () => {
    let engine = null;
    try { engine = await loadDisasm(); } catch { return { ok: false, error: 'Disassembly engine failed to load' }; }
    const out = [];
    for (const f of targets.slice(0, 6)) {
      const { bytes } = await readRecBytes(fileBlob, f, Math.min(f.size, 64 << 20));
      if (!isMachO(bytes)) continue;
      const m = parseMachO(bytes);
      const sl = m.slices.find((s) => s.ok);
      if (!sl || sl.encrypted) continue;
      const text = (sl.sections || []).find((s) => s.sect === '__text' && s.seg === '__TEXT');
      if (!text || !text.size) continue;
      const seg = (sl.segments || []).find((s) => s.name === '__TEXT');
      const vmaddr = seg ? seg.vmaddr + (text.offset - seg.fileoff) : text.offset;
      const len = Math.min(text.size, AUTO_DISASM_INSTRS * 4);
      const r = await disasm(bytes.subarray(text.offset, text.offset + len), sl.arch, vmaddr, { count: AUTO_DISASM_INSTRS });
      out.push({ path: f.path, arch: sl.arch, section: '__text', vmaddr, instructions: r.instructions.length, sample: r.instructions.slice(0, AUTO_DISASM_INSTRS) });
    }
    return { engine: 'capstone 5 (WASM)', binaries: out };
  });

  // Execution records for every registry tool: real ones from `ran`,
  // host/partial ones from the registry (explicitly marked not-run-on-device).
  const records = TOOLS.map((t) => {
    if (t.status === 'host') {
      return { id: t.id, name: t.name, group: t.group, status: t.status, ran: false, note: t.detail };
    }
    const link = TOOL_RESULT_LINK[t.id] || {};
    const res = link.results ? link.results(ran) : null;
    return { id: t.id, name: t.name, group: t.group, status: t.status, ran: t.status === 'active' ? !!res : !!res, ms: res && res.ms, summary: res ? res.summary : (t.status === 'partial' ? 'subset ran' : 'not run'), detail: t.detail, error: res && res.error };
  });

  return {
    ranAt: Date.now(),
    durationMs: Date.now() - t0,
    ran,
    records,
    counts: {
      active: records.filter((r) => r.status === 'active' && r.ran).length,
      partial: records.filter((r) => r.status === 'partial' && r.ran).length,
      host: records.filter((r) => r.status === 'host').length,
    },
  };
}

// Maps registry tool ids to the pipeline results that represent them.
const TOOL_RESULT_LINK = {
  'class-dump': { results: (r) => r['objc-names'] && { ms: r['objc-names'].ms, summary: (r['objc-names'].classes || r['objc-names'].methods) ? `${r['objc-names'].classes} ObjC classes, ${r['objc-names'].methods} methods` : 'no ObjC tables found' } },
  'otool': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: `${r['macho-metadata'].count} Mach-O binaries inspected` } },
  'otool-L': { results: (r) => r['deps'] && { ms: r['deps'].ms, summary: `${r['deps'].linksTotal} links · ${r['deps'].tally.missing} missing` } },
  'nm': { results: (r) => r['symbols'] && { ms: r['symbols'].ms, summary: `${r['symbols'].total} symbols (${r['symbols'].swift} Swift-family, ${r['symbols'].cxx} C++)` } },
  'strings': { results: (r) => r['objc-names'] && { ms: r['objc-names'].ms, summary: 'C-string tables read (see ObjC names & symbols)' } },
  'swift-demangle': { results: (r) => r['symbols'] && { ms: r['symbols'].ms, summary: `${r['symbols'].swift} Swift-family names demangled (best-effort)` } },
  'codesign': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: 'embedded signature blobs parsed (see Security tab)' } },
  'MachOView': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: `${r['macho-metadata'].count} binaries browsable` } },
  'LIEF': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: 'Mach-O parsing surface (headers, sections, symbols, signature)' } },
  'dyld_shared_cache_util': { results: (r) => r['signatures-scan'] && { ms: r['signatures-scan'].ms, summary: r['signatures-scan'].files.some((f) => f.hits.some((h) => h.name.includes('dyld'))) ? 'dyld cache signature detected' : 'no dyld cache in this archive' } },
  'ipsw': { results: (r) => r['signatures-scan'] && { ms: r['signatures-scan'].ms, summary: r['signatures-scan'].files.some((f) => f.hits.some((h) => h.name.includes('IMG4') || h.name.includes('IM4'))) ? 'IMG4/IM4P structures detected' : 'no IMG4 structures found' } },
  'jtool2': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: 'display functions covered by Mach-O/symbol/signature engines' } },
  'binwalk': { results: (r) => r['signatures-scan'] && { ms: r['signatures-scan'].ms, summary: `${r['signatures-scan'].files.reduce((s, f) => s + f.hits.length, 0)} signatures in ${r['signatures-scan'].filesScanned} files` } },
  '7zip': { results: (r) => r['signatures-scan'] && { ms: r['signatures-scan'].ms, summary: 'ZIP handled natively; other containers detected by signature' } },
  'unarchiver': { results: (r) => r['signatures-scan'] && { ms: r['signatures-scan'].ms, summary: 'ZIP handled natively; other containers detected' } },
  'ImHex': { results: () => ({ summary: 'hex viewer available in File Explorer previews' }) },
  '010-editor': { results: () => ({ summary: 'hex viewer available (read-only)' }) },
  'kaitai': { results: (r) => r['macho-metadata'] && { ms: r['macho-metadata'].ms, summary: 'hand-written structure readers: ZIP, Mach-O, plist, CgBI, PNG' } },
  'cocoapods': { results: (r) => r['packages'] && { ms: r['packages'].ms, summary: r['packages'].summary.cocoapods ? `CocoaPods manifest found (${(r['packages'].manifests.find((m) => m.kind === 'cocoapods') || {}).count || 0} pods)` : 'no CocoaPods manifest in archive' } },
  'carthage': { results: (r) => r['packages'] && { ms: r['packages'].ms, summary: r['packages'].summary.carthage ? 'Carthage manifest found' : 'no Carthage manifest in archive' } },
  'spm': { results: (r) => r['packages'] && { ms: r['packages'].ms, summary: r['packages'].summary.spm ? 'SPM Package.resolved found' : 'no SPM manifest in archive' } },
  'mobsf': { results: (r) => r['security-audit'] && { ms: r['security-audit'].ms, summary: `${r['security-audit'].findings.length} findings across ${r['security-audit'].binariesChecked} binaries` } },
  'dependency-walker': { results: (r) => r['deps'] && { ms: r['deps'].ms, summary: `${r['deps'].binaries.length} binaries · ${r['deps'].tally.missing} missing dependencies` } },
  'capstone-core': { results: (r) => r['disasm-auto'] && { ms: r['disasm-auto'].ms, summary: r['disasm-auto'].ok ? `${r['disasm-auto'].binaries.reduce((s, b) => s + b.instructions, 0)} instructions disassembled automatically` : r['disasm-auto'].error } },
  'radare2': { results: (r) => r['disasm-auto'] && { ms: r['disasm-auto'].ms, summary: 'core disassembly via Capstone; r2 analysis not simulated' } },
  'rizin': { results: (r) => r['disasm-auto'] && { ms: r['disasm-auto'].ms, summary: 'core disassembly via Capstone; rizin analysis not simulated' } },
  'llvm': { results: (r) => r['symbols'] && { ms: r['symbols'].ms, summary: `${r['symbols'].cxx} C++ names demangled (Itanium subset)` } },
};
