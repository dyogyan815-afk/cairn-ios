// ALL-IN-ONE export — one special file per scanned app that carries everything
// the scan produced, so a single download brings the whole analysis along:
//
//   info/       the complete analysis report (REPORT.md, analysis.json,
//               manifest.json + .csv, SHA256SUMS.txt, readable Info.plist,
//               entitlements, icon)
//   files/      EVERY file from the IPA, original folder structure,
//               byte-for-byte (raw-copied compressed streams)
//   xcode/      a resource-only Xcode project reconstructed from the IPA
//               (project.pbxproj, readable Info.plist, entitlements, all
//               assets in project-style folders) — plus a real checklist of
//               what the app actually contains
//   toolchain/  the 45-tool analysis workspace (dependencies, symbols, ObjC
//               names, disassembly, signatures, packages, audit) when that
//               pipeline has run — an honest NOT-RUN.txt otherwise
//
// Honesty rules (same as every Cairn exporter): sections that were not
// produced are listed as absent, never fabricated. Every entry is re-opened
// and checked before this blob is handed to the caller's own verification.

import { ZipWriter } from './zip-writer.js';
import { openZip } from './zip-reader.js';
import { buildOriginalZip, buildReportZip, buildProjectZip } from './exporter.js';
import { buildToolchainZip } from './tcexport.js';
import { AppError } from './util.js';

const yieldNow = () => new Promise((r) => setTimeout(r, 0));

/** Re-add every entry of a finished zip blob under a prefix inside zw.
 * Raw-copies compressed bytes, so merged content stays byte-identical. */
async function mergeZip(zw, srcBlob, { prefix, strip = '', label, onProgress, signal }) {
  const z = await openZip(srcBlob, { signal });
  let i = 0, bytes = 0, unreadable = 0;
  for (const e of z.entries) {
    if (signal && signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
    let name = e.name;
    if (strip && name.startsWith(strip)) name = name.slice(strip.length);
    if (!name) { i++; continue; }
    if (name.endsWith('/')) zw.addDirectory(prefix + name, e);
    else if (e.dataOffset >= 0) { zw.addRaw(prefix + name, srcBlob, e); bytes += e.usize; }
    else { unreadable++; zw.addBytes(`${prefix}${name}.UNREADABLE.txt`, `Entry "${e.name}" had a damaged local header in the source archive and could not be copied.\n`); }
    if (onProgress && ++i % 20 === 0) { onProgress({ done: i, total: z.entries.length, current: `${label}: ${name}` }); await yieldNow(); }
  }
  return { entries: i, bytes, unreadable };
}

/** REAL per-app project checklist — what the IPA actually contains, counted
 * from the scanned entries. Nothing inferred beyond the paths themselves. */
export function projectChecklist(model) {
  const a = model.app;
  const files = model.files.filter((f) => !f.isDir);
  const count = (re) => files.filter((f) => re.test(f.path)).length;
  const dirs = (re) => model.files.filter((f) => f.isDir && re.test(f.path)).length;
  return {
    xcodeproj: true, // generated resource-only project in xcode/
    sourceFiles: count(/\.(swift|m|mm|h|hpp|c|cpp)$/i),
    assetCatalogs: count(/\.car$/i),
    xcassetsFolders: dirs(/\.xcassets\/?$/i),
    images: count(/\.(png|jpg|jpeg|gif|webp|svg|ico|heic)$/i),
    infoPlist: !!(a && a.infoPlist),
    entitlements: !!(a && a.entitlementsXml),
    provisioning: a && a.provisioning && a.provisioning.kind ? a.provisioning.kind : null,
    podfile: count(/(^|\/)Podfile(\.lock)?$/i),
    spm: count(/(^|\/)Package\.(swift|resolved)$/i),
    carthage: count(/(^|\/)Cartfile(\.resolved)?$/i),
    podspecs: count(/\.podspec(\.json)?$/i),
    frameworks: dirs(/\.framework\/?$/i),
  };
}

/** Build the complete ALL-IN-ONE package for one open session.
 * fileBlob: the IPA File/Blob; model: scanIPA result;
 * tc: the session's toolchain state ({ state: 'done', result } when finished) or null. */
export async function buildAllInOneZip(fileBlob, model, tc, { onProgress = () => {}, signal } = {}) {
  const app = model.app;
  const appName = (app && (app.displayName || app.name)) || model.fileName.replace(/\.[^.]+$/, '');
  const root = `${appName.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)}_ALL-IN-ONE/`;
  const zw = new ZipWriter();
  const step = (current, done, total) => onProgress({ done, total, current });
  const parts = {};

  // 1 — files/ : every original entry, byte-for-byte, original structure
  step('gathering every original file…', 0, 1);
  const orig = await buildOriginalZip(fileBlob, model, { signal, onProgress: (p) => onProgress({ done: p.done, total: p.total, current: `files: ${p.current || ''}` }) });
  parts.files = await mergeZip(zw, orig.blob, { prefix: `${root}files/`, label: 'files', onProgress, signal });
  parts.files.skipped = orig.skipped;

  // 2 — info/ : the complete analysis report + the real project checklist
  step('packaging the analysis report…', 0, 1);
  const rep = await buildReportZip(fileBlob, model, { signal });
  const ck = projectChecklist(model);
  const yn = (b) => (b ? 'yes' : 'none');
  zw.addBytes(`${root}info/PROJECT-CHECKLIST.txt`, [
    `PROJECT CHECKLIST — ${appName}`, '=========================', '',
    'Exactly what this IPA contains, counted from the real scan. Nothing invented.', '',
    `[x] Xcode project            ${appName}.xcodeproj (resource-only) — see xcode/`,
    `    Generated from the IPA so its contents can be browsed and rebuilt-around in Xcode.`,
    `[${ck.sourceFiles ? 'x' : ' '}] .swift/.m/.h source files ${ck.sourceFiles ? String(ck.sourceFiles).padStart(4) + ' found — shipped inside the IPA, copied as-is' : '   0 found — IPAs ship compiled code only; none were fabricated'}`, '',
    `[${ck.assetCatalogs || ck.xcassetsFolders ? 'x' : ' '}] Assets                     ${ck.assetCatalogs} compiled .car catalog(s), ${ck.xcassetsFolders} .xcassets folder(s), ${ck.images} image file(s)`,
    `    IPAs store assets compiled (Assets.car / PNGs). The ORIGINAL files are shipped`,
    `    as-is in xcode/Resources/Images; compiling back to .xcassets is not done because`,
    `    that cannot be honest.`, '',
    `[${ck.infoPlist ? 'x' : ' '}] Info.plist                ${yn(ck.infoPlist)} — original in files/, readable XML in xcode/Supporting/`,
    `[${ck.entitlements ? 'x' : ' '}] Entitlements              ${yn(ck.entitlements)}${ck.provisioning ? ` (provisioning: ${ck.provisioning})` : ''}`, '',
    `[${ck.podfile ? 'x' : ' '}] Podfile / Podfile.lock    ${ck.podfile} found in the IPA`,
    `[${ck.spm ? 'x' : ' '}] Package.swift / .resolved ${ck.spm} found in the IPA`,
    `[${ck.carthage ? 'x' : ' '}] Cartfile / .resolved      ${ck.carthage} found in the IPA`,
    `[${ck.podspecs ? 'x' : ' '}] .podspec manifests        ${ck.podspecs} found in the IPA`,
    `[${ck.frameworks ? 'x' : ' '}] Embedded frameworks       ${ck.frameworks} bundle(s)`, '',
    'Note: source code, Podfiles and Package.swift only exist in an IPA when the',
    'developer actually shipped them. Their absence is the app\'s real state, not a',
    'shortage of this tool.', '',
  ].join('\n'));
  parts.info = await mergeZip(zw, rep.blob, { prefix: `${root}info/`, label: 'info', onProgress, signal });

  // 2b — xcode/ : the reconstructed resource-only Xcode project for THIS app
  step('reconstructing the Xcode project…', 0, 1);
  const proj = await buildProjectZip(fileBlob, model, { signal, onProgress: (p) => onProgress({ done: p.done, total: p.total, current: `xcode: ${p.current || ''}` }) });
  parts.xcode = await mergeZip(zw, proj.blob, { prefix: `${root}xcode/`, strip: `${proj.name}/`, label: 'xcode', onProgress, signal });

  // 3 — toolchain/ : the 45-tool workspace when it has run
  if (tc && tc.state === 'done' && tc.result) {
    step('packaging the 45-tool workspace…', 0, 1);
    const tcz = await buildToolchainZip(fileBlob, model, tc.result, { signal, onProgress: (p) => onProgress({ done: p.done, total: p.total, current: `toolchain: ${p.current || ''}` }) });
    parts.toolchain = await mergeZip(zw, tcz.blob, { prefix: `${root}toolchain/`, strip: tcz.root, label: 'toolchain', onProgress, signal });
    parts.toolchain.notes = tcz.notes;
    parts.toolchainState = 'included';
  } else {
    zw.addBytes(`${root}toolchain/NOT-RUN.txt`, [
      'The 45-tool pipeline has not finished for this app yet, so the analysis',
      'workspace is NOT included in this package. Nothing is simulated here.',
      '',
      'Run the Toolchain card in Cairn, wait for all 45 tools to finish, then',
      'build the ALL-IN-ONE package again — toolchain/ will be complete.',
      '',
      `Requested at: ${new Date().toISOString()}`,
      `Source: ${model.fileName}`,
    ].join('\n'));
    parts.toolchain = { entries: 1, bytes: 0, unreadable: 0, notes: [] };
    parts.toolchainState = 'not-run';
  }

  // ---------- top-level README ----------
  const fmt = (p) => `${p.entries} entries${p.bytes ? ` · ${p.bytes} bytes` : ''}`;
  const readme = [
    `Cairn IPA Studio — ALL-IN-ONE package: ${appName}`,
    '='.repeat(46 + appName.length),
    `Generated locally on ${new Date().toISOString()} from ${model.fileName} (${model.fileSize} bytes).`,
    'Nothing was uploaded; every section below was produced on this device.',
    '',
    'ئەم فایلە هەموو شتێکی ئەپەکە لەیەک فایلدا کۆدەکاتەوە:',
    '  info/       زانیاری و ڕاپۆرتی تەواو + لیستی پشکنینی پڕۆژە',
    '  files/      هەموو فایلە ڕەسەنەکان، بە پێکهاتەی خۆیان، بێ هیچ گۆڕانکاری',
    '  xcode/      پڕۆژەی Xcode ی ئەم ئەپە (وەک خۆی، ڕەسەن — نەک ساختە)',
    '  toolchain/  ورگەی شیکاری 45-توول (ئەگەر جێبەجێ کرابێ)',
    '',
    'WHAT IS INSIDE',
    '--------------',
    'info/       REPORT.md, analysis.json, manifest.json + .csv, SHA256SUMS.txt,',
    '            PROJECT-CHECKLIST.txt, Info.plist (readable XML), entitlements.xml, icon.png',
    'files/      every file from the IPA — original paths, byte-for-byte',
    'xcode/      <App>.xcodeproj (resource-only) + readable Info.plist + entitlements',
    '            + every asset in project-style folders + project.manifest.json',
    'toolchain/  toolchain.json, tool-status.csv, dependencies/, symbols/, objc/,',
    '            disasm/, signatures/, packages/, audit/',
    '',
    'COUNTS',
    '------',
    `files/      ${fmt(parts.files)}${orig.skipped.length ? ` (${orig.skipped.length} damaged entries recorded inside as listings)` : ''}`,
    `info/       ${fmt(parts.info)}`,
    `xcode/      ${fmt(parts.xcode)}`,
    `toolchain/  ${parts.toolchainState === 'included' ? fmt(parts.toolchain) : 'NOT RUN YET — see toolchain/NOT-RUN.txt'}`,
    '',
    'HONEST SCOPE',
    '------------',
    '- Compiled code ships as machine code; nothing was decompiled or AI-generated.',
    '- FairPlay-encrypted binaries are labelled as such, never decrypted.',
    '- The xcode/ project is a real container for the app\'s OWN files (resource-only):',
    '  what the IPA does not carry (Swift source) is listed as absent, never fabricated.',
    '- Rebuild the package after the toolchain pipeline finishes to include its full workspace.',
    ...(parts.files.unreadable || parts.toolchain.unreadable ? ['- Some entries could not be copied and are recorded as .UNREADABLE.txt listings.'] : []),
    ...(parts.toolchainState === 'included' && parts.toolchain.notes.length ? ['', 'WORKSPACE NOTES', '---------------', ...parts.toolchain.notes.map((n) => `- ${n}`)] : []),
    '',
  ].join('\n');
  zw.addBytes(`${root}README-FIRST.txt`, readme);

  const count = parts.files.entries + parts.info.entries + parts.xcode.entries + parts.toolchain.entries + 2; // + README-FIRST.txt + info/PROJECT-CHECKLIST.txt
  step('packaging', 1, 1);
  return { blob: zw.finish(), count, skipped: orig.skipped, appName, root, parts, toolchainState: parts.toolchainState, checklist: ck };
}
