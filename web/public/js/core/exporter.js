// Export engine. Original entries are RAW-COPIED (compressed bytes untouched), so contents stay byte-identical.
import { ZipWriter } from './zip-writer.js';
import { openZip, readEntry } from './zip-reader.js';
import { Sha256 } from './sha256.js';
import { CATEGORY_LABELS } from './classify.js';
import { plistDocument } from './plist.js';
import { cgbiToPng } from './cgbi.js';
import { readFileBytes } from './ipa.js';
import { AppError, formatBytes } from './util.js';

export const DOWNLOADS = { original: 'ORIGINAL_IPA_CONTENTS.zip', project: 'RECONSTRUCTED_APPLICATION_PROJECT.zip', resources: 'AVAILABLE_SOURCE_AND_RESOURCES.zip', report: 'APPLICATION_ANALYSIS_REPORT.zip' };

/** Pick records: all, or by a set of file paths / directory prefixes (selecting "a/b/" selects everything below). */
export function selectRecords(model, { paths, prefixes } = {}) {
  if (!paths && !prefixes) return model.files.slice();
  const P = paths || new Set(), X = prefixes || [];
  return model.files.filter((f) => P.has(f.path) || X.some((x) => f.path.startsWith(x)));
}

async function copyRaw(zw, blob, recs, { onProgress, signal, rename } = {}) {
  let i = 0, bytes = 0; const skipped = [];
  for (const f of recs) {
    if (signal && signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
    const out = rename ? rename(f) : f.path;
    if (f.isDir) zw.addDirectory(out, f.entry);
    else if (f.entry.dataOffset < 0) skipped.push({ path: f.path, reason: 'damaged local header' });
    else zw.addRaw(out, blob, f.entry, { keepRawName: !rename });
    bytes += f.size; i++;
    if (onProgress && i % 25 === 0) { onProgress({ phase: 'zip', done: i, total: recs.length, current: f.path }); await new Promise((r) => setTimeout(r, 0)); }
  }
  return skipped;
}

export async function buildOriginalZip(blob, model, opts = {}) {
  const recs = opts.records || selectRecords(model, opts);
  const zw = new ZipWriter();
  const skipped = await copyRaw(zw, blob, recs, opts);
  return { blob: zw.finish(), count: recs.length, skipped, records: recs };
}

export function buildManifest(model) {
  const rows = model.files.map((f) => ({
    path: f.path, type: f.isDir ? 'directory' : f.isSymlink ? 'symlink' : 'file', size: f.size, compressedSize: f.csize, crc32: f.isDir ? '' : f.crc.toString(16).padStart(8, '0'), sha256: f.sha256,
    category: f.category, mime: f.mime || '', signature: f.sig || '', status: f.status, problems: f.problems, hidden: f.hidden, modified: f.mtime,
    inspection: inspectionStatus(model, f), dependencies: dependenciesOf(model, f),
  }));
  return { generator: 'Cairn IPA Studio', generatedAt: new Date().toISOString(), source: { fileName: model.fileName, fileSize: model.fileSize }, summary: { ...model.stats, allPreserved: rows.every((r) => r.status === 'ok') }, entries: rows };
}
function inspectionStatus(model, f) {
  if (f.isDir) return 'directory';
  const a = model.app;
  if (a && f.path === a.executablePath) return a.encrypted ? 'mach-o: FairPlay-encrypted (compiled-only)' : a.macho && a.macho.ok ? 'mach-o: inspected (compiled-only)' : 'executable: not inspected';
  if (f.status !== 'ok') return 'problem: ' + f.status;
  if (/Mach-O/.test(f.sig)) return 'mach-o: compiled binary (compiled-only)';
  if (f.category === 'source') return 'source file (original, as shipped)';
  return 'preserved';
}
function dependenciesOf(model, f) {
  const a = model.app;
  return a && f.path === a.executablePath && a.macho && a.macho.ok ? [...new Set(a.macho.slices.flatMap((s) => (s.dylibs || []).map((d) => d.name)))] : [];
}
export function manifestCsv(m) {
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  return ['path,type,size,compressedSize,crc32,sha256,category,status'].concat(m.entries.map((e) => [e.path, e.type, e.size, e.compressedSize, e.crc32, e.sha256, e.category, e.status].map(q).join(','))).join('\n') + '\n';
}
export const sha256sums = (m) => m.entries.filter((e) => e.type !== 'directory').map((e) => `${e.sha256 || '?'.repeat(64)}  ${e.path}`).join('\n') + '\n';

/** Re-open an export, and prove every expected entry is present with matching size + CRC (and optionally SHA-256). */
export async function verifyExport(zipBlob, expected, { deep = false, signal, onProgress } = {}) {
  const z = await openZip(zipBlob, { signal });
  const byName = new Map(); for (const e of z.entries) { (byName.get(e.name) || byName.set(e.name, []).get(e.name)).push(e); }
  const result = { expected: expected.length, found: z.entries.length, missing: [], mismatched: [], verified: 0, deep };
  let i = 0;
  for (const f of expected) {
    const cand = (byName.get(f.path) || []).shift();
    if (!cand) { result.missing.push(f.path); continue; }
    if (!f.isDir && (cand.usize !== f.size || cand.crc !== f.crc)) { result.mismatched.push(f.path); continue; }
    if (deep && !f.isDir && f.sha256) {
      const sha = new Sha256(); await readEntry(zipBlob, cand, { signal, onChunk: (c) => sha.update(c) });
      if (sha.hex() !== f.sha256) { result.mismatched.push(f.path + ' (sha256)'); continue; }
    }
    result.verified++;
    if (onProgress && ++i % 50 === 0) { onProgress({ done: i, total: expected.length }); await new Promise((r) => setTimeout(r, 0)); }
  }
  result.ok = !result.missing.length && !result.mismatched.length && result.found === result.expected;
  return result;
}

// ---------- Reconstruction workspace ----------
const CAT_DIR = { image: 'Resources/Images', font: 'Resources/Fonts', audio: 'Resources/Audio', video: 'Resources/Video', ui: 'Resources/Interface', config: 'Resources/Configuration', localization: 'Resources/Localization', other: 'Resources/Other', headers: 'Headers', symbols: 'Symbols', source: 'Source', signing: 'Signing', framework: 'Embedded/Frameworks', extension: 'Embedded/PlugIns', executable: 'Binaries' };
const sanitize = (s) => s.replace(/[^A-Za-z0-9._-]+/g, '_') || 'App';
function projectRel(f, appDir) { return f.path.startsWith(appDir) ? f.path.slice(appDir.length) : f.path; }
function hex24(str) { let h = 0x811c9dc5, o = ''; for (let k = 0; k < 3; k++) { for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i) + k; h = Math.imul(h, 16777619) >>> 0; } o += h.toString(16).padStart(8, '0'); } return o.toUpperCase().slice(0, 24); }

export function projectLayout(model) {
  const appDir = model.app ? model.app.appDir : '';
  const map = [];
  for (const f of model.files) {
    if (f.isDir) continue;
    let cat = f.category;
    if (cat === 'executable' || (/Mach-O/.test(f.sig) && cat !== 'framework' && cat !== 'extension')) cat = 'executable';
    const rel = appDir && f.path.startsWith(appDir) ? projectRel(f, appDir) : f.path;
    const isInfo = appDir && f.path === appDir + 'Info.plist';
    const dest = isInfo ? 'Supporting/Info.plist' : `${CAT_DIR[cat] || CAT_DIR.other}/${rel}`;
    map.push({ rec: f, dest, cat });
  }
  return map;
}

function pbxproj(name, topDirs) {
  const id = (s) => hex24(name + s);
  const refs = topDirs.map((d) => ({ d, ref: id('ref' + d), build: id('bf' + d) }));
  return `// !$*UTF8*$!
// GENERATED by Cairn IPA Studio. This is a RESOURCE-ONLY project: the original app's source code is not in an IPA,
// so there are no Swift/Objective-C sources and this project will not build an app. See README_RECONSTRUCTION.md.
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 56;
	objects = {
${refs.map((r) => `		${r.ref} /* ${r.d} */ = {isa = PBXFileReference; lastKnownFileType = folder; name = "${r.d}"; path = "${r.d}"; sourceTree = "<group>"; };`).join('\n')}
${refs.map((r) => `		${r.build} /* ${r.d} in Resources */ = {isa = PBXBuildFile; fileRef = ${r.ref}; };`).join('\n')}
		${id('group')} = {isa = PBXGroup; children = (
${refs.map((r) => `			${r.ref},`).join('\n')}
		); sourceTree = "<group>"; };
		${id('phase')} = {isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = (
${refs.map((r) => `			${r.build},`).join('\n')}
		); runOnlyForDeploymentPostprocessing = 0; };
		${id('target')} = {isa = PBXNativeTarget; buildConfigurationList = ${id('tcl')}; buildPhases = (${id('phase')},); buildRules = (); dependencies = (); name = "${name}"; productName = "${name}"; productType = "com.apple.product-type.application"; };
		${id('cfgd')} = {isa = XCBuildConfiguration; buildSettings = {PRODUCT_NAME = "${name}";}; name = Debug; };
		${id('tcl')} = {isa = XCConfigurationList; buildConfigurations = (${id('cfgd')},); defaultConfigurationName = Debug; };
		${id('pcl')} = {isa = XCConfigurationList; buildConfigurations = (${id('cfgd')},); defaultConfigurationName = Debug; };
		${id('proj')} = {isa = PBXProject; buildConfigurationList = ${id('pcl')}; compatibilityVersion = "Xcode 14.0"; mainGroup = ${id('group')}; projectDirPath = ""; projectRoot = ""; targets = (${id('target')},); };
	};
	rootObject = ${id('proj')};
}
`;
}

export async function buildProjectZip(blob, model, opts = {}) {
  const app = model.app, name = sanitize((app && (app.displayName || app.name)) || model.fileName.replace(/\.[^.]+$/, ''));
  const layout = projectLayout(model);
  const zw = new ZipWriter(); const root = name + '/';
  const skipped = [];
  const origin = [];
  let i = 0;
  for (const m of layout) {
    if (opts.signal && opts.signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
    if (m.rec.entry.dataOffset < 0) { skipped.push({ path: m.rec.path, reason: 'damaged local header' }); continue; }
    zw.addRaw(root + m.dest, blob, m.rec.entry);
    origin.push({ projectPath: m.dest, originalPath: m.rec.path, size: m.rec.size, sha256: m.rec.sha256, component: m.cat, status: m.rec.status, kind: m.cat === 'executable' || m.cat === 'framework' ? 'compiled-binary-or-bundle (no source)' : m.cat === 'source' ? 'original source (as shipped in the IPA)' : 'original resource' });
    if (opts.onProgress && ++i % 25 === 0) { opts.onProgress({ phase: 'zip', done: i, total: layout.length, current: m.rec.path }); await new Promise((r) => setTimeout(r, 0)); }
  }
  const topDirs = [...new Set(origin.map((o) => o.projectPath.split('/')[0]))].sort();
  zw.addBytes(`${root}${name}.xcodeproj/project.pbxproj`, pbxproj(name, topDirs));
  if (app && app.infoPlist) zw.addBytes(`${root}Supporting/Info.plist.readable.xml`, plistDocument(app.infoPlist));
  if (app && app.entitlementsXml) zw.addBytes(`${root}Signing/entitlements.readable.xml`, app.entitlementsXml);
  if (app && app.provisioning && app.provisioning.entitlements) zw.addBytes(`${root}Signing/provisioning-entitlements.readable.xml`, plistDocument(app.provisioning.entitlements));
  const sourceCount = layout.filter((m) => m.cat === 'source').length;
  const unrecoverable = [];
  if (app && app.encrypted) unrecoverable.push('Main executable is FairPlay-encrypted (cryptid=1): its code is not readable until decrypted, which this tool does not do.');
  unrecoverable.push('Swift/Objective-C source code is not stored in an IPA. Compiled executables are shipped as machine code only; nothing here is decompiled, and nothing is AI-generated.');
  if (!sourceCount) unrecoverable.push('No original source files were present in this IPA (Source/ is empty).');
  if (!layout.some((m) => m.cat === 'symbols')) unrecoverable.push('No debug symbols (dSYM) were present.');
  const manifest = { generator: 'Cairn IPA Studio', app: app ? { name: app.displayName, bundleId: app.bundleId, version: app.version, build: app.build } : null, components: Object.fromEntries(Object.entries(model.stats.byCategory).map(([k, v]) => [k, { label: CATEGORY_LABELS[k], ...v }])), unrecoverable, files: origin };
  zw.addBytes(`${root}project.manifest.json`, JSON.stringify(manifest, null, 2));
  zw.addBytes(`${root}README_RECONSTRUCTION.md`, `# ${name} — recovered application workspace\n\nBuilt from \`${model.fileName}\` by Cairn IPA Studio, locally in your browser.\n\n## What this is\nEvery file from the IPA, **byte-for-byte unchanged**, sorted into project-style folders. \`project.manifest.json\` maps each file back to its original IPA path with a SHA-256.\n\n| Folder | Contents |\n|---|---|\n${Object.entries(CAT_DIR).map(([c, d]) => `| \`${d}/\` | ${CATEGORY_LABELS[c]} (${(model.stats.byCategory[c] || { files: 0 }).files} files) |`).join('\n')}\n| \`Supporting/\` | Original Info.plist (+ a readable XML rendering, marked as converted) |\n\n## What this is NOT\n${unrecoverable.map((u) => `- ${u}`).join('\n')}\n\nThe \`.xcodeproj\` is a resource-only container so you can browse the recovered assets in Xcode. It has no sources and will not compile into a working app.\n`);
  return { blob: zw.finish(), count: origin.length, skipped, name };
}

export async function buildResourcesZip(blob, model, opts = {}) {
  const keep = new Set(['source', 'headers', 'image', 'font', 'audio', 'video', 'ui', 'config', 'localization', 'symbols']);
  const recs = model.files.filter((f) => !f.isDir && keep.has(f.category) && !/Mach-O/.test(f.sig));
  const appDir = model.app ? model.app.appDir : '';
  const zw = new ZipWriter(); const skipped = [];
  for (const f of recs) {
    if (f.entry.dataOffset < 0) { skipped.push({ path: f.path, reason: 'damaged local header' }); continue; }
    zw.addRaw(appDir && f.path.startsWith(appDir) ? f.path.slice(appDir.length) : f.path, blob, f.entry);
  }
  const src = recs.filter((f) => f.category === 'source').length;
  zw.addBytes('_README.txt', `Available source files and resources extracted unchanged from ${model.fileName}.\nOriginal source files present in the IPA: ${src}${src ? '' : ' (none - IPAs normally contain compiled code only)'}.\nCompiled binaries, frameworks and signing data are excluded here; see ORIGINAL_IPA_CONTENTS.zip for everything.\n`);
  return { blob: zw.finish(), count: recs.length, skipped };
}

export async function buildReportZip(blob, model, opts = {}) {
  const zw = new ZipWriter(); const app = model.app; const manifest = buildManifest(model);
  const strip = (a) => a && JSON.parse(JSON.stringify(a, (k, v) => (k === 'entry' || k === 'sampleSymbols' && false ? undefined : v instanceof Uint8Array ? `<${v.length} bytes>` : v)));
  zw.addBytes('analysis.json', JSON.stringify({ file: { name: model.fileName, size: model.fileSize }, stats: model.stats, warnings: model.warnings, zip: { entries: model.zip.entries.length, zip64: model.zip.zip64, comment: model.zip.comment }, app: strip(app) }, null, 2));
  zw.addBytes('manifest.json', JSON.stringify(manifest, null, 2));
  zw.addBytes('manifest.csv', manifestCsv(manifest));
  zw.addBytes('SHA256SUMS.txt', sha256sums(manifest));
  if (app && app.infoPlist) zw.addBytes('Info.plist.readable.xml', plistDocument(app.infoPlist));
  if (app && app.entitlementsXml) zw.addBytes('entitlements.xml', app.entitlementsXml);
  if (app && app.icon) { try { const r = model.files.find((f) => f.path === app.icon); const { bytes } = await readFileBytes(blob, r, 8 << 20); zw.addBytes('icon.png', await cgbiToPng(bytes)); } catch { /* icon is optional */ } }
  zw.addBytes('REPORT.md', reportMarkdown(model));
  return { blob: zw.finish(), count: 8 };
}

export function reportMarkdown(model) {
  const a = model.app, s = model.stats, L = [];
  L.push(`# Analysis report — ${model.fileName}`, '', `Generated locally by Cairn IPA Studio on ${new Date().toISOString()}. Nothing was uploaded.`, '');
  L.push('## Archive', `- Size: ${formatBytes(model.fileSize)}  ·  Entries: ${s.entries} (${s.files} files, ${s.folders} folders)  ·  Uncompressed: ${formatBytes(s.bytes)}`, `- Entries with problems: ${s.problems}`, ...model.warnings.map((w) => `- ⚠ ${w}`), '');
  if (a) {
    L.push('## Application', `- Name: ${a.displayName} (${a.name})`, `- Bundle ID: ${a.bundleId}`, `- Version: ${a.version} (${a.build})`, `- Minimum iOS: ${a.minOS}`, `- Devices: ${a.deviceFamilies.join(', ') || 'n/a'}`, `- Executable: ${a.executable} — ${(a.architectures || []).join(', ') || 'not inspected'}${a.encrypted ? ' — **FairPlay encrypted**' : ''}`, `- URL schemes: ${a.urlSchemes.join(', ') || 'none'}`, `- Frameworks: ${a.frameworks.length}  ·  Extensions: ${a.extensions.length}`, `- Code signature: ${a.codeSigned ? 'present' : 'not found'}${a.provisioning && a.provisioning.kind ? `  ·  Provisioning: ${a.provisioning.kind}` : ''}`, '');
    if (a.permissions.length) L.push('## Declared privacy permissions', ...a.permissions.map((p) => `- ${p.key}: ${p.reason}`), '');
  }
  L.push('## Components', ...Object.entries(s.byCategory).map(([k, v]) => `- ${CATEGORY_LABELS[k] || k}: ${v.files} files, ${formatBytes(v.bytes)}`), '', '## Limits', '- Compiled code is never converted back to Swift/Objective-C. Encrypted or compiled-only components are labelled as such.', '');
  return L.join('\n');
}
