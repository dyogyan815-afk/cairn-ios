// IPA scanner: opens the archive (read-only), hashes every entry, builds the file model and app metadata.
import { AppError, extOf, baseName, formatBytes, td } from './util.js';
import { openZip, readEntry, entryBytes, entryToBlob } from './zip-reader.js';
import { Sha256 } from './sha256.js';
import { classify, mimeOf, sniff } from './classify.js';
import { parsePlist } from './plist.js';
import { parseMachO, isMachO } from './macho.js';

const FULL_EXEC_LIMIT = 160 * 1024 * 1024;

export async function scanIPA(blob, { onProgress = () => {}, signal, hash = true } = {}) {
  const zip = await openZip(blob, { signal });
  if (!zip.entries.length) throw new AppError('empty', 'The archive contains no entries.');
  const files = [];
  const totalBytes = zip.entries.reduce((s, e) => s + (e.isDir ? 0 : e.usize), 0) || 1;
  let done = 0;
  for (const e of zip.entries) {
    if (signal && signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
    const path = e.name;
    const rec = {
      index: e.index, path, name: baseName(path), ext: extOf(path), isDir: e.isDir, isSymlink: e.isSymlink,
      hidden: baseName(path).startsWith('.'), size: e.usize, csize: e.csize, method: e.method, crc: e.crc, mtime: dosToDate(e.date, e.time),
      mode: e.mode, category: classify(path, e.isDir), mime: mimeOf(path), sig: '', sha256: '', status: 'ok', problems: e.problems.slice(), entry: e,
    };
    if (!e.isDir) {
      const blocked = e.problems.some((p) => ['encrypted-entry', 'unsupported-method', 'local-header-missing', 'local-header-truncated'].includes(p));
      if (blocked) rec.status = e.encrypted ? 'encrypted-in-zip' : e.problems.includes('unsupported-method') ? 'unsupported-compression' : 'damaged';
      else {
        try {
          const sha = hash ? new Sha256() : null; let first = null;
          const r = await readEntry(blob, e, { signal, onChunk: (c) => { if (!first) first = c.slice(0, 64); if (sha) sha.update(c); } });
          if (hash) rec.sha256 = sha.hex();
          if (r.size !== e.usize) { rec.status = 'size-mismatch'; rec.problems.push(`declared ${e.usize} bytes, got ${r.size}`); }
          else if (r.crc !== e.crc) { rec.status = 'crc-mismatch'; rec.problems.push('CRC-32 mismatch'); }
          const s = first ? sniff(first) : { sig: '' };
          rec.sig = s.sig; rec.cgbi = !!s.cgbi;
        } catch (err) {
          if (err.code === 'aborted') throw err;
          rec.status = 'unreadable'; rec.problems.push(String(err.message || err));
        }
      }
      done += e.usize;
    }
    files.push(rec);
    onProgress({ phase: 'hash', done, total: totalBytes, current: path, files: files.length, totalFiles: zip.entries.length });
    if (files.length % 40 === 0) await new Promise((r) => setTimeout(r, 0));
  }
  const model = { fileName: blob.name || 'app.ipa', fileSize: blob.size, zip, files, stats: stats(files), app: null, warnings: zip.warnings.slice() };
  model.app = await inspectApp(blob, model, signal);
  if (!model.app) model.warnings.push('No Payload/<Name>.app bundle was found. The archive is still fully listed, extractable and exportable.');
  return model;
}

function dosToDate(d, t) { try { return new Date(((d >> 9) & 127) + 1980, ((d >> 5) & 15) - 1, d & 31, (t >> 11) & 31, (t >> 5) & 63, (t & 31) * 2).toISOString(); } catch { return null; } }

export function stats(files) {
  const f = files.filter((x) => !x.isDir), dirs = new Set();
  for (const x of files) {
    const parts = x.path.replace(/\/$/, '').split('/');
    const n = x.isDir ? parts.length : parts.length - 1;
    for (let i = 1; i <= n; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  const byCat = {};
  for (const x of f) { const c = (byCat[x.category] ||= { files: 0, bytes: 0 }); c.files++; c.bytes += x.size; }
  return { files: f.length, folders: dirs.size, entries: files.length, bytes: f.reduce((s, x) => s + x.size, 0), compressed: f.reduce((s, x) => s + x.csize, 0), problems: files.filter((x) => x.status !== 'ok').length, byCategory: byCat };
}

const find = (files, path) => files.find((f) => f.path === path && !f.isDir);

async function readPlistAt(blob, rec, max = 4 << 20) {
  const { bytes } = await entryBytes(blob, rec.entry, max);
  return parsePlist(bytes);
}

export async function inspectApp(blob, model, signal) {
  const files = model.files;
  const info = files.find((f) => !f.isDir && /^Payload\/[^/]+\.app\/Info\.plist$/.test(f.path));
  if (!info) return null;
  const appDir = info.path.replace(/Info\.plist$/, '');
  const app = { appDir, appFolder: appDir.split('/')[1], warnings: [] };
  let P;
  try { const r = await readPlistAt(blob, info); P = r.value; app.infoPlistFormat = r.format; app.infoPlist = P; } catch (e) { app.warnings.push('Info.plist could not be decoded: ' + e.message); return app; }
  const g = (k) => P[k];
  Object.assign(app, {
    name: g('CFBundleName') || '', displayName: g('CFBundleDisplayName') || g('CFBundleName') || '', bundleId: g('CFBundleIdentifier') || '', version: g('CFBundleShortVersionString') || '', build: g('CFBundleVersion') || '',
    minOS: g('MinimumOSVersion') || '', executable: g('CFBundleExecutable') || '', sdk: g('DTSDKName') || '', platformVersion: g('DTPlatformVersion') || '', xcode: g('DTXcode') || '',
    deviceFamilies: (g('UIDeviceFamily') || []).map((n) => ({ 1: 'iPhone/iPod', 2: 'iPad', 3: 'Apple TV', 4: 'Apple Watch', 7: 'Apple Vision' }[n] || `family ${n}`)),
    requiredCaps: g('UIRequiredDeviceCapabilities') || [], bgModes: g('UIBackgroundModes') || [],
    urlSchemes: (g('CFBundleURLTypes') || []).flatMap((t) => (t.CFBundleURLSchemes || [])),
    queriedSchemes: g('LSApplicationQueriesSchemes') || [],
    permissions: Object.keys(P).filter((k) => /UsageDescription$/.test(k) || /^NS.*Usage/.test(k)).map((k) => ({ key: k, reason: String(P[k]) })),
    ats: g('NSAppTransportSecurity') || null,
  });
  // Executable + Mach-O
  const exec = app.executable && find(files, appDir + app.executable);
  if (exec) {
    app.executablePath = exec.path; app.executableSize = exec.size;
    try {
      const partial = exec.size > FULL_EXEC_LIMIT;
      const { bytes } = await entryBytes(blob, exec.entry, partial ? 8 << 20 : exec.size, signal);
      if (isMachO(bytes)) { app.macho = parseMachO(bytes); app.machoPartial = partial; if (partial) app.warnings.push(`Executable is ${formatBytes(exec.size)}; only the first 8 MB were inspected (code signature/entitlements/symbol tables may be unavailable).`); }
      else app.warnings.push('The declared executable is not a Mach-O file.');
    } catch (e) { app.warnings.push('Executable inspection failed: ' + e.message); }
  } else if (app.executable) app.warnings.push(`Declared executable "${app.executable}" was not found in the bundle.`);
  const slices = app.macho && app.macho.ok ? app.macho.slices.filter((s) => s.ok) : [];
  app.architectures = [...new Set(slices.map((s) => s.arch))];
  app.encrypted = slices.some((s) => s.encrypted);
  const ent = slices.find((s) => s.entitlementsXml);
  if (ent) { app.entitlementsXml = ent.entitlementsXml; try { app.entitlements = parsePlist(new TextEncoder().encode(ent.entitlementsXml)).value; } catch { /* keep xml only */ } }
  app.codeSigned = slices.some((s) => s.codeSignature);
  app.signatureIdentifier = slices.map((s) => s.signature && s.signature.identifier).find(Boolean) || '';
  app.teamIdFromSignature = slices.map((s) => s.signature && s.signature.teamId).find(Boolean) || '';
  // Provisioning profile
  const prov = find(files, appDir + 'embedded.mobileprovision');
  if (prov) {
    try {
      const { bytes } = await entryBytes(blob, prov.entry, 2 << 20);
      const txt = new TextDecoder('latin1').decode(bytes); const a = txt.indexOf('<?xml'), b = txt.indexOf('</plist>');
      if (a >= 0 && b > a) {
        const pp = parsePlist(new TextEncoder().encode(txt.slice(a, b + 8))).value;
        app.provisioning = { name: pp.Name, appIdName: pp.AppIDName, teamName: pp.TeamName, teamIds: pp.TeamIdentifier, uuid: pp.UUID, created: pp.CreationDate && pp.CreationDate.$date, expires: pp.ExpirationDate && pp.ExpirationDate.$date, devices: pp.ProvisionedDevices ? pp.ProvisionedDevices.length : 0, allDevices: !!pp.ProvisionsAllDevices, getTaskAllow: pp.Entitlements && pp.Entitlements['get-task-allow'], apsEnvironment: pp.Entitlements && pp.Entitlements['aps-environment'], entitlements: pp.Entitlements, kind: pp.ProvisionsAllDevices ? 'Enterprise' : pp.ProvisionedDevices ? (pp.Entitlements && pp.Entitlements['get-task-allow'] ? 'Development' : 'Ad Hoc') : 'App Store' };
      } else app.provisioning = { error: 'Profile present but no readable plist was found inside it.' };
    } catch (e) { app.provisioning = { error: e.message }; }
  }
  // Frameworks, extensions
  app.frameworks = await bundles(blob, files, appDir + 'Frameworks/', /\.framework$/);
  app.extensions = await bundles(blob, files, appDir + 'PlugIns/', /\.appex$/, true);
  app.watchApps = files.filter((f) => f.isDir && new RegExp('^' + escapeRe(appDir) + 'Watch/[^/]+\\.app/$').test(f.path)).map((f) => f.path);
  app.hasCodeResources = !!find(files, appDir + '_CodeSignature/CodeResources');
  app.icon = findIcon(files, appDir, P);
  return app;
}
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

async function bundles(blob, files, prefix, re, ext) {
  const names = new Set();
  for (const f of files) if (f.path.startsWith(prefix)) { const n = f.path.slice(prefix.length).split('/')[0]; if (re.test(n)) names.add(n); }
  const out = [];
  for (const n of [...names].sort()) {
    const rec = { name: n, path: prefix + n + '/', files: files.filter((f) => !f.isDir && f.path.startsWith(prefix + n + '/')).length };
    const ip = find(files, prefix + n + '/Info.plist');
    if (ip) { try { const P = (await readPlistAt(blob, ip)).value; rec.bundleId = P.CFBundleIdentifier; rec.version = P.CFBundleShortVersionString; rec.executable = P.CFBundleExecutable; if (ext && P.NSExtension) rec.extensionPoint = P.NSExtension.NSExtensionPointIdentifier; } catch { /* ignore */ } }
    out.push(rec);
  }
  return out;
}

function findIcon(files, appDir, P) {
  const names = new Set();
  const add = (v) => { if (typeof v === 'string') names.add(v); };
  const icons = P.CFBundleIcons && P.CFBundleIcons.CFBundlePrimaryIcon;
  if (icons) { (icons.CFBundleIconFiles || []).forEach(add); add(icons.CFBundleIconName); }
  (P.CFBundleIconFiles || []).forEach(add); add(P.CFBundleIconFile);
  const pngs = files.filter((f) => !f.isDir && f.path.startsWith(appDir) && !f.path.slice(appDir.length).includes('/') && /\.png$/i.test(f.path));
  let cands = pngs.filter((f) => [...names].some((n) => f.name.startsWith(n)));
  if (!cands.length) cands = pngs.filter((f) => /^AppIcon/i.test(f.name));
  cands.sort((a, b) => b.size - a.size);
  return cands[0] ? cands[0].path : null;
}

export function buildTree(files) {
  const root = { name: '', path: '', isDir: true, children: new Map(), size: 0, count: 0 };
  for (const f of files) {
    const parts = f.path.replace(/\/$/, '').split('/'); let n = root;
    for (let i = 0; i < parts.length; i++) {
      const last = i === parts.length - 1; const key = parts[i] + (last && !f.isDir ? '' : '/');
      let c = n.children.get(key);
      if (!c) { c = { name: parts[i], path: parts.slice(0, i + 1).join('/') + (last && !f.isDir ? '' : '/'), isDir: !last || f.isDir, children: new Map(), size: 0, count: 0, rec: null }; n.children.set(key, c); }
      if (last) { c.rec = f; if (!f.isDir) { c.size = f.size; c.count = 1; } }
      n = c;
    }
  }
  const total = (n) => { if (!n.isDir) return; let s = 0, c = 0; for (const ch of n.children.values()) { total(ch); s += ch.size; c += ch.count; } n.size = s; n.count = c; };
  total(root);
  return root;
}

export async function readFileBytes(blob, rec, max = 2 << 20) { return entryBytes(blob, rec.entry, max); }
export { entryToBlob };
