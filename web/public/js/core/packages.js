// Package-manager analysis: detects and parses CocoaPods (Podfile.lock),
// Carthage (Cartfile.resolved) and Swift Package Manager (Package.resolved)
// manifests that ship inside an IPA, plus the Pods/ framework structure.
import { td } from './util.js';

export const PKG_LIMITS = { maxManifestBytes: 2 << 20 };

function basename(p) { return p.replace(/^.*\//, ''); }

export const MANIFEST_NAMES = {
  'Podfile.lock': 'cocoapods', 'Podfile': 'cocoapods',
  'Cartfile.resolved': 'carthage', 'Cartfile': 'carthage',
  'Package.resolved': 'spm', 'Package.swift': 'spm',
};

export function parsePodfileLock(text) {
  const pods = [];
  let inPods = false;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (/^(PODS|DEPENDENCIES|SPEC REPOS|SPEC CHECKSUMS|CHECKOUT OPTIONS|PLUGIN PODS):$/.test(t)) { inPods = t === 'PODS:'; continue; }
    if (inPods && /^ {2}- /.test(line)) {
      const m = t.slice(2).match(/^(.+?)\s*\(([^)]+)\)/);
      if (m) pods.push({ name: m[1].split('/')[0], spec: m[1], version: m[2] });
    }
  }
  const uniq = [];
  const seen = new Set();
  for (const p of pods) { if (!seen.has(p.name)) { seen.add(p.name); uniq.push(p); } }
  return { ok: pods.length > 0, pods: uniq, count: uniq.length };
}

export function parseCartfile(text) {
  const pins = [];
  const re = /(?:github|binary|git)"?\s*"?\(?([^"\s)]+)[\"\s)]*(?:,\s*)?"?([0-9][^"\s)]*)?/g;
  let m;
  while ((m = re.exec(text))) {
    const repo = m[1].replace(/^https?:\/\//, '').replace(/\.git$/, '');
    pins.push({ name: repo, version: m[2] || '(unpinned)' });
  }
  return { ok: pins.length > 0, pods: pins, count: pins.length };
}

export function parsePackageResolved(text) {
  try {
    const j = JSON.parse(text);
    const pins = [];
    if (j.pins && Array.isArray(j.pins)) {
      for (const p of j.pins) {
        const identity = p.identity || (p.state && p.state.name) || '?';
        const version = p.state && (p.state.version || p.state.revision || p.state.branch) || '?';
        pins.push({ name: identity, version: String(version) + (p.state && p.state.revision && !p.state.version ? ' (revision)' : '') });
      }
    } else if (j.object && Array.isArray(j.object.pins)) { // v1 format
      for (const p of j.object.pins) {
        pins.push({ name: p.packageName || p.identity || '?', version: p.state && (p.state.version || p.state.revision) || '?' });
      }
    }
    return { ok: pins.length > 0, pods: pins, count: pins.length };
  } catch { return { ok: false, pods: [], count: 0, error: 'Not valid JSON.' }; }
}

/** Scan the IPA model for package manifests + Pods/Carthage structure. */
export async function analysePackages(model, getBytes) {
  const found = [];
  for (const f of model.files) {
    if (f.isDir) continue;
    const b = basename(f.path);
    if (!MANIFEST_NAMES[b]) continue;
    const kind = MANIFEST_NAMES[b];
    let text = '';
    try { const { bytes } = await getBytes(f, PKG_LIMITS.maxManifestBytes); text = td.decode(bytes); } catch { continue; }
    let parsed = { ok: false, pods: [], count: 0 };
    if (b === 'Podfile.lock') parsed = parsePodfileLock(text);
    else if (b === 'Cartfile.resolved' || b === 'Cartfile') parsed = parseCartfile(text);
    else if (b === 'Package.resolved') parsed = parsePackageResolved(text);
    else if (b === 'Podfile') parsed = { ok: /target\s+['"]/.test(text), pods: [], count: 0, note: 'Podfile (specification, not resolved versions)' };
    else if (b === 'Package.swift') parsed = { ok: /\.package\(/.test(text), pods: [], count: 0, note: 'Package.swift (specification, not resolved versions)' };
    found.push({ path: f.path, kind, manager: kind, ...parsed });
  }
  const podsDirs = model.files.filter((f) => f.isDir && /(^|\/)Pods(\/|$)/.test(f.path)).length;
  const carthageBins = model.files.filter((f) => /(^|\/)Carthage\/Build\//.test(f.path)).length;
  const spmBuild = model.files.filter((f) => /(^|\/)\.build\//.test(f.path)).length;
  const frameworks = [...new Set(model.files.filter((f) => !f.isDir && /\/Frameworks\/[^/]+\.framework\//.test(f.path)).map((f) => f.path.match(/\/Frameworks\/([^/]+\.framework)\//)[1]))];
  return {
    ok: true,
    manifests: found,
    podsDirEntries: podsDirs,
    carthageBuildEntries: carthageBins,
    spmBuildEntries: spmBuild,
    embeddedFrameworks: frameworks,
    summary: {
      cocoapods: found.some((x) => x.kind === 'cocoapods'),
      carthage: found.some((x) => x.kind === 'carthage'),
      spm: found.some((x) => x.kind === 'spm'),
    },
  };
}
