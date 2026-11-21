import { scanIPA, buildTree, readFileBytes } from '../core/ipa.js';
import { DOWNLOADS, buildOriginalZip, buildProjectZip, buildResourcesZip, buildReportZip, buildManifest, manifestCsv, sha256sums, verifyExport, selectRecords, reportMarkdown } from '../core/exporter.js';
import { CATEGORY_LABELS, TEXT_EXT, IMAGE_EXT, looksText, sniff } from '../core/classify.js';
import { parsePlist, plistDocument } from '../core/plist.js';
import { parseMachO, isMachO, objcNames } from '../core/macho.js';
import { cgbiToPng, isCgBI } from '../core/cgbi.js';
import { carveEntry } from '../core/carve.js';
import { ZipWriter } from '../core/zip-writer.js';
import { formatBytes, toHex, throttle } from '../core/util.js';
import { runToolchain, TOOLS } from '../core/toolchain.js';
import { disasm, DISASM_LIMITS } from '../core/disasm.js';
import { readRecBytes } from '../core/pkg-utils.js';

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const TABS = [['home', 'Home'], ['inspect', 'IPA Inspector'], ['explorer', 'File Explorer'], ['extract', 'Extraction'], ['downloads', 'ZIP Downloads'], ['security', 'Security Analysis'], ['tools', 'Toolchain'], ['settings', 'Settings']];
const S = { tab: 'home', sessions: [], cur: null, busy: null, settings: load('cairn.settings', { history: false, deep: false }), history: load('cairn.history', []), urls: [] };
function load(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }
function save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage may be blocked */ } }
function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 3200); }
const cur = () => S.cur;
// Native app reports where an export landed (and if a save failed) — show it once.
if (typeof window.addEventListener === 'function') {
  window.addEventListener('cairnsaveok', (e) => {
    toast(`📁 Saved in phone: Files app → On My iPhone → Cairn → ${e.detail?.file || 'Exports'}`);
    // Refresh the "Phone files" card if it is on screen (reuses its Refresh path).
    const rf = document.getElementById('pf-refresh');
    if (rf && window.__cairnFiles) rf.click();
  });
  window.addEventListener('cairnsavefail', (e) => toast(`⚠ Save failed: ${e.detail?.message || 'unknown error'}`));
  window.addEventListener('cairnsaveprogress', (e) => toast(`📲 Saving to phone: ${e.detail?.pct ?? 0}% …`));
}

// ---------- navigation ----------
function renderNav() { $('#nav').innerHTML = TABS.map(([k, l]) => `<button data-t="${k}" class="${S.tab === k ? 'on' : ''}">${l}</button>`).join(''); }
$('#nav').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) go(b.dataset.t); });
function go(t) { S.tab = t; renderNav(); closePreview(); render(); window.scrollTo(0, 0); }
function renderSessionSel() {
  const sel = $('#sessionSel'); sel.hidden = S.sessions.length < 2;
  sel.innerHTML = S.sessions.map((s) => `<option value="${s.id}" ${s === S.cur ? 'selected' : ''}>${esc(s.file.name)}</option>`).join('');
}
$('#sessionSel').addEventListener('change', (e) => { S.cur = S.sessions.find((s) => String(s.id) === e.target.value); render(); });

function render() {
  const v = $('#view');
  const needs = ['inspect', 'explorer', 'extract', 'downloads', 'security', 'tools'].includes(S.tab);
  if (needs && !cur()) { v.innerHTML = `<div class="card"><h2>No IPA open</h2><p class="note">Open an IPA from Home first.</p><button class="btn" data-go="home">Go to Home</button></div>`; return; }
  ({ home: viewHome, inspect: viewInspect, explorer: viewExplorer, extract: viewExtract, downloads: viewDownloads, security: viewSecurity, tools: viewTools, settings: viewSettings })[S.tab](v);
}
document.addEventListener('click', (e) => { const g = e.target.closest('[data-go]'); if (g) go(g.dataset.go); });

// ---------- home / upload ----------
function viewHome(v) {
  v.innerHTML = `
  <div class="drop" id="drop"><h1>Open an IPA</h1><p>Drop an <b>.ipa</b> here, or choose it from the Files app / iCloud Drive. A <b>.zip</b> containing a <code>Payload/</code> folder works too.<br>Everything stays on this device.</p>
  <label class="btn">Browse Files<input id="file" type="file" multiple hidden></label>
  <p class="note">Your original file is only ever read, never changed. Very large IPAs depend on your device's memory; tested up to the sizes shown in the README.</p></div>
  <div id="progress"></div>
  ${S.sessions.length ? `<div class="card"><h3>Open sessions</h3>${S.sessions.map((s) => `<div class="row"><b>${esc(s.file.name)}</b><span class="note">${formatBytes(s.file.size)} · ${s.model.stats.files} files</span><button class="btn sm alt" data-open="${s.id}">Open</button><button class="btn sm alt" data-close="${s.id}">Close</button></div>`).join('')}</div>` : ''}
  <div class="card"><h3>Recently inspected ${S.settings.history ? '' : '<span class="tag">off</span>'}</h3>${S.settings.history ? (S.history.length ? S.history.map((h) => `<div class="note">${esc(h.name)} · ${formatBytes(h.size)} · ${esc(h.app || '')} · ${new Date(h.at).toLocaleString()}</div>`).join('') + '<p class="note">Only names and dates are stored, on this device. Files are never stored.</p>' : '<p class="note">Nothing yet.</p>') : '<p class="note">History is off. Enable it in Settings if you want a local list of inspected files (names only).</p>'}</div>`;
  const drop = $('#drop'); const pick = $('#file');
  pick.onchange = () => { openFiles([...pick.files]); pick.value = ''; };
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => openFiles([...e.dataTransfer.files]));
  v.querySelectorAll('[data-open]').forEach((b) => (b.onclick = () => { S.cur = S.sessions.find((s) => String(s.id) === b.dataset.open); go('inspect'); }));
  v.querySelectorAll('[data-close]').forEach((b) => (b.onclick = () => { S.sessions = S.sessions.filter((s) => String(s.id) !== b.dataset.close); if (S.cur && String(S.cur.id) === b.dataset.close) S.cur = S.sessions[0] || null; renderSessionSel(); render(); }));
  if (S.busy) showProgress(S.busy.last);
}
function showProgress(p) {
  const el = $('#progress'); if (!el || !S.busy) return;
  const pct = p && p.total ? Math.min(100, (p.done / p.total) * 100) : 0;
  el.innerHTML = `<div class="card"><h3>${esc(S.busy.label)}</h3><div class="bar"><i style="width:${pct}%"></i></div><p class="note">${p ? esc(p.current || '') : ''} ${p && p.files ? `(${p.files}/${p.totalFiles})` : ''}</p><button class="btn sm alt" id="cancel">Cancel</button></div>`;
  $('#cancel').onclick = () => S.busy.ctl.abort();
}
async function openFiles(files) {
  for (const file of files) {
    if (!/\.(ipa|zip)$/i.test(file.name) && !confirm(`"${file.name}" doesn't end in .ipa or .zip. Try to open it as an archive anyway?`)) continue;
    const ctl = new AbortController(); S.busy = { label: `Reading ${file.name}…`, ctl, last: null };
    go('home');
    try {
      const model = await scanIPA(file, { signal: ctl.signal, onProgress: (p) => { S.busy.last = p; showProgress(p); } });
      const s = { id: Date.now() + Math.random(), file, model, tree: buildTree(model.files), selected: new Set(), prefixes: new Set(), expanded: new Set(['Payload/']), q: '', sort: 'name', results: {} };
      S.sessions.push(s); S.cur = s; renderSessionSel();
      s.tc = { state: 'running', progress: { done: 0, current: 'starting' }, result: null };
      runToolchainAuto(s); // full analysis pipeline, in background
      if (S.settings.history) { S.history = [{ name: file.name, size: file.size, app: model.app && model.app.bundleId, at: Date.now() }, ...S.history].slice(0, 20); save('cairn.history', S.history); }
      S.busy = null; go('inspect'); toast(`Opened ${file.name}`);
    } catch (e) {
      S.busy = null; go('home');
      $('#progress').innerHTML = `<div class="card"><h3 class="err">${e.code === 'aborted' ? 'Cancelled' : 'Could not open this file'}</h3><p>${esc(e.message)}</p><p class="note">You can pick another file or try again. Nothing was changed.</p></div>`;
    }
  }
}

if (typeof window !== 'undefined') window.__cairnOpenFiles = openFiles;

// ---------- inspector ----------
const dl = (o) => `<dl class="kv">${Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && v !== null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
async function viewInspect(v) {
  const m = cur().model, a = m.app, st = m.stats;
  v.innerHTML = `<div class="card"><div class="row">${a ? `<img class="icon" id="appicon" alt="">` : ''}<div><h2 style="font-size:20px">${esc(a ? a.displayName : cur().file.name)}</h2><div class="note">${esc(a ? a.bundleId : 'No app bundle found')}</div></div></div>
  <div class="grid" style="margin-top:10px"><div class="stat"><b>${st.files}</b><span>files</span></div><div class="stat"><b>${st.folders}</b><span>folders</span></div><div class="stat"><b>${formatBytes(st.bytes)}</b><span>extracted size</span></div><div class="stat"><b class="${st.problems ? 'err' : 'ok'}">${st.problems ? st.problems + ' flagged' : 'All OK'}</b><span>entry integrity (CRC)</span></div></div>
  ${m.warnings.map((w) => `<p class="note">⚠ ${esc(w)}</p>`).join('')}</div>
  ${a ? `<div class="card"><h3>Application</h3>${dl({ Name: esc(a.name), 'Display name': esc(a.displayName), 'Bundle ID': esc(a.bundleId), Version: esc(a.version), Build: esc(a.build), 'Minimum iOS': esc(a.minOS), Devices: esc(a.deviceFamilies.join(', ')), Executable: esc(a.executable) + (a.executableSize ? ` (${formatBytes(a.executableSize)})` : ''), Architectures: esc((a.architectures || []).join(', ') || 'not inspected'), 'URL schemes': esc(a.urlSchemes.join(', ') || 'none'), 'Info.plist': a.infoPlistFormat + ' format', SDK: esc(a.sdk), Xcode: esc(a.xcode) })}</div>
  <div class="card"><h3>Privacy permissions (${a.permissions.length})</h3>${a.permissions.length ? `<table>${a.permissions.map((p) => `<tr><td>${esc(p.key)}</td><td>${esc(p.reason)}</td></tr>`).join('')}</table>` : '<span class="note">None declared.</span>'}</div>
  <div class="card"><h3>Frameworks (${a.frameworks.length})</h3>${a.frameworks.map((f) => `<div>${esc(f.name)} <span class="note">${esc(f.bundleId || '')} ${esc(f.version || '')}</span></div>`).join('') || '<span class="note">None embedded.</span>'}</div>
  <div class="card"><h3>App extensions (${a.extensions.length})</h3>${a.extensions.map((f) => `<div>${esc(f.name)} <span class="note">${esc(f.bundleId || '')} ${esc(f.extensionPoint || '')}</span></div>`).join('') || '<span class="note">None.</span>'}</div>
  <div class="card"><h3>Signing</h3>${dl({ 'Code signature': a.codeSigned ? 'present' : 'not found', 'Signature identifier': esc(a.signatureIdentifier), 'Team (signature)': esc(a.teamIdFromSignature), Provisioning: a.provisioning ? esc(a.provisioning.error || `${a.provisioning.kind} · ${a.provisioning.name} · ${a.provisioning.teamName || ''}`) : 'no embedded profile', Expires: a.provisioning && esc(a.provisioning.expires) })}${a.entitlementsXml ? `<details><summary>Entitlements</summary><pre>${esc(a.entitlementsXml)}</pre></details>` : '<p class="note">No readable entitlements.</p>'}</div>` : ''}
  <div class="card"><h3>Components</h3><table>${Object.entries(st.byCategory).map(([k, c]) => `<tr><td>${esc(CATEGORY_LABELS[k] || k)}</td><td>${c.files}</td><td>${formatBytes(c.bytes)}</td></tr>`).join('')}</table></div>
  <div class="row"><button class="btn" data-go="explorer">Open File Explorer</button><button class="btn alt" data-go="downloads">Downloads</button><button class="btn alt" data-go="tools">Toolchain</button></div>`;
  if (a && a.icon) { try { const r = m.files.find((f) => f.path === a.icon); const { bytes } = await readFileBytes(cur().file, r, 8 << 20); const png = await cgbiToPng(bytes); const u = URL.createObjectURL(new Blob([png], { type: 'image/png' })); S.urls.push(u); const im = $('#appicon'); if (im) im.src = u; } catch { /* icon is optional */ } }
}

// ---------- explorer ----------
function viewExplorer(v) {
  const s = cur();
  v.innerHTML = `<div class="card"><div class="row"><input type="search" id="q" placeholder="Search name or .ext" value="${esc(s.q)}" style="flex:1;min-width:150px"><select id="sort"><option value="name">Sort: name</option><option value="size">Sort: size</option><option value="type">Sort: type</option></select></div>
  <div class="row" style="margin-top:8px"><span class="note" id="selinfo"></span><button class="btn sm alt" id="selall">Select all</button><button class="btn sm alt" id="selnone">Clear</button><button class="btn sm" id="dlsel">Download selected (ZIP)</button></div></div><div class="tree" id="tree"></div>`;
  $('#sort').value = s.sort;
  $('#q').oninput = (e) => { s.q = e.target.value; drawTree(); };
  $('#sort').onchange = (e) => { s.sort = e.target.value; drawTree(); };
  $('#selall').onclick = () => { s.prefixes = new Set(['']); drawTree(); }; $('#selnone').onclick = () => { s.selected.clear(); s.prefixes.clear(); drawTree(); };
  $('#dlsel').onclick = () => exportJob('selected');
  $('#tree').addEventListener('click', onTreeClick);
  drawTree();
}
const sorter = (k) => (a, b) => (a.isDir !== b.isDir ? (a.isDir ? -1 : 1) : k === 'size' ? b.size - a.size : k === 'type' ? ((a.rec && a.rec.ext) || '').localeCompare((b.rec && b.rec.ext) || '') || a.name.localeCompare(b.name) : a.name.localeCompare(b.name, undefined, { numeric: true }));
function isSel(s, n) { return s.selected.has(n.path) || [...s.prefixes].some((p) => n.path.startsWith(p)); }
function drawTree() {
  const s = cur(), rows = []; const q = s.q.trim().toLowerCase(); const LIM = 2500;
  if (q) {
    const ext = q.startsWith('.') ? q.slice(1) : null;
    for (const f of s.model.files) { if (rows.length >= LIM) break; if (ext !== null ? f.ext === ext : f.path.toLowerCase().includes(q)) rows.push({ n: { path: f.path, name: f.path, isDir: f.isDir, size: f.size, rec: f }, d: 0 }); }
  } else {
    const walk = (n, d) => { for (const c of [...n.children.values()].sort(sorter(s.sort))) { if (rows.length >= LIM) return; rows.push({ n: c, d }); if (c.isDir && s.expanded.has(c.path)) walk(c, d + 1); } };
    walk(s.tree, 0);
  }
  $('#tree').innerHTML = rows.map(({ n, d }) => `<div class="tr" style="padding-left:${8 + d * 16}px" data-p="${esc(n.path)}"><span class="tw" data-tw>${n.isDir ? (s.expanded.has(n.path) ? '▾' : '▸') : ''}</span><input type="checkbox" data-sel ${isSel(s, n) ? 'checked' : ''} aria-label="Select"><span class="nm" data-nm>${n.isDir ? '📁' : '📄'} ${esc(n.name)}${n.rec && n.rec.status !== 'ok' ? ' <span class="tag bad">' + esc(n.rec.status) + '</span>' : ''}${n.rec && n.rec.hidden ? ' <span class="tag">hidden</span>' : ''}</span><span class="sz">${n.isDir && !q ? n.count + ' files · ' : ''}${formatBytes(n.size)}</span></div>`).join('') + (rows.length >= LIM ? `<div class="tr note">Showing the first ${LIM} rows. Narrow the search or collapse folders to see more.</div>` : '') || '<div class="tr note">No matches.</div>';
  const cnt = selectRecords(s.model, { paths: s.selected, prefixes: [...s.prefixes] }); $('#selinfo').textContent = (s.selected.size || s.prefixes.size) ? `${cnt.filter((x) => !x.isDir).length} files selected` : 'Nothing selected';
}
function onTreeClick(e) {
  const s = cur(), row = e.target.closest('.tr'); if (!row || !row.dataset.p) return; const p = row.dataset.p; const isDir = p.endsWith('/');
  if (e.target.matches('[data-sel]')) {
    if (isDir) { e.target.checked ? s.prefixes.add(p) : s.prefixes.delete(p); } else { e.target.checked ? s.selected.add(p) : s.selected.delete(p); }
    return drawTree();
  }
  if (e.target.closest('[data-tw]') || (isDir && e.target.closest('[data-nm]'))) { if (isDir) { s.expanded.has(p) ? s.expanded.delete(p) : s.expanded.add(p); drawTree(); } return; }
  if (e.target.closest('[data-nm]') && !isDir) openPreview(s.model.files.find((f) => f.path === p));
}

// ---------- preview ----------
function closePreview() { const p = $('#preview'); p.hidden = true; p.innerHTML = ''; S.urls.filter((u) => u.preview).forEach(URL.revokeObjectURL); }
const hexDump = (u8, n = 512) => { let o = ''; for (let i = 0; i < Math.min(n, u8.length); i += 16) { const r = u8.subarray(i, i + 16); o += i.toString(16).padStart(8, '0') + '  ' + [...r].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' + [...r].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('') + '\n'; } return o; };
async function openPreview(f) {
  const P = $('#preview'); P.hidden = false; P.innerHTML = `<p>Loading…</p>`;
  const head = `<div class="row"><b style="flex:1;word-break:break-all">${esc(f.path)}</b><button class="btn sm alt" id="pclose">Close</button></div><div class="row"><button class="btn sm alt" id="pcopy">Copy path</button><button class="btn sm" id="pdl">Download file</button></div>${dl({ Size: formatBytes(f.size) + ` (${f.size} bytes)`, Type: esc(f.mime || f.sig || 'unknown'), Signature: esc(f.sig), Category: esc(CATEGORY_LABELS[f.category]), 'SHA-256': `<code style="word-break:break-all">${esc(f.sha256)}</code>`, Status: f.status })}`;
  let body = '';
  try {
    const LIMIT = 1 << 20; const { bytes, truncated } = await readFileBytes(cur().file, f, LIMIT); const sg = sniff(bytes); const ext = f.ext;
    if (IMAGE_EXT.has(ext) && ext !== 'svg' && f.size < 30e6 || ['PNG image', 'JPEG image', 'GIF image', 'WebP image'].includes(sg.sig)) {
      const full = (await readFileBytes(cur().file, f, 30e6)).bytes; const data = isCgBI(full) ? await cgbiToPng(full) : full;
      const u = URL.createObjectURL(new Blob([data], { type: f.mime || 'image/png' })); S.urls.push(u); body = `<div class="prev"><img src="${u}" alt="preview"></div>${isCgBI(full) ? '<p class="note">Apple-optimised (CgBI) PNG, converted for display only. The original is unchanged.</p>' : ''}`;
    } else if (ext === 'pdf' && f.size < 40e6) { const full = (await readFileBytes(cur().file, f, 40e6)).bytes; const u = URL.createObjectURL(new Blob([full], { type: 'application/pdf' })); body = `<a class="btn alt" href="${u}" target="_blank" rel="noopener">Open PDF</a>`; }
    else if (['ttf', 'otf', 'woff', 'woff2'].includes(ext)) { const full = (await readFileBytes(cur().file, f, 10e6)).bytes; try { const ff = new FontFace('prev' + f.index, full.buffer.slice(full.byteOffset, full.byteOffset + full.byteLength)); await ff.load(); document.fonts.add(ff); body = `<p style="font:28px 'prev${f.index}'">The quick brown fox 0123456789</p>`; } catch { body = '<p class="note">This font could not be rendered by the browser.</p>'; } }
    else if (sg.sig === 'Binary property list' || ext === 'plist' || ext === 'strings' && sg.sig === 'Binary property list') { const r = parsePlist((await readFileBytes(cur().file, f, 8 << 20)).bytes); body = `<p class="note">${r.format === 'binary' ? 'Binary plist, shown as XML. The file itself is not modified.' : 'XML plist'}</p><pre>${esc(plistDocument(r.value).slice(0, 200000))}</pre>`; }
    else if (isMachO(bytes)) { const full = (await readFileBytes(cur().file, f, 160 << 20)).bytes; const m = parseMachO(full); body = `<p class="note">Compiled machine code. No source code is recoverable from this file.</p>` + m.slices.map((x) => !x.ok ? `<p class="err">${esc(x.error)}</p>` : `<h3>${esc(x.arch)} · ${esc(x.filetype)}${x.encrypted ? ' · <span class="err">FairPlay-encrypted</span>' : ''}</h3>${dl({ UUID: esc(x.uuid), Platform: esc(x.platform), 'Min OS': esc(x.minOS), PIE: x.pie ? 'yes' : 'no', 'Stack canary': x.signals.stackCanary === undefined ? 'unknown' : x.signals.stackCanary ? 'yes' : 'no', ARC: x.signals.arc === undefined ? 'unknown' : x.signals.arc ? 'yes' : 'no', 'Debug symbols': x.hasDebugSymbols ? 'DWARF segment present' : 'none', 'Linked libraries': esc(x.dylibs.map((d) => d.name).join('\n')).replace(/\n/g, '<br>'), 'Load commands': esc(Object.entries(x.cmdCounts).map(([k, n]) => k + '×' + n).join(', ')) })}`).join('') + `<h3>First bytes</h3><div class="hex">${esc(hexDump(bytes, 256))}</div>`; }
    else if ((TEXT_EXT.has(ext) || looksText(bytes)) && sg.sig !== 'Binary property list') body = `${truncated ? '<p class="note">Showing the first 1 MB.</p>' : ''}<pre>${esc(new TextDecoder().decode(bytes))}</pre>`;
    else body = `<p class="note">Binary file shown as raw bytes${f.category === 'ui' ? ' (compiled interface/asset data cannot be turned back into source)' : ''}. Nothing has been converted.</p><div class="hex">${esc(hexDump(bytes, 512))}</div>${f.size >= 4096 ? '<div class="row" style="margin-top:8px"><button class="btn sm" id="p-carve">Find images in this file</button></div><div id="p-carve-out"></div>' : ''}`;
  } catch (e) { body = `<p class="err">Preview failed: ${esc(e.message)}</p>`; }
  P.innerHTML = head + body;
  $('#pclose').onclick = closePreview; $('#pcopy').onclick = () => { navigator.clipboard && navigator.clipboard.writeText(f.path).then(() => toast('Path copied'), () => toast('Copy not available')); };
  $('#pdl').onclick = () => exportJob('selected', { paths: new Set([f.path]), single: true });
  const pc = $('#p-carve');
  if (pc) pc.onclick = async () => {
    const out = $('#p-carve-out'); out.innerHTML = '<p class="note">Scanning…</p>';
    try {
      const r = await carveEntry(cur().file, f.entry, { maxImages: 60 });
      if (!r.images.length) { out.innerHTML = '<p class="note">No complete images were found in this file.</p>'; return; }
      const all = r.images.map((im) => ({ ...im, container: f.path }));
      out.innerHTML = `<div class="prev" style="display:flex;flex-wrap:wrap;gap:6px" id="one-grid"></div><div class="row" style="margin-top:8px"><button class="btn sm" id="one-dl">Download ${r.images.length} image${r.images.length === 1 ? '' : 's'} (ZIP)</button></div>${r.limitReached ? '<p class="note">Limit reached — shown/collected images stop early.</p>' : ''}`;
      await drawThumbs($('#one-grid'), all, 12);
      $('#one-dl').onclick = () => downloadCarved(all);
    } catch (e) { out.innerHTML = `<p class="err">${e.code === 'aborted' ? 'Cancelled' : 'Scan failed: ' + esc(e.message)}</p>`; }
  };
}

// ---------- extraction + downloads ----------
function viewExtract(v) {
  const s = cur(), st = s.model.stats;
  v.innerHTML = `<div class="card"><h3>Extract everything</h3><p class="note">${st.files} files · ${st.folders} folders · ${formatBytes(st.bytes)}. Files are copied exactly as stored in the IPA — nothing is renamed, skipped or recompressed.</p>
  <div class="row"><button class="btn" id="b-all">Extract all → ZIP</button><button class="btn alt" id="b-sel">Selected files/folders → ZIP</button><button class="btn alt" data-go="explorer">Select files…</button><a class="btn alt" id="b-orig" download="${esc(s.file.name)}">Original IPA</a></div></div>
  <div class="card"><h3>Hidden images in compiled files</h3><p class="note">Apps keep most of their images inside compiled containers like <b>Assets.car</b> — those images never appear in the file list above. Cairn can recover the complete PNG/JPEG images stored inside such containers. Best-effort and local-only; the original file is never modified, and nothing is fabricated (only fully valid image streams are reported).</p>
  <div class="row"><button class="btn" id="b-carve">Find hidden images</button></div><div id="carve"></div></div><div id="job"></div>`;
  $('#b-all').onclick = () => exportJob('original'); $('#b-sel').onclick = () => exportJob('selected');
  $('#b-carve').onclick = () => carveJob($('#carve'));
  if (s.carved) drawCarveResults($('#carve'));
  const u = URL.createObjectURL(s.file); S.urls.push(u); const b = $('#b-orig'); b.href = u; b.onclick = (e) => { if (window.__cairnNativeSaver) { e.preventDefault(); window.__cairnNativeSaver(s.file, s.file.name); } };
}

// ---------- hidden-image carving (v1.1) ----------
async function carveJob(out) {
  const s = cur();
  const files = s.model.files.filter((f) => !f.isDir && (f.ext === 'car' || f.category === 'ui' || (f.category === 'other' && f.size >= (1 << 20))));
  files.sort((a, b) => b.size - a.size);
  const pick = []; let total = 0;
  for (const f of files) { if (pick.length >= 6) break; if (total + f.size > (512 << 20)) continue; pick.push(f); total += f.size; }
  if (!pick.length) { out.innerHTML = '<div class="card"><p class="note">No compiled containers were found in this IPA — there is nothing to scan.</p></div>'; return; }
  const ctl = new AbortController(); const results = []; let collected = 0;
  const prog = throttle((p) => { const bar = out.querySelector('.bar > i'); if (bar && p.total) bar.style.width = Math.min(100, (p.scanned / p.total) * 100) + '%'; }, 120);
  for (let i = 0; i < pick.length; i++) {
    const f = pick[i];
    out.innerHTML = `<div class="card"><h3>Scanning ${esc(f.path)}</h3><div class="bar"><i style="width:0%"></i></div><p class="note">Container ${i + 1}/${pick.length} · ${formatBytes(f.size)}${collected ? ` · ${collected} image${collected === 1 ? '' : 's'} so far` : ''}</p><button class="btn sm alt" id="cc">Cancel</button></div>`;
    $('#cc').onclick = () => ctl.abort();
    try {
      const r = await carveEntry(s.file, f.entry, { signal: ctl.signal, onProgress: prog, maxImages: 300, maxCarvedBytes: 96 << 20 });
      if (r.images.length) { results.push({ file: f, images: r.images, limitReached: r.limitReached, truncated: r.truncated }); collected += r.images.length; }
    } catch (e) {
      if (e.code === 'aborted') { out.innerHTML = '<div class="card"><p class="note">Cancelled — nothing was changed.</p></div>'; return; }
      results.push({ file: f, images: [], error: e.message });
    }
    if (collected >= 400) break;
  }
  s.carved = results;
  drawCarveResults(out);
}
function drawCarveResults(out) {
  const results = cur().carved || [];
  const all = results.flatMap((r) => r.images.map((im) => ({ ...im, container: r.file.path })));
  if (!all.length) { out.innerHTML = '<div class="card"><p class="note">No complete images were found inside the compiled containers of this IPA.</p></div>'; return; }
  const totalBytes = all.reduce((a, b) => a + b.size, 0);
  out.innerHTML = `<div class="card"><h3 class="ok">Recovered ${all.length} image${all.length === 1 ? '' : 's'} · ${formatBytes(totalBytes)}</h3>
  ${results.map((r) => `<div class="row"><span style="flex:1;word-break:break-all">${esc(r.file.path)}</span><span class="note">${r.images.length} image${r.images.length === 1 ? '' : 's'}${r.limitReached ? ' · limit reached, scan stopped early' : ''}${r.truncated ? ' · file partially scanned' : ''}</span></div>`).join('')}
  <div class="prev" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px" id="carve-grid"></div>
  <div class="row" style="margin-top:8px"><button class="btn" id="carve-dl">Download all images (ZIP)</button></div>
  <p class="note">Apple CgBI images are converted to standard PNG inside the ZIP so they display anywhere; the originals inside the container are untouched. A MANIFEST.txt records where each image was found. Limits: first 300 images / 96 MB per container.</p></div>`;
  drawThumbs($('#carve-grid'), all, 24);
  $('#carve-dl').onclick = () => downloadCarved(all);
}
async function drawThumbs(grid, all, max) {
  let n = 0;
  for (const im of all) {
    if (n >= max) { grid.insertAdjacentHTML('beforeend', `<span class="note" style="align-self:center">…and ${all.length - max} more</span>`); break; }
    n++;
    try {
      let bytes = im.bytes, type = 'image/jpeg';
      if (im.kind !== 'jpeg') { bytes = await cgbiToPng(im.bytes); type = 'image/png'; }
      const u = URL.createObjectURL(new Blob([bytes], { type })); S.urls.push(u);
      grid.insertAdjacentHTML('beforeend', `<img src="${u}" alt="" style="width:64px;height:64px;object-fit:contain;background:#0b1220;border:1px solid var(--line);border-radius:6px">`);
    } catch { grid.insertAdjacentHTML('beforeend', `<span class="note">1 image could not be shown</span>`); }
  }
}
async function downloadCarved(all) {
  const zw = new ZipWriter(); const lines = ['file\tcontainer\toffset\tsize\tkind']; const used = new Map();
  for (let i = 0; i < all.length; i++) {
    const im = all[i];
    let bytes = im.bytes, kind = im.kind;
    if (kind !== 'jpeg') { try { bytes = await cgbiToPng(bytes); kind = 'png'; } catch { /* keep original bytes if conversion is impossible */ } }
    const cont = (im.container.replace(/\/$/, '').split('/').pop() || 'container').replace(/\.[^.]*$/, '');
    const stem = `${cont}_img_${String(i + 1).padStart(3, '0')}`;
    const ext = kind === 'jpeg' ? 'jpg' : 'png';
    let name = `${stem}.${ext}`; const seen = used.get(name) || 0; used.set(name, seen + 1); if (seen) name = `${stem}_${seen}.${ext}`;
    lines.push(`${name}\t${im.container}\t${im.offset}\t${bytes.length}\t${im.kind}${im.kind !== kind ? ' → converted to ' + kind : ''}`);
    zw.addBytes(`CARVED_IMAGES/${name}`, bytes);
  }
  zw.addBytes('CARVED_IMAGES/MANIFEST.txt', lines.join('\n'));
  await saveBlob(zw.finish(), 'CARVED_IMAGES.zip');
}
function viewDownloads(v) {
  v.innerHTML = `<div class="card"><h3>Downloads</h3><p class="note">Every export is re-opened and checked against the archive (size + CRC${S.settings.deep ? ' + SHA-256' : ''}) before the download starts.</p>
  <div class="grid">${[['original', DOWNLOADS.original, 'Every file, original folder structure, byte-for-byte'], ['project', DOWNLOADS.project, 'Project-style workspace + manifest (resources only — no source is fabricated)'], ['resources', DOWNLOADS.resources, 'Source files if the IPA shipped any, plus images, fonts, audio, UI, localisation'], ['report', DOWNLOADS.report, 'Analysis report, manifest.json/.csv, SHA256SUMS, icon']].map(([k, n, d]) => `<div class="card" style="margin:0"><b style="word-break:break-all">${n}</b><p class="note">${d}</p><button class="btn sm" data-x="${k}">Build &amp; download</button></div>`).join('')}</div>
  <div class="row" style="margin-top:10px"><button class="btn alt sm" data-x="manifest">manifest.json</button><button class="btn alt sm" data-x="csv">manifest.csv</button><button class="btn alt sm" data-x="sums">SHA256SUMS.txt</button><a class="btn alt sm" id="b-orig" download="${esc(cur().file.name)}">Original IPA (unmodified)</a></div></div><div id="job"></div>`;
  v.querySelectorAll('[data-x]').forEach((b) => (b.onclick = () => exportJob(b.dataset.x)));
  const u = URL.createObjectURL(cur().file); S.urls.push(u); const b = $('#b-orig'); b.href = u; b.onclick = (e) => { const f = cur().file; if (window.__cairnNativeSaver) { e.preventDefault(); window.__cairnNativeSaver(f, f.name); } };
  if (window.__cairnFiles) drawPhoneFiles(v);
}
async function drawPhoneFiles(v) {
  const card = document.createElement('div'); card.className = 'card'; v.appendChild(card);
  card.innerHTML = `<h3>📁 Phone files</h3><p class="note">Everything Cairn saves stays here: <b>Files app → On My iPhone → Cairn → Exports</b>. From the Files app you can move any file anywhere on the phone. Share again at any time:</p><div id="pf-list"><p class="note">Loading…</p></div><div class="row" style="margin-top:8px"><button class="btn sm alt" id="pf-refresh">Refresh</button></div>`;
  const draw = (d) => {
    const files = (d && d.files) || [];
    const el = $('#pf-list', card);
    if (!files.length) { el.innerHTML = '<p class="note">No saved files yet. Build a ZIP above and it will appear here automatically.</p>'; return; }
    el.innerHTML = files.map((f) => `<div class="row" style="border-bottom:1px solid var(--line);padding:6px 0"><span style="flex:1;word-break:break-all">${esc(f.name)}<div class="note">${formatBytes(f.size || 0)}</div></span><button class="btn sm" data-share="${esc(f.name)}">Share</button><button class="btn sm alt" data-del="${esc(f.name)}">Remove</button></div>`).join('');
    el.querySelectorAll('[data-share]').forEach((b) => (b.onclick = () => window.__cairnFiles.share(b.dataset.share)));
    el.querySelectorAll('[data-del]').forEach((b) => (b.onclick = async () => { window.__cairnFiles.del(b.dataset.del); await new Promise((r) => setTimeout(r, 300)); window.__cairnFiles.list().then(draw); }));
  };
  $('#pf-refresh', card).onclick = () => window.__cairnFiles.list().then(draw);
  window.__cairnFiles.list().then(draw);
}
async function saveBlob(blob, name) {
  if (typeof window !== 'undefined' && window.__cairnNativeSaver) {
    let ok = false;
    try { ok = await window.__cairnNativeSaver(blob, name); } catch (e) { ok = false; }
    if (ok) return null;
  }
  const u = URL.createObjectURL(blob); S.urls.push(u); const a = document.createElement('a'); a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  return u;
}
async function exportJob(kind, opt = {}) {
  const s = cur(); const jobEl = () => $('#job') || (() => { const d = document.createElement('div'); d.id = 'job'; $('#view').appendChild(d); return d; })();
  const ctl = new AbortController(); const prog = (p) => { jobEl().innerHTML = `<div class="card"><h3>Building ${esc(kind)}…</h3><div class="bar"><i style="width:${p.total ? (p.done / p.total) * 100 : 5}%"></i></div><p class="note">${esc(p.current || '')}</p><button class="btn sm alt" id="jc">Cancel</button></div>`; $('#jc').onclick = () => ctl.abort(); };
  prog({}); const o = { signal: ctl.signal, onProgress: prog };
  try {
    let res, name, expected = null;
    if (kind === 'manifest' || kind === 'csv' || kind === 'sums') {
      const m = buildManifest(s.model); const t = kind === 'manifest' ? [JSON.stringify(m, null, 2), 'manifest.json', 'application/json'] : kind === 'csv' ? [manifestCsv(m), 'manifest.csv', 'text/csv'] : [sha256sums(m), 'SHA256SUMS.txt', 'text/plain'];
      await saveBlob(new Blob([t[0]], { type: t[2] }), t[1]); jobEl().innerHTML = `<div class="card ok">Saved ${t[1]} (${m.entries.length} entries).</div>`; return;
    }
    if (kind === 'original') { res = await buildOriginalZip(s.file, s.model, o); name = DOWNLOADS.original; expected = res.records; }
    else if (kind === 'selected') {
      const recs = selectRecords(s.model, { paths: opt.paths || s.selected, prefixes: opt.paths ? [] : [...s.prefixes] });
      if (!recs.length) { jobEl().innerHTML = `<div class="card err">Nothing is selected. Pick files or folders in the File Explorer first.</div>`; return; }
      if (opt.single && recs.length === 1) { const f = recs[0]; const { blob } = await (await import('../core/zip-reader.js')).entryToBlob(s.file, f.entry, { signal: ctl.signal }); await saveBlob(blob, f.name); jobEl().innerHTML = `<div class="card ok">Downloaded ${esc(f.name)}.</div>`; return; }
      res = await buildOriginalZip(s.file, s.model, { ...o, records: recs }); name = 'SELECTED_FILES.zip'; expected = recs;
    }
    else if (kind === 'project') { res = await buildProjectZip(s.file, s.model, o); name = DOWNLOADS.project; }
    else if (kind === 'resources') { res = await buildResourcesZip(s.file, s.model, o); name = DOWNLOADS.resources; }
    else if (kind === 'report') { res = await buildReportZip(s.file, s.model, o); name = DOWNLOADS.report; }
    let ver = null;
    if (expected) ver = await verifyExport(res.blob, expected, { deep: S.settings.deep, signal: ctl.signal });
    if (ver && !ver.ok) { jobEl().innerHTML = `<div class="card"><h3 class="err">Verification failed — download withheld</h3><p>Missing: ${ver.missing.length}, mismatched: ${ver.mismatched.length}</p></div>`; return; }
    const u = await saveBlob(res.blob, name);
    jobEl().innerHTML = `<div class="card"><h3 class="ok">${esc(name)} ready</h3><p>${res.count} entries · ${formatBytes(res.blob.size)}${ver ? ` · <span class="ok">verified ${ver.verified}/${ver.expected} entries${ver.deep ? ' (SHA-256)' : ' (size + CRC)'}</span>` : ''}</p>${res.skipped && res.skipped.length ? `<p class="err">${res.skipped.length} entries could not be copied: ${esc(res.skipped.map((x) => x.path).join(', '))}</p>` : ''}${u ? `<p class="note">If the save sheet didn't appear, tap:</p><a class="btn sm" href="${u}" download="${esc(name)}">Save ${esc(name)}</a>` : ''}</div>`;
  } catch (e) { jobEl().innerHTML = `<div class="card"><h3 class="err">${e.code === 'aborted' ? 'Cancelled' : 'Export failed'}</h3><p>${esc(e.message)}</p><p class="note">${e.code === 'aborted' ? '' : 'This can happen when the device runs out of memory on a very large IPA. Try exporting selected folders instead.'}</p></div>`; }
}

// ---------- security ----------
function viewSecurity(v) {
  const m = cur().model, a = m.app, F = []; const add = (lvl, t, d) => F.push({ lvl, t, d });
  const bad = m.files.filter((f) => f.status !== 'ok');
  if (bad.length) add('bad', `${bad.length} archive entries failed integrity checks`, bad.slice(0, 5).map((f) => f.path + ' (' + f.status + ')').join(', '));
  const unsafe = m.files.filter((f) => f.problems.includes('unsafe-path')); if (unsafe.length) add('bad', 'Unsafe paths in archive', 'Entries use absolute paths or "..". They are listed and preserved verbatim but never written to disk by this tool.');
  if (m.files.some((f) => f.problems.includes('duplicate-name'))) add('warn', 'Duplicate entry names', 'Both copies are kept in the exports.');
  if (a) {
    if (a.encrypted) add('warn', 'Main executable is FairPlay-encrypted', 'Code is not readable until it is decrypted. This tool does not decrypt anything. Metadata, resources and all other files are still fully available.');
    else if (a.macho && a.macho.ok) add('ok', 'Main executable is not encrypted', 'Mach-O headers, linked libraries and symbols are readable.');
    const sl = a.macho && a.macho.ok ? a.macho.slices.filter((x) => x.ok) : [];
    for (const x of sl) add(x.pie ? 'ok' : 'warn', `${x.arch}: PIE ${x.pie ? 'enabled' : 'not set'}`, ''), x.signals.stackCanary !== undefined && add(x.signals.stackCanary ? 'ok' : 'warn', `${x.arch}: stack canary ${x.signals.stackCanary ? 'indicators found' : 'indicators not found'}`, 'Heuristic from symbol names; not available if symbols are stripped.'), x.signals.arc !== undefined && add(x.signals.arc ? 'ok' : 'warn', `${x.arch}: ARC ${x.signals.arc ? 'indicators found' : 'indicators not found'}`, 'Heuristic.');
    if (sl.some((x) => x.hasDebugSymbols)) add('warn', 'DWARF debug segment present', '');
    if (!a.codeSigned) add('warn', 'No code signature found in the executable', '');
    if (a.provisioning && a.provisioning.kind) add(a.provisioning.kind === 'App Store' ? 'ok' : 'warn', `Provisioning profile: ${a.provisioning.kind}`, `${a.provisioning.teamName || ''} ${a.provisioning.expires || ''}${a.provisioning.getTaskAllow ? ' · get-task-allow = true (debuggable)' : ''}`);
    if (a.ats && (a.ats.NSAllowsArbitraryLoads === true)) add('warn', 'App Transport Security allows arbitrary loads', 'NSAllowsArbitraryLoads = true');
    if (a.permissions.length) add('ok', `${a.permissions.length} privacy permission strings`, a.permissions.map((p) => p.key.replace(/^NS|UsageDescription$/g, '')).join(', '));
    if (a.urlSchemes.length) add('ok', 'Custom URL schemes', a.urlSchemes.join(', '));
    if (a.entitlements) add('ok', 'Entitlements', Object.keys(a.entitlements).join(', '));
  } else add('warn', 'No app bundle', 'Not a standard IPA layout.');
  v.innerHTML = `<div class="card"><h3>Security analysis</h3><p class="note">Static, local checks of metadata only. Not a malware scan and not a guarantee of safety.</p>${F.map((f) => `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><span class="tag ${f.lvl}">${f.lvl === 'ok' ? 'info' : f.lvl === 'warn' ? 'note' : 'issue'}</span><b>${esc(f.t)}</b><div class="note">${esc(f.d)}</div></div>`).join('')}</div>`;
  fillExecutableNames(v);
}
async function fillExecutableNames(v) {
  const m = cur().model, a = m.app;
  const card = document.createElement('div'); card.className = 'card'; v.appendChild(card);
  if (!a || !a.macho || !a.macho.ok) { card.innerHTML = '<h3>Names inside the executable</h3><p class="note">No readable Mach-O executable in this IPA.</p>'; return; }
  if (a.encrypted) { card.innerHTML = '<h3>Names inside the executable</h3><p class="note">The executable is FairPlay-encrypted, so name tables are not readable. Everything else in the IPA is still fully available.</p>'; return; }
  if (a.machoPartial) { card.innerHTML = '<h3>Names inside the executable</h3><p class="note">The executable is too large to read fully on this device, so name tables are unavailable.</p>'; return; }
  card.innerHTML = '<h3>Names inside the executable</h3><p class="note">Reading…</p>';
  try {
    const rec = m.files.find((f) => f.path === a.executablePath);
    const { bytes } = await readFileBytes(cur().file, rec, a.executableSize || rec.size);
    const slice = a.macho.slices.find((s) => s.ok && !s.encrypted) || a.macho.slices[0];
    const names = objcNames(bytes, slice);
    if (!names.ok) { card.innerHTML = `<h3>Names inside the executable</h3><p class="note">${esc(names.error || 'Not readable.')}</p>`; return; }
    const list = (arr, n) => arr.slice(0, n).map((x) => `<div style="word-break:break-all;font-family:monospace;font-size:12px;padding:1px 0">${esc(x)}</div>`).join('') || '<span class="note">none found</span>';
    card.innerHTML = `<h3>Names inside the executable</h3>
    <p class="note">Human-readable identifiers the compiler stored inside the binary (ObjC class and method names, C strings). This is a map of what is inside the program — <b>not</b> source code and not decompiled logic.</p>
    <div class="row" style="margin:6px 0"><span class="tag info">classes</span><b>&nbsp;${names.classCount}</b><span class="tag info" style="margin-left:10px">methods</span><b>&nbsp;${names.methodCount}</b><span class="tag info" style="margin-left:10px">strings</span><b>&nbsp;${names.stringsTotal || 0}</b>${names.truncated ? '<span class="tag note" style="margin-left:10px">list truncated</span>' : ''}</div>
    <details><summary style="cursor:pointer">Show classes (first 60)</summary><div style="max-height:180px;overflow:auto;margin-top:6px">${list(names.classes, 60)}</div></details>
    <details style="margin-top:6px"><summary style="cursor:pointer">Show method names (first 60)</summary><div style="max-height:180px;overflow:auto;margin-top:6px">${list(names.methods, 60)}</div></details>
    <details style="margin-top:6px"><summary style="cursor:pointer">Show strings (first 60)</summary><div style="max-height:180px;overflow:auto;margin-top:6px">${list(names.strings, 60)}</div></details>
    <div class="row" style="margin-top:10px"><button class="btn sm" id="names-txt">Save full name list → .txt</button></div>`;
    $('#names-txt', card).onclick = () => {
      const L = ['Cairn IPA Studio — names inside the binary', `App: ${a.displayName} (${a.bundleId}) v${a.version} (${a.build})`, `IPA: ${m.fileName}`, `Generated: ${new Date().toISOString()}`, '', 'NOTE: These are identifier strings the compiler stored inside the executable (ObjC class/method names, C strings). This is not source code and not decompiled logic.', '', `CLASSES (${names.classCount})`, ...names.classes, '', `METHODS (${names.methodCount})`, ...names.methods];
      if (names.strings && names.strings.length) L.push('', `STRINGS sample (${names.strings.length}${names.stringsTotal ? ' of ' + names.stringsTotal : ''})`, ...names.strings);
      saveBlob(new Blob([L.join('\n')], { type: 'text/plain' }), 'BINARY_NAMES.txt');
    };
  } catch (e) { card.innerHTML = `<h3>Names inside the executable</h3><p class="note">Could not read the executable: ${esc(e.message)}</p>`; }
}

// ---------- toolchain (45-tool unified analysis workspace) ----------
async function runToolchainAuto(s) {
  try {
    const result = await runToolchain(s.file, s.model, {
      onProgress: (p) => { s.tc.progress = p; if (S.tab === 'tools' && S.cur === s) drawToolProgress(); },
    });
    s.tc.state = 'done'; s.tc.result = result;
    toast(`Toolchain finished: ${result.counts.active + result.counts.partial} tools ran · ${result.counts.host} need a desktop`);
  } catch (e) {
    s.tc.state = 'error'; s.tc.error = String(e && e.message || e);
    toast('Toolchain run failed: ' + s.tc.error);
  }
  if (S.tab === 'tools' && S.cur === s) render();
}
function drawToolProgress() {
  const el = $('#tc-progress'); if (!el) return;
  const s = cur(); const p = s.tc.progress || {};
  el.innerHTML = `<div class="bar"><i style="width:${Math.min(100, ((p.done || 0) / 8) * 100)}%"></i></div><p class="note">Running analysis engines… (${p.done || 0}/8 · ${esc(p.current || '')})</p>`;
}
function toolChip(r) {
  if (r.status === 'host') return `<span class="tag bad" title="Needs a desktop computer">desktop required</span>`;
  if (r.ran) return `<span class="tag ok" title="Ran on this file">✓ ran</span>`;
  return `<span class="tag note">not applicable</span>`;
}
function statusChip(t) {
  if (t.status === 'active') return '<span class="tag ok">active</span>';
  if (t.status === 'partial') return '<span class="tag note">partial</span>';
  return '<span class="tag bad">desktop</span>';
}
function viewTools(v) {
  const s = cur(); const tc = s.tc || (s.tc = { state: 'idle', result: null });
  const r = tc.result;
  v.innerHTML = `<div class="card"><h2>Toolchain — 45-tool analysis workspace</h2>
  <p class="note">Every compatible engine runs automatically when a file is opened. Results below are real output for <b>${esc(s.file.name)}</b>. Tools marked <b>desktop required</b> genuinely cannot execute inside an iOS app — they are not simulated; the note explains what Cairn provides instead.</p>
  <div id="tc-progress">${tc.state === 'running' ? '<div class="bar"><i style="width:5%"></i></div><p class="note">Running analysis engines…</p>' : ''}</div>
  ${tc.state === 'error' ? `<p class="err">Pipeline error: ${esc(tc.error)}</p>` : ''}</div>
  <div id="tc-body"></div>`;
  const body = $('#tc-body');
  if (tc.state !== 'done') { body.innerHTML = '<div class="card"><p class="note">Pipeline still running — this page updates when it finishes.</p></div>'; return; }

  // --- pipeline summary ---
  const ran = r.ran;
  const audit = ran['security-audit'] || {};
  const deps = ran['deps'] || {};
  const syms = ran['symbols'] || {};
  const objcn = ran['objc-names'] || {};
  const sigs = ran['signatures-scan'] || {};
  const pkgs = ran['packages'] || {};
  const dis = ran['disasm-auto'] || {};
  const sigTotal = (sigs.files || []).reduce((n, f) => n + f.hits.length, 0);
  const sevColor = { high: 'bad', medium: 'warn', low: 'note', info: 'note' };
  body.innerHTML = `
  <div class="card"><h3>Pipeline summary <span class="tag info">${r.durationMs} ms</span></h3>
  <div class="grid"><div class="stat"><b>${r.counts.active}</b><span>tools ran (full)</span></div>
  <div class="stat"><b>${r.counts.partial}</b><span>tools ran (subset)</span></div>
  <div class="stat"><b>${r.counts.host}</b><span>need a desktop</span></div>
  <div class="stat"><b class="${audit.score && audit.score.high ? 'err' : 'ok'}">${audit.findings ? audit.findings.length : 0}</b><span>audit findings</span></div></div>
  <p class="note">Honest scope: 45 tools registered — ${r.counts.active + r.counts.partial} executed their core function on this file on-device; ${r.counts.host} require a Mac/PC environment and are listed with the reason (never simulated).</p></div>

  <div class="card"><h3>🔗 Dependencies (otool -L across every binary)</h3>
  <p><b>${deps.linksTotal || 0}</b> links · <span class="tag ok">system ${deps.tally && deps.tally.system || 0}</span> <span class="tag info">embedded ${deps.tally && deps.tally.embedded || 0}</span> ${deps.tally && deps.tally.missing ? `<span class="tag bad">MISSING ${deps.tally.missing}</span>` : '<span class="tag ok">no missing libraries</span>'}</p>
  ${deps.missing && deps.missing.length ? `<p class="err">Missing (neither system nor embedded) — would crash at launch or on load:</p><div style="max-height:160px;overflow:auto">${deps.missing.map((m) => `<div style="font-family:monospace;font-size:12px;word-break:break-all">${esc(m.base)} ← ${esc(m.refs.join(', '))}</div>`).join('')}</div>` : ''}
  ${deps.unique && deps.unique.length ? `<details><summary>All unique dependencies (${deps.unique.length})</summary><div style="max-height:240px;overflow:auto">${deps.unique.map((m) => `<div style="padding:2px 0"><span class="tag ${m.kind.startsWith('missing') ? 'bad' : m.kind.startsWith('embedded') ? 'info' : 'ok'}">${esc(m.kind)}</span> <span style="font-family:monospace;font-size:12px">${esc(m.base)}</span></div>`).join('')}</div></details>` : ''}</div>

  <div class="card"><h3>℗ Symbols (nm + swift-demangle)</h3>
  ${syms.error ? `<p class="err">${esc(syms.error)}</p>` : `<p><b>${syms.total || 0}</b> symbols across ${((syms.binaries || []).filter((b) => b.count !== undefined)).length} binaries · <span class="tag info">Swift-family ${syms.swift || 0}</span> <span class="tag info">C++ ${syms.cxx || 0}</span>${syms.truncated ? ' <span class="tag note">truncated to 60k per binary</span>' : ''}</p>
  ${(syms.binaries || []).filter((b) => b.sample && b.sample.length).slice(0, 3).map((b) => `<details><summary>${esc(b.path)} — ${b.count} symbols (${b.arch})</summary><div style="max-height:200px;overflow:auto;font-family:monospace;font-size:12px">${b.sample.filter((x) => x.name).slice(0, 60).map((x) => `<div style="word-break:break-all;padding:1px 0">${esc(x.demangled || x.name)}${x.demangled ? ` <span class="note">← ${esc(x.name)}</span>` : ''}</div>`).join('')}</div></details>`).join('')}</div>`}
  </div>

  <div class="card"><h3>🔤 ObjC names (class-dump tables)</h3>
  ${objcn.classes ? `<p><b>${objcn.classes}</b> classes · <b>${objcn.methods}</b> methods${objcn.truncated ? ' <span class="tag note">truncated</span>' : ''}</p>${(objcn.binaries || []).slice(0, 2).map((b) => `<details><summary>${esc(b.path)} (${b.arch})</summary><div style="max-height:200px;overflow:auto;font-family:monospace;font-size:12px">${b.sample.map((x) => `<div>${esc(x)}</div>`).join('') || '<span class="note">none</span>'}</div></details>`).join('')}` : '<p class="note">No ObjC name tables found (or binary encrypted).</p>'}</div>

  <div class="card"><h3>🧭 Disassembly (Capstone 5 — real machine code)</h3>
  ${dis.ok === false ? `<p class="err">Engine: ${esc(dis.error || 'unavailable')}</p>` : `<p class="note">${dis.binaries && dis.binaries.length ? `${dis.binaries.reduce((n, b) => n + b.instructions, 0)} instructions auto-disassembled from __text. Pick a binary below for more.` : 'No readable __text section found (binary may be FairPlay-encrypted).'}</p>`}
  <div class="row"><select id="ds-file" style="flex:1;min-width:160px">${(ran['macho-metadata'] && ran['macho-metadata'].binaries || []).map((b, i) => `<option value="${i}">${esc(b.path)}</option>`).join('') || '<option>No Mach-O found</option>'}</select>
  <select id="ds-n"><option value="256">256 insns</option><option value="1024">1024 insns</option><option value="4096">4096 insns</option></select>
  <button class="btn sm" id="ds-run">Disassemble</button></div>
  <div id="ds-out"></div></div>

  <div class="card"><h3>🛡️ Security audit (MobSF-style static rules)</h3>
  ${audit.findings ? `<div class="grid" style="margin-bottom:8px"><div class="stat"><b class="err">${audit.score.high}</b><span>high</span></div><div class="stat"><b>${audit.score.medium}</b><span>medium</span></div><div class="stat"><b>${audit.score.low}</b><span>low</span></div><div class="stat"><b>${audit.score.info}</b><span>info</span></div></div>
  ${audit.findings.slice(0, 40).map((f) => `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><span class="tag ${sevColor[f.sev]}">${f.sev}</span> <b>${esc(f.title)}</b><div class="note">${esc(f.detail)}${f.where ? ' · ' + esc(f.where) : ''}</div></div>`).join('')}${audit.findings.length > 40 ? `<p class="note">…and ${audit.findings.length - 40} more.</p>` : ''}` : '<p class="note">Audit did not run.</p>'}</div>

  <div class="card"><h3>📦 Package managers</h3>
  ${(pkgs.manifests || []).length ? pkgs.manifests.map((m) => `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><span class="tag info">${esc(m.manager)}</span> <b>${esc(m.path)}</b>${m.count ? ` — ${m.count} entries` : ''}${m.note ? ` <span class="note">${esc(m.note)}</span>` : ''}
  ${m.pods && m.pods.length ? `<div style="max-height:180px;overflow:auto;font-family:monospace;font-size:12px">${m.pods.map((p) => `<div>${esc(p.name)} <span class="note">${esc(p.version || '')}</span></div>`).join('')}</div>` : ''}</div>`).join('') : '<p class="note">No Podfile.lock / Cartfile.resolved / Package.resolved inside this IPA.</p>'}
  ${pkgs.embeddedFrameworks && pkgs.embeddedFrameworks.length ? `<p class="note">Embedded frameworks: ${esc(pkgs.embeddedFrameworks.join(', '))}</p>` : ''}</div>

  <div class="card"><h3>🔎 Binary signatures (binwalk scan)</h3>
  ${sigTotal ? `<p><b>${sigTotal}</b> signatures across ${(sigs.files || []).length} files</p><details><summary>Show all</summary><div style="max-height:220px;overflow:auto;font-family:monospace;font-size:12px">${(sigs.files || []).map((f) => f.hits.map((h) => `<div>${esc(f.path)} @ 0x${h.offset.toString(16)} — ${esc(h.name)}</div>`).join('')).join('')}</div></details>` : '<p class="note">No embedded signatures found in scannable files.</p>'}</div>

  <div class="card"><h3>🧰 Every tool — status on this file</h3><p class="note">Each row is the real execution record. "desktop required" rows did NOT run — the reason is stated, nothing is simulated.</p>
  ${Object.entries(TOOLS.reduce((g, t) => { (g[t.group] ||= []).push(t); return g; }, {})).map(([group, tools]) => `<details open><summary><b>${esc(group)}</b> (${tools.length})</summary>${tools.map((t) => {
    const rec = r.records.find((x) => x.id === t.id) || {};
    return `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><b>${esc(t.name)}</b> ${statusChip(t)} ${toolChip(rec)} ${rec.ms !== undefined ? `<span class="tag note">${rec.ms} ms</span>` : ''}<div class="note">${esc(rec.summary && rec.summary !== 'subset ran' ? rec.summary : t.detail)}</div></div>`;
  }).join('')}</details>`).join('')}</div>`;
  bindDisasm(v);
}
async function bindDisasm(v) {
  const btn = $('#ds-run'); if (!btn) return;
  btn.onclick = async () => {
    const s = cur(); const i = parseInt($('#ds-file').value, 10); const n = parseInt($('#ds-n').value, 10);
    const out = $('#ds-out'); const recs = (s.tc.result.ran['macho-metadata'] && s.tc.result.ran['macho-metadata'].binaries) || [];
    const b = recs[i]; if (!b) { out.innerHTML = '<p class="note">Pick a binary first.</p>'; return; }
    out.innerHTML = '<p class="note">Loading Capstone engine and disassembling…</p>';
    try {
      const rec = s.model.files.find((f) => f.path === b.path);
      const { bytes } = await readRecBytes(s.file, rec, Math.min(rec.size, 64 << 20));
      const m = parseMachO(bytes);
      const sl = m.slices.find((x) => x.ok); if (!sl) throw new Error('No readable slice');
      const text = (sl.sections || []).find((x) => x.sect === '__text' && x.seg === '__TEXT');
      if (!text) throw new Error('No __text section');
      const seg = (sl.segments || []).find((x) => x.name === '__TEXT');
      const vmaddr = seg ? seg.vmaddr + (text.offset - seg.fileoff) : text.offset;
      const r = await disasm(bytes.subarray(text.offset, Math.min(text.offset + Math.min(text.size, DISASM_LIMITS.maxBytesPerRun), bytes.length)), sl.arch, vmaddr, { count: n });
      out.innerHTML = `<p class="note">${r.instructions.length} instructions from __text @ vmaddr 0x${vmaddr.toString(16)} (${esc(sl.arch)})</p><div style="max-height:340px;overflow:auto;font-family:monospace;font-size:11px">${r.instructions.map((x) => `<div>0x${x.address.toString(16).padStart(8, '0')}  ${esc(x.bytes)}  ${esc(x.mnemonic.padEnd(8))} ${esc(x.op)}</div>`).join('')}</div>`;
    } catch (e) { out.innerHTML = `<p class="err">Disassembly failed: ${esc(e.message)}</p>`; }
  };
}

// ---------- settings ----------
function viewSettings(v) {
  v.innerHTML = `<div class="card"><h3>Privacy</h3><p class="ok">🔒 Everything runs in this page. This site makes no network requests with your files, has no analytics, and its Content-Security-Policy blocks outbound connections.</p></div>
  <div class="card"><h3>Options</h3><label class="row"><input type="checkbox" id="s-hist" ${S.settings.history ? 'checked' : ''} style="width:22px;height:22px"> Keep a local list of inspected files (names only)</label>
  <label class="row" style="margin-top:8px"><input type="checkbox" id="s-deep" ${S.settings.deep ? 'checked' : ''} style="width:22px;height:22px"> Deep-verify exports with SHA-256 (slower)</label>
  <div class="row" style="margin-top:10px"><button class="btn alt sm" id="s-clear">Clear history</button></div></div>
  <div class="card"><h3>About limits</h3><p class="note">Browsers limit memory. Exports reference the original file instead of copying it, which keeps memory low, but very large IPAs (multiple GB) may still fail on a phone. If so, export selected folders.</p></div>`;
  $('#s-hist').onchange = (e) => { S.settings.history = e.target.checked; save('cairn.settings', S.settings); if (!e.target.checked) { S.history = []; save('cairn.history', []); } };
  $('#s-deep').onchange = (e) => { S.settings.deep = e.target.checked; save('cairn.settings', S.settings); };
  $('#s-clear').onclick = () => { S.history = []; save('cairn.history', []); toast('History cleared'); };
}

renderNav(); render();
