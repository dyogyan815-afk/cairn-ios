// Web / App Store image harvester for the "Hidden images in compiled files"
// card. Given a link the user pastes (an App Store page or any website), it
// collects every image the page references, downloads the images through the
// native bridge (window.__cairnFetch — plain-web fetch is attempted too and
// reports honestly when the environment blocks it), validates each download
// with the same magic-byte checking the in-app tools use, and packages them
// in batches so even tens of thousands of images stream to the phone without
// exhausting memory. Nothing is fabricated: failures are listed, not hidden.

import { ZipWriter } from './zip-writer.js';
import { Sha256 } from './sha256.js';

const IMG_EXT_RE = /\.(jpe?g|png|gif|webp|bmp|ico|svg|heic|heif|avif|tiff?)(?:[?#].*)?$/i;

/** Resolve a possibly-relative URL against a base. Returns null when invalid. */
export function resolveUrl(u, base) {
  try { return new URL(String(u).trim(), base).href; } catch { return null; }
}

function attr(tag, name) {
  const m = tag.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : '';
}

/** Pull every image candidate out of an HTML page.
 * Covers: img/source (src, data-src, srcset), meta og:image / twitter:image,
 * link rel icons / image_src, inline CSS url(...), and image URLs quoted
 * inside <script> JSON blobs (how App Store / gallery pages embed shots). */
export function extractImageUrls(html, baseUrl) {
  const found = [];
  const push = (u) => {
    if (!u) return;
    const clean = String(u).trim().replace(/^["'\s]+|["'\s]+$/g, '');
    if (!clean || clean.startsWith('data:') || clean.startsWith('blob:') || clean.startsWith('javascript:')) return;
    const abs = resolveUrl(clean, baseUrl);
    if (abs && /^https?:/i.test(abs)) found.push(abs);
  };
  html = String(html || '');
  // <img> and <source> tags — tag presence proves these are images
  for (const tag of html.match(/<(img|source)\b[^>]*>/gi) || []) {
    push(attr(tag, 'src')); push(attr(tag, 'data-src')); push(attr(tag, 'data-srcset')); push(attr(tag, 'data-original')); push(attr(tag, 'data-lazy-src'));
    const ss = attr(tag, 'srcset');
    if (ss) for (const cand of ss.split(',')) push(cand.trim().split(/\s+/)[0]);
  }
  // <meta> og/twitter images
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const prop = attr(tag, 'property') || attr(tag, 'name');
    if (/^(og:image|twitter:image|twitter:image:src|og:image:url|og:image:secure_url)$/i.test(prop)) push(attr(tag, 'content'));
  }
  // <link rel=icon / apple-touch-icon / image_src>
  for (const tag of html.match(/<link\b[^>]*>/gi) || []) {
    const rel = attr(tag, 'rel');
    if (/icon|image_src|apple-touch/i.test(rel)) push(attr(tag, 'href'));
  }
  // inline CSS url(...)
  for (const m of html.match(/url\(\s*['"]?[^)'"]+['"]?\s*\)/gi) || []) push(m.replace(/^url\(\s*['"]?|['"]?\s*\)$/g, ''));
  // image URLs quoted inside script JSON (App Store screenshots, galleries)
  for (const m of html.match(/"(https?:[^"\\\s]+?)"/gi) || []) {
    const u = m.slice(1, -1).replace(/\\\//g, '/').replace(/\\u002F/gi, '/');
    if (IMG_EXT_RE.test(u)) push(u);
  }
  return dedupe(found);
}

/** App Store link → all artwork + screenshots via Apple's public lookup API.
 * Returns [] for non-App-Store links or when the lookup finds nothing. */
export async function appStoreUrls(doFetch, pageUrl) {
  let u;
  try { u = new URL(pageUrl); } catch { return []; }
  if (!/apps\.apple\.com|itunes\.apple\.com/i.test(u.hostname)) return [];
  const res = await doFetch(`https://itunes.apple.com/lookup?url=${encodeURIComponent(pageUrl)}`, { maxBytes: 4 << 20 });
  if (!res || !res.ok || !res.bytes) return [];
  try {
    const j = JSON.parse(new TextDecoder().decode(res.bytes));
    const out = [];
    for (const r of j.results || []) {
      for (const k of ['artworkUrl512', 'artworkUrl100', 'artworkUrl60']) if (r[k]) out.push(r[k]);
      for (const arr of [r.screenshotUrls, r.ipadScreenshotUrls, r.appletvScreenshotUrls]) for (const s of arr || []) out.push(s);
    }
    return dedupe(out);
  } catch { return []; }
}

/** Case-insensitive, order-preserving dedupe. */
export function dedupe(list) {
  const seen = new Set(), out = [];
  for (const u of list) { const k = u.toLowerCase(); if (!seen.has(k)) { seen.add(k); out.push(u); } }
  return out;
}

/** Every <a href> on a page that stays on the same site — used by crawlSite to
 * walk the app's website so images from all its pages are collected, not only
 * the landing page. Skips non-http links, in-page anchors, and direct image
 * URLs (those are images, not pages to crawl). */
export function extractPageLinks(html, baseUrl, keepHost) {
  const out = [];
  for (const tag of String(html || '').match(/<a\b[^>]*>/gi) || []) {
    const href = attr(tag, 'href');
    if (!href || href.startsWith('#')) continue; // in-page anchor, not a page
    const abs = resolveUrl(href, baseUrl);
    if (!abs || !/^https?:/i.test(abs)) continue;
    let u; try { u = new URL(abs); } catch { continue; }
    if (keepHost && u.hostname.toLowerCase() !== keepHost.toLowerCase()) continue;
    if (IMG_EXT_RE.test(u.pathname)) continue; // that IS an image, not a page
    out.push(abs);
  }
  return dedupe(out);
}

/** Walk an app's website (the page the user pasted plus same-site pages it
 * links to) and collect every image URL found on each real page fetched.
 * Bounded honestly: maxPages real page fetches, nothing invented. Progress
 * reports each page so the UI can show real movement. */
export async function crawlSite({ startUrl, firstHtml, doFetch, signal, maxPages = 40, onProgress = () => {} }) {
  const base = (() => { try { return new URL(startUrl); } catch { return null; } })();
  if (!base) return { images: [], pagesVisited: 0, pagesFailed: 0 };
  const keepHost = base.hostname;
  const images = dedupe(extractImageUrls(firstHtml || '', startUrl));
  const queue = dedupe(extractPageLinks(firstHtml || '', startUrl, keepHost))
    .filter((u) => u !== startUrl)
    .slice(0, maxPages);
  const visited = new Set([startUrl]);
  let pagesVisited = 1, pagesFailed = 0, i = 0;
  for (const pageUrl of queue) {
    if (signal && signal.aborted) break;
    if (visited.has(pageUrl)) continue;
    visited.add(pageUrl);
    onProgress({ page: i + 1, total: queue.length + 1, url: pageUrl });
    i++;
    let page;
    try { page = await doFetch(pageUrl, { maxBytes: 8 << 20 }); } catch { pagesFailed++; continue; }
    pagesVisited++;
    if (!page || !page.ok || !page.bytes) { pagesFailed++; continue; }
    const html = new TextDecoder('utf-8', { fatal: false }).decode(page.bytes);
    for (const u of extractImageUrls(html, page.finalUrl || pageUrl)) images.push(u);
  }
  return { images: dedupe(images), pagesVisited, pagesFailed };
}

const SAFE_BASE = (s) => (String(s).split('?')[0].split('#')[0].split('/').pop() || '').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 48).replace(/^_+|_+$/g, '');

/** Real magic-byte validation of a downloaded image. Returns a MIME kind or
 * null when the bytes are not a genuine image (the same check in-app tools
 * apply to every file they report). */
export function imageKind(u8) {
  const n = u8 && u8.length;
  if (!n) return null;
  const is = (...b) => b.every((v, i) => u8[i] === v);
  const latin = (o, l) => String.fromCharCode.apply(null, u8.subarray(o, Math.min(o + l, n)));
  if (n >= 8 && is(0x89, 0x50, 0x4e, 0x47)) return 'image/png';
  if (n >= 3 && is(0xff, 0xd8, 0xff)) return 'image/jpeg';
  if (n >= 4 && is(0x47, 0x49, 0x46, 0x38)) return 'image/gif';
  if (n >= 12 && latin(0, 4) === 'RIFF' && latin(8, 4) === 'WEBP') return 'image/webp';
  if (n >= 2 && is(0x42, 0x4d)) return 'image/bmp';
  if (n >= 4 && (is(0, 0, 1, 0) || is(0, 0, 2, 0))) return 'image/x-icon';
  if (n >= 12 && latin(4, 4) === 'ftyp' && /heic|heix|hevc|hevx|mif1|msf1/i.test(latin(8, 4))) return 'image/heic';
  const head = latin(0, Math.min(n, 1024));
  if (/<svg[\s>]/i.test(head) && (/^\s*(<\?xml|<svg)/i.test(head) || /^\s*(<\?xml)/i.test(head))) return 'image/svg+xml';
  return null;
}

const EXT_OF = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp', 'image/bmp': 'bmp', 'image/x-icon': 'ico', 'image/svg+xml': 'svg', 'image/heic': 'heic', 'image/tiff': 'tif' };

/** Download every URL, validate, and hand completed batches to onBatch.
 * doFetch(url, {maxBytes}) -> {ok, status?, bytes?:Uint8Array, error?}.
 * Batch boundaries are driven by budgetBytes so memory stays bounded no
 * matter how many images the source page holds. Concurrency-safe: whichever
 * worker crosses the threshold flushes, the others join the next batch. */
export async function fetchAllWebImages({ urls, pageUrl, doFetch, onBatch, onProgress, signal, budgetBytes = 220 << 20, maxImages = 50000, perImageMaxBytes = 25 << 20, concurrency = 6 }) {
  const failures = [];
  let downloaded = 0, bytesTotal = 0, batchIndex = 0;
  const savedBatches = [];
  let zw = null, batchCount = 0, batchBytes = 0, manifest = [];
  const usedNames = new Map();
  let nextIndex = 1;

  const startBatch = () => {
    zw = new ZipWriter(); batchCount = 0; batchBytes = 0;
    manifest = [`WEB_IMAGES — batch ${batchIndex + 1}`, `source page: ${pageUrl}`, `generated: ${new Date().toISOString()}`, '', 'file\tsource URL\tbytes\tkind\tsha256'];
  };
  const flushBatch = async () => {
    if (!zw || !batchCount) return;
    const z = zw, cnt = batchCount, man = manifest, bb = batchBytes;
    zw = null; batchCount = 0; batchBytes = 0; // other workers start a fresh batch
    man.push('', `batch total: ${cnt} images, ${bb} bytes`);
    z.addBytes('WEB_IMAGES/MANIFEST.txt', man.join('\n'));
    const name = `WEB_IMAGES${batchIndex ? '_' + (batchIndex + 1) : ''}.zip`;
    batchIndex++;
    const blob = z.finish();
    await onBatch({ name, blob, count: cnt, bytes: bb });
    savedBatches.push({ name, count: cnt, bytes: bb });
  };

  const takeOne = async (url) => {
    if (signal && signal.aborted) return; // no NEW fetches after abort
    const res = await doFetch(url, { maxBytes: perImageMaxBytes });
    if (!res || !res.ok || !res.bytes || !res.bytes.length) {
      failures.push({ url, reason: res && res.error ? res.error : `HTTP ${res && res.status || 'error'}` });
      return;
    }
    const kind = imageKind(res.bytes);
    if (!kind) { failures.push({ url, reason: 'not an image (magic-byte check failed)' }); return; }
    // The bytes are real and already here: they are kept even when an abort
    // lands mid-run — only fetches that have not started yet are skipped.
    if (!zw) startBatch(); // another worker may be mid-flush
    const ext = EXT_OF[kind] || (IMG_EXT_RE.exec(url) || [])[1] || 'img';
    const stem = SAFE_BASE(url) || 'image';
    let name = `${stem}.${ext}`;
    const n = usedNames.get(name) || 0; usedNames.set(name, n + 1);
    if (n) name = `${stem}_${n}.${ext}`;
    name = `${String(nextIndex++).padStart(5, '0')}_${name}`;
    const sha = new Sha256(); sha.update(res.bytes);
    zw.addBytes(`WEB_IMAGES/${name}`, res.bytes);
    manifest.push(`${name}\t${url}\t${res.bytes.length}\t${kind}\t${sha.hex()}`);
    batchCount++; batchBytes += res.bytes.length; bytesTotal += res.bytes.length;
    downloaded++;
    if (batchBytes >= budgetBytes || batchCount >= 3000) await flushBatch();
    if (!zw) startBatch();
  };

  const queue = urls.slice(0, maxImages).map((u) => () => takeOne(u));
  let cursor = 0, settled = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      if (signal && signal.aborted) return;
      const job = queue[cursor++];
      try { await job(); } catch (e) { failures.push({ url: 'unknown', reason: e && e.message || String(e) }); }
      settled++;
      if (onProgress) onProgress({ done: settled, total: queue.length, downloaded, failed: failures.length, batchIndex });
    }
  };
  if (queue.length) startBatch();
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, queue.length)) }, worker));
  await flushBatch(); // the final, possibly partial batch
  return { downloaded, failures, batches: savedBatches, aborted: !!(signal && signal.aborted), bytesTotal };
}
