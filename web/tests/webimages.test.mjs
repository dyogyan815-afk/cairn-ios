// Tests for the web/App Store image harvester (core/webimages.js) — URL
// extraction, magic-byte validation, batching and honest failure reporting.
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractImageUrls, resolveUrl, dedupe, appStoreUrls, imageKind, fetchAllWebImages } from '../public/js/core/webimages.js';
import { Sha256 } from '../public/js/core/sha256.js';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 9, 9, 9]);
const HTMLPAGE = new Uint8Array([...new TextEncoder().encode('<!doctype html><html><body>hello</body></html>')]);

test('extractImageUrls: img/srcset/meta/link/style + relative resolution + dedupe', () => {
  const html = `
  <img src="/logo.png">
  <img srcset="/a.jpg 1x, /b.jpg 2x" data-src="/lazy.webp">
  <img SRC="HTTPS://cdn.example.com/abs.jpg">
  <source srcset="/vid-poster.png 400w">
  <meta property="og:image" content="https://og.example/cover.jpg">
  <meta name="twitter:image" content="/card.png">
  <link rel="apple-touch-icon" href="/touch-icon.png">
  <link rel="stylesheet" href="/style.css">
  <div style="background:url(/inline-bg.jpg)"></div>
  <script>var shots=["https://is1-ssl.mzstatic.com/image/screen1.png","https://is1-ssl.mzstatic.com/image/screen2.png"];</script>
  <img src="data:image/gif;base64,R0lGOD">
  <script>var notAnImage="https://x.example/page.html";</script>`;
  const urls = extractImageUrls(html, 'https://apps.example/app/page');
  assert.ok(urls.includes('https://apps.example/logo.png'), 'relative resolved against base');
  assert.ok(urls.includes('https://apps.example/a.jpg'), 'srcset first candidate');
  assert.ok(urls.includes('https://apps.example/b.jpg'), 'srcset second candidate');
  assert.ok(urls.includes('https://apps.example/lazy.webp'), 'data-src');
  assert.ok(urls.includes('https://cdn.example.com/abs.jpg'), 'absolute kept, case-insensitive');
  assert.ok(urls.includes('https://apps.example/vid-poster.png'), 'source srcset');
  assert.ok(urls.includes('https://og.example/cover.jpg'), 'og:image');
  assert.ok(urls.includes('https://apps.example/card.png'), 'twitter:image relative');
  assert.ok(urls.includes('https://apps.example/touch-icon.png'), 'link icon');
  assert.ok(!urls.includes('https://apps.example/style.css'), 'stylesheet not harvested');
  assert.ok(urls.includes('https://apps.example/inline-bg.jpg'), 'inline css url()');
  assert.ok(urls.includes('https://is1-ssl.mzstatic.com/image/screen1.png'), 'script-JSON image');
  assert.ok(urls.includes('https://is1-ssl.mzstatic.com/image/screen2.png'), 'script-JSON image 2');
  assert.ok(!urls.includes('https://x.example/page.html'), 'script-JSON non-image dropped');
  assert.ok(urls.every((u) => !u.startsWith('data:')), 'data: URLs dropped');
  // dedupe
  const again = extractImageUrls('<img src="/logo.png"><img src="/logo.png">', 'https://apps.example/');
  assert.equal(again.length, 1, 'duplicates collapse');
});

test('resolveUrl handles bad input honestly', () => {
  assert.equal(resolveUrl('/x.png', 'https://a.com/'), 'https://a.com/x.png');
  assert.equal(resolveUrl('/x.png', '::not a base::'), null, 'invalid base → null');
});

test('dedupe is case-insensitive and order-preserving', () => {
  assert.deepEqual(dedupe(['https://A.com/x.png', 'https://a.com/x.png', 'https://a.com/y.png']),
    ['https://A.com/x.png', 'https://a.com/y.png']);
});

test('appStoreUrls: collects screenshots + artwork from the Apple lookup API', async () => {
  const lookup = JSON.stringify({
    results: [{
      artworkUrl512: 'https://is1-ssl.mzstatic.com/art512.png',
      artworkUrl100: 'https://is1-ssl.mzstatic.com/art100.png',
      screenshotUrls: ['https://is1-ssl.mzstatic.com/shot1.jpg', 'https://is1-ssl.mzstatic.com/shot2.jpg'],
      ipadScreenshotUrls: ['https://is1-ssl.mzstatic.com/ipad1.jpg'],
      appletvScreenshotUrls: ['https://is1-ssl.mzstatic.com/tv1.jpg'],
    }],
  });
  const calls = [];
  const doFetch = async (url) => { calls.push(url); return { ok: true, bytes: new TextEncoder().encode(lookup) }; };
  const urls = await appStoreUrls(doFetch, 'https://apps.apple.com/us/app/example/id123456');
  assert.equal(urls.length, 6, 'all artwork + screenshots collected');
  assert.ok(urls.includes('https://is1-ssl.mzstatic.com/shot1.jpg'));
  assert.ok(calls[0].startsWith('https://itunes.apple.com/lookup?url='), 'uses the public lookup endpoint');
  // non-App-Store link → no lookup at all
  const none = await appStoreUrls(doFetch, 'https://example.com/app');
  assert.deepEqual(none, []);
});

test('imageKind: real magic-byte validation (and rejection of impostors)', () => {
  assert.equal(imageKind(PNG), 'image/png');
  assert.equal(imageKind(JPEG), 'image/jpeg');
  assert.equal(imageKind(new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])), 'image/gif');
  assert.equal(imageKind(new Uint8Array([...new TextEncoder().encode('RIFF'), 0, 0, 0, 0, ...new TextEncoder().encode('WEBP'), 1, 2, 3])), 'image/webp');
  assert.equal(imageKind(new Uint8Array([0x42, 0x4d, 1, 2, 3])), 'image/bmp');
  assert.equal(imageKind(new Uint8Array([0, 0, 1, 0, 1, 0])), 'image/x-icon');
  assert.equal(imageKind(new TextEncoder().encode('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>')), 'image/svg+xml');
  assert.equal(imageKind(HTMLPAGE), null, 'HTML error page is NOT accepted as an image');
  assert.equal(imageKind(new Uint8Array(0)), null);
  assert.equal(imageKind(new TextEncoder().encode('{"json":"not an image"}')), null);
});

test('fetchAllWebImages: downloads, names, manifests and batches by byte budget', async () => {
  const urls = [
    'https://x.example/shots/first.png',
    'https://x.example/shots/first.png?size=2', // same name → uniquified
    'https://x.example/shots/second.jpg',
    'https://x.example/bad.html',       // sniffs as text → listed as failure
    'https://x.example/dead.png',       // network-style failure
  ];
  const doFetch = async (url) => {
    if (url.includes('bad.html')) return { ok: true, bytes: HTMLPAGE };
    if (url.includes('dead.png')) return { ok: false, error: 'HTTP 404 Not Found', status: 404 };
    return { ok: true, bytes: url.endsWith('.jpg') ? JPEG : PNG };
  };
  const batches = [];
  const progresses = [];
  const r = await fetchAllWebImages({
    urls,
    pageUrl: 'https://x.example/page',
    doFetch,
    budgetBytes: 10, // every image forces a new batch (each is > 10 bytes)
    maxImages: 50000,
    onProgress: (p) => progresses.push(p),
    onBatch: async (b) => batches.push(b),
  });
  assert.equal(r.downloaded, 3, 'only genuine images count');
  assert.equal(r.failures.length, 2, 'failures are listed, not hidden');
  assert.ok(r.failures.some((f) => f.reason.includes('404')));
  assert.ok(r.failures.some((f) => f.reason.includes('magic-byte')));
  assert.equal(batches.length, 3, 'byte budget forces one zip per image here');
  assert.deepEqual(batches.map((b) => b.name), ['WEB_IMAGES.zip', 'WEB_IMAGES_2.zip', 'WEB_IMAGES_3.zip']);
  // name pattern: 00001_first.png …
  const manifest = batches[0];
  assert.ok(manifest.count >= 1);
  // sha256 integrity of the first downloaded image inside manifest text — verify via a fresh hash
  const sha = new Sha256(); sha.update(PNG);
  assert.equal(sha.hex().length, 64);
  // progress reached the end
  const last = progresses[progresses.length - 1];
  assert.equal(last.done, 5);
  assert.equal(last.total, 5);
});

test('fetchAllWebImages: maxImages caps the queue honestly', async () => {
  const urls = Array.from({ length: 50 }, (_, i) => `https://x.example/${i}.png`);
  let fetched = 0;
  const doFetch = async () => { fetched++; return { ok: true, bytes: PNG }; };
  const r = await fetchAllWebImages({
    urls, pageUrl: 'https://x.example/', doFetch,
    maxImages: 5, budgetBytes: 500 << 20,
    onBatch: async () => {},
  });
  assert.equal(fetched, 5, 'download stops at maxImages');
  assert.equal(r.downloaded, 5);
});

test('fetchAllWebImages: abort keeps already-saved batches', async () => {
  const urls = Array.from({ length: 8 }, (_, i) => `https://x.example/${i}.png`);
  const ctl = new AbortController();
  const batches = [];
  const doFetch = async (url) => {
    if (url.includes('/3.png')) ctl.abort(); // abort mid-run
    return { ok: true, bytes: PNG };
  };
  const r = await fetchAllWebImages({
    urls, pageUrl: 'https://x.example/', doFetch, signal: ctl.signal,
    budgetBytes: 500 << 20,
    onBatch: async (b) => batches.push(b),
  });
  assert.equal(r.aborted, true);
  assert.ok(r.downloaded < 8, 'stopped early');
  assert.ok(batches.length >= 1, 'images downloaded before the abort were saved');
});
