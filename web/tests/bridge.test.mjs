// Protocol-conformance test: runs the EXACT injected JS from
// ios/Sources/BridgeJS.swift against a mock of the native SaveBridge.
//
// Why this exists: v1.2.1 shipped chunk messages without the "name" field; the
// native side looked them up under its "export.zip" default, every transfer
// failed ("No active session for export.zip") and no chunk was ever ACKed
// ("the app did not confirm chunk 0"). This file fails if the JS and the
// native contract ever drift apart again.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const swift = fs.readFileSync(new URL('../../ios/Sources/BridgeJS.swift', import.meta.url), 'utf8');
const m = swift.match(/static let source = """\r?\n([\s\S]*?)"""/);
assert.ok(m, 'BridgeJS.source found in Swift source');
const injected = m[1];

class CustomEvent extends Event {
  constructor(type, init) { super(type); this.detail = (init && init.detail) || null; }
}

// Mock of the native SaveBridge protocol: begin registers a session, every
// chunk is ACKed (window event 'cairnsaveack'), finish resolves with
// 'cairnsaveok'. Mirrors SaveBridge.swift.
function makeEnv() {
  const messages = [];
  const window = new EventTarget();
  window.CustomEvent = CustomEvent;
  // The v1.4.x device bug: the page posted 'fetch' (and list/share/delete) to
  // the cairnSave channel, where SaveBridge silently ignored them — so the
  // "Images from a link" fetch never started and died on the 45 s watchdog.
  // This mock enforces the exact routing contract ContentView.swift installs:
  //   begin/chunk/finish/abort -> cairnSave, list/share/delete -> cairnFiles,
  //   fetch -> cairnFetch. A wrong channel throws and fails the test.
  const ROUTES = { begin: 'cairnSave', chunk: 'cairnSave', finish: 'cairnSave', abort: 'cairnSave', fetch: 'cairnFetch', list: 'cairnFiles', share: 'cairnFiles', delete: 'cairnFiles' };
  const native = {
    sessions: new Map(),
    exports: [{ name: 'X.zip', size: 123 }, { name: 'Y.zip', size: 456 }],
    fetchResponder: null, // per-test override; default answers a tiny PNG
    postMessage(msg) { // mirrors SaveBridge.swift
      if (msg.kind === 'begin') {
        this.sessions.set(msg.name, { received: 0 });
      } else if (msg.kind === 'chunk') {
        const s = this.sessions.get(msg.name);
        if (!s) {
          window.dispatchEvent(new CustomEvent('cairnsavefail', {
            detail: { name: msg.name ?? 'export.zip', message: `No active session for ${msg.name ?? 'export.zip'}` },
          }));
          return;
        }
        s.received += Buffer.from(msg.data ?? '', 'base64').length;
        queueMicrotask(() => window.dispatchEvent(new CustomEvent('cairnsaveack', {
          detail: { name: msg.name, index: msg.index, received: s.received },
        })));
      } else if (msg.kind === 'finish') {
        this.sessions.delete(msg.name);
        window.dispatchEvent(new CustomEvent('cairnsaveok', {
          detail: { name: msg.name, file: 'Exports/' + msg.name },
        }));
      }
    },
  };
  const respond = (type, detail) => queueMicrotask(() => window.dispatchEvent(new CustomEvent(type, { detail })));
  const filesHandler = (msg) => { // mirrors FilesBridge.swift
    if (msg.kind === 'list') respond('cairnfiles', { req: msg.req, files: native.exports });
    else if (msg.kind === 'delete') {
      native.exports = native.exports.filter((f) => f.name !== msg.name);
      respond('cairnfiles', { req: msg.req, files: native.exports });
    } else if (msg.kind === 'share') respond('cairnfiles', { req: msg.req, shared: msg.name });
  };
  const fetchHandler = (msg) => { // mirrors FetchBridge.swift
    if (native.fetchResponder) { native.fetchResponder(msg); return; }
    respond('cairnfetch', {
      req: msg.req, ok: true, status: 200, finalUrl: msg.url,
      data: Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]).toString('base64'),
    });
  };
  const post = (channel) => (msg) => {
    const expect = ROUTES[msg.kind];
    if (expect && expect !== channel) {
      throw new Error(`routing bug: "${msg.kind}" posted to ${channel} instead of ${expect} — the 45 s timeout bug`);
    }
    messages.push({ channel, ...msg });
    if (channel === 'cairnSave') native.postMessage(msg);
    else if (channel === 'cairnFiles') filesHandler(msg);
    else fetchHandler(msg);
  };
  window.webkit = { messageHandlers: {
    cairnSave: { postMessage: post('cairnSave') },
    cairnFiles: { postMessage: post('cairnFiles') },
    cairnFetch: { postMessage: post('cairnFetch') },
  } };
  return { window, messages, native };
}

function install(env) {
  const run = new Function('window', 'CustomEvent', injected);
  run(env.window, CustomEvent);
  assert.equal(typeof env.window.__cairnNativeSaver, 'function', '__cairnNativeSaver installed');
  return env.window.__cairnNativeSaver;
}

test('injected JS installs when the cairnSave handler exists', () => {
  const env = makeEnv();
  install(env);
});

test('every chunk message carries the file name (v1.2.1 regression)', async () => {
  const env = makeEnv();
  const saver = install(env);
  const bytes = new Uint8Array(2.5 * 1024 * 1024).fill(7);
  const ok = await saver(new Blob([bytes]), 'ORIGINAL_IPA_CONTENTS.zip', null, { chunkBytes: 512 * 1024 });
  assert.equal(ok, true, 'transfer must complete');
  const begin = env.messages.find((x) => x.kind === 'begin');
  assert.equal(begin.name, 'ORIGINAL_IPA_CONTENTS.zip');
  assert.equal(begin.size, bytes.length);
  const chunks = env.messages.filter((x) => x.kind === 'chunk');
  assert.ok(chunks.length >= 5, `expected >=5 chunks, got ${chunks.length}`);
  for (const c of chunks) {
    assert.equal(c.name, 'ORIGINAL_IPA_CONTENTS.zip', 'every chunk must carry the name');
    assert.equal(typeof c.index, 'number');
    assert.equal(typeof c.data, 'string');
  }
  const finish = env.messages.find((x) => x.kind === 'finish');
  assert.equal(finish.name, 'ORIGINAL_IPA_CONTENTS.zip');
  const total = chunks.reduce((n, c) => n + Buffer.from(c.data, 'base64').length, 0);
  assert.equal(total, bytes.length, 'all bytes delivered');
});

test('chunk indexes are sequential and strictly flow-controlled (ack before next chunk)', async () => {
  const env = makeEnv();
  const saver = install(env);
  // Sequence log: our mock ACKs from a setTimeout, so if the JS ever posts a
  // chunk without waiting for the previous ack it shows up immediately here.
  const seq = [];
  let ackTimer = null;
  env.native.postMessage = (msg) => {
    if (msg.kind === 'chunk') seq.push(`post:${msg.index}`);
    const s = msg.kind === 'begin' ? env.native.sessions.set(msg.name, { received: 0 })
      : msg.kind === 'chunk' ? env.native.sessions.get(msg.name) : null;
    if (msg.kind === 'chunk') {
      if (!s) return;
      s.received += Buffer.from(msg.data ?? '', 'base64').length;
      const idx = msg.index, name = msg.name;
      clearTimeout(ackTimer);
      ackTimer = setTimeout(() => {
        seq.push(`ack:${idx}`);
        env.window.dispatchEvent(new CustomEvent('cairnsaveack', { detail: { name, index: idx, received: s.received } }));
      }, 5);
    }
  };
  const bytes = new Uint8Array(3 * 1024 * 1024).fill(9);
  const ok = await saver(new Blob([bytes]), 'flow.zip', null, { chunkBytes: 1024 * 1024 });
  clearTimeout(ackTimer);
  assert.equal(ok, true);
  // strict alternation: post:0, ack:0, post:1, ack:1, post:2, ack:2
  assert.deepEqual(seq, ['post:0', 'ack:0', 'post:1', 'ack:1', 'post:2', 'ack:2'],
    `chunks must wait for the previous ack, sequence was: ${seq.join(' ')}`);
});

test('zero-byte file sends one named empty chunk and finishes', async () => {
  const env = makeEnv();
  const saver = install(env);
  const ok = await saver(new Blob([]), 'empty.zip');
  assert.equal(ok, true);
  const chunks = env.messages.filter((x) => x.kind === 'chunk');
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].name, 'empty.zip');
  assert.equal(chunks[0].data, '');
});

test('progress callback and cairnsaveprogress events fire during transfer', async () => {
  const env = makeEnv();
  const saver = install(env);
  const bytes = new Uint8Array(2 * 1024 * 1024).fill(1);
  const calls = [];
  const events = [];
  env.window.addEventListener('cairnsaveprogress', (e) => events.push(e.detail.pct));
  const ok = await saver(new Blob([bytes]), 'p.zip', (done, total) => calls.push([done, total]), { chunkBytes: 512 * 1024 });
  assert.equal(ok, true);
  assert.ok(calls.length >= 3, 'progress callback fired');
  assert.equal(calls[calls.length - 1][0], bytes.length);
  assert.ok(events.length >= 1, 'cairnsaveprogress events fired');
});

test('native failure resolves the wait immediately with the real reason', async () => {
  const env = makeEnv();
  const saver = install(env);
  // Broken bridge: nothing registers on begin; every chunk gets a native fail.
  env.native.postMessage = (msg) => {
    env.messages.push(msg);
    if (msg.kind === 'chunk') {
      env.window.dispatchEvent(new CustomEvent('cairnsavefail', {
        detail: { name: msg.name ?? 'export.zip', message: 'No active session for ' + (msg.name ?? 'export.zip') },
      }));
    }
  };
  const t0 = Date.now();
  const ok = await saver(new Blob([new Uint8Array(4096)]), 'broken.zip', null, { chunkBytes: 1024 });
  const dt = Date.now() - t0;
  assert.equal(ok, false);
  assert.ok(dt < 5000, `must fail fast on a native failure (took ${dt} ms, 15 s timeout means the fix regressed)`);
});

test('abort is posted when the transfer fails', async () => {
  const env = makeEnv();
  const saver = install(env);
  env.native.postMessage = (msg) => {
    env.messages.push(msg);
    if (msg.kind === 'chunk') {
      env.window.dispatchEvent(new CustomEvent('cairnsavefail', {
        detail: { name: msg.name ?? 'export.zip', message: 'No active session' },
      }));
    }
  };
  await saver(new Blob([new Uint8Array(2048)]), 'aborted.zip', null, { chunkBytes: 1024 });
  assert.ok(env.messages.some((x) => x.kind === 'abort' && x.name === 'aborted.zip'), 'abort message posted');
});

test('non-Blob input falls back to the browser download path (returns false)', async () => {
  const env = makeEnv();
  const saver = install(env);
  const ok = await saver({ size: 10 }, 'not-a-blob.zip');
  assert.equal(ok, false);
  assert.equal(env.messages.length, 0, 'no native messages for a non-Blob');
});

// ---------- window.__cairnFetch (native HTTP bridge for "Images from a link") ----------

test('routing contract: every kind travels on its own native channel (45 s-timeout regression)', async () => {
  const env = makeEnv();
  const saver = install(env);
  await saver(new Blob([new Uint8Array(4096)]), 'route.zip', null, { chunkBytes: 1024 });
  await env.window.__cairnFetch('https://example.com/a.png');
  await env.window.__cairnFiles.list();
  const byKind = Object.fromEntries(env.messages.map((m) => [m.kind, m.channel]));
  assert.equal(byKind.begin, 'cairnSave', 'begin -> cairnSave');
  assert.equal(byKind.chunk, 'cairnSave', 'chunk -> cairnSave');
  assert.equal(byKind.finish, 'cairnSave', 'finish -> cairnSave');
  assert.equal(byKind.fetch, 'cairnFetch', 'fetch -> cairnFetch (was cairnSave in v1.4.x: the 45 s timeout bug)');
  assert.equal(byKind.list, 'cairnFiles', 'list -> cairnFiles');
});

test('phone files list/delete run through the cairnFiles channel', async () => {
  const env = makeEnv();
  install(env);
  const d = await env.window.__cairnFiles.list();
  assert.ok(Array.isArray(d.files) && d.files.length === 2 && d.files[0].name === 'X.zip', `list resolves with real exports: ${JSON.stringify(d.files)}`);
  env.window.__cairnFiles.del('X.zip');
  await new Promise((r) => setTimeout(r, 10));
  const d2 = await env.window.__cairnFiles.list();
  assert.equal(d2.files.length, 1, 'delete really removed the file in the mock');
});

test('injected source wires each handler by name (cross-checked against ContentView.swift)', () => {
  const cv = fs.readFileSync(new URL('../../ios/Sources/ContentView.swift', import.meta.url), 'utf8');
  assert.match(injected, /handlers\.cairnSave/, 'saver channel referenced');
  assert.match(injected, /handlers\.cairnFiles/, 'files channel referenced');
  assert.match(injected, /handlers\.cairnFetch/, 'fetch channel referenced');
  assert.doesNotMatch(injected, /mh\.postMessage\(\{\s*kind:\s*'fetch'/, 'fetch must never be posted to the cairnSave handle');
  // every channel the JS speaks to must be registered natively (and vice versa)
  const sources = ['SaveBridge.swift', 'FetchBridge.swift', 'FilesBridge.swift']
    .map((f) => { try { return fs.readFileSync(new URL('../../ios/Sources/' + f, import.meta.url), 'utf8'); } catch { return ''; } })
    .join('\n');
  for (const name of ['cairnSave', 'cairnFiles', 'cairnFetch']) {
    assert.match(sources, new RegExp(`messageHandlerName\\s*=\\s*"${name}"`), `Swift defines the ${name} handler constant`);
  }
  const adds = cv.match(/userContent\.add\([A-Za-z]+, name: [A-Za-z]+\.messageHandlerName\)/g) || [];
  assert.ok(adds.length >= 3, `ContentView registers all three bridges via add(name:) — found ${adds.length}`);
});

test('__cairnFetch is installed together with the saver', () => {
  const env = makeEnv();
  install(env);
  assert.equal(typeof env.window.__cairnFetch, 'function', '__cairnFetch installed');
});

test('__cairnFetch posts a fetch message and resolves with the native response', async () => {
  const env = makeEnv();
  install(env);
  const res = await env.window.__cairnFetch('https://example.com/a.png', { maxBytes: 1 << 20 });
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  const bytes = new Uint8Array(Buffer.from(res.data, 'base64'));
  assert.deepEqual([...bytes], [0x89, 0x50, 0x4e, 0x47, 1, 2, 3], 'bytes survive the bridge roundtrip');
  const msg = env.messages.find((x) => x.kind === 'fetch');
  assert.equal(msg.channel, 'cairnFetch', 'the fetch rode the cairnFetch channel');
  assert.equal(msg.url, 'https://example.com/a.png');
  assert.equal(msg.maxBytes, 1 << 20);
  assert.equal(typeof msg.req, 'number');
});

test('__cairnFetch surfaces native errors (http status, bad scheme)', async () => {
  const env = makeEnv();
  install(env);
  env.native.fetchResponder = (msg) => {
    queueMicrotask(() => env.window.dispatchEvent(new CustomEvent('cairnfetch', {
      detail: { req: msg.req, ok: false, status: 404, error: 'HTTP 404 Not Found' },
    })));
  };
  const res = await env.window.__cairnFetch('https://example.com/missing.png');
  assert.equal(res.ok, false);
  assert.equal(res.error, 'HTTP 404 Not Found');
});

test('__cairnFetch resolves with a real error when the native side never answers (no dead wait)', async () => {
  const env = makeEnv();
  install(env);
  env.native.fetchResponder = () => { /* native never responds */ };
  // The injected timeout calls .unref() (correct for the app). In Node that
  // would let the event loop drain before the 300 ms timer fires, so hold the
  // loop open for the duration of this test only.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    const t0 = Date.now();
    const res = await env.window.__cairnFetch('https://example.com/slow.png', { timeoutMs: 300 });
    const dt = Date.now() - t0;
    assert.equal(res.ok, false);
    assert.ok(res.error.includes('timed out'), `got: ${res.error}`);
    assert.ok(dt < 5000, `must resolve via its own timeout (took ${dt} ms)`);
  } finally {
    clearInterval(keepAlive);
  }
});
