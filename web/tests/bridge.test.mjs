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
  const native = {
    sessions: new Map(),
    postMessage(msg) {
      messages.push(msg);
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
  window.webkit = { messageHandlers: { cairnSave: { postMessage: (x) => native.postMessage(x) } } };
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

test('__cairnFetch is installed together with the saver', () => {
  const env = makeEnv();
  install(env);
  assert.equal(typeof env.window.__cairnFetch, 'function', '__cairnFetch installed');
});

test('__cairnFetch posts a fetch message and resolves with the native response', async () => {
  const env = makeEnv();
  install(env);
  const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
  env.native.postMessage = (msg) => {
    env.messages.push(msg);
    if (msg.kind === 'fetch') {
      queueMicrotask(() => env.window.dispatchEvent(new CustomEvent('cairnfetch', {
        detail: {
          req: msg.req, ok: true, status: 200,
          finalUrl: msg.url,
          data: Buffer.from(PNG).toString('base64'),
        },
      })));
    }
  };
  const res = await env.window.__cairnFetch('https://example.com/a.png', { maxBytes: 1 << 20 });
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  const bytes = new Uint8Array(Buffer.from(res.data, 'base64'));
  assert.deepEqual([...bytes], [...PNG], 'bytes survive the bridge roundtrip');
  const msg = env.messages.find((x) => x.kind === 'fetch');
  assert.equal(msg.url, 'https://example.com/a.png');
  assert.equal(msg.maxBytes, 1 << 20);
  assert.equal(typeof msg.req, 'number');
});

test('__cairnFetch surfaces native errors (http status, bad scheme)', async () => {
  const env = makeEnv();
  install(env);
  env.native.postMessage = (msg) => {
    env.messages.push(msg);
    if (msg.kind === 'fetch') {
      queueMicrotask(() => env.window.dispatchEvent(new CustomEvent('cairnfetch', {
        detail: { req: msg.req, ok: false, status: 404, error: 'HTTP 404 Not Found' },
      })));
    }
  };
  const res = await env.window.__cairnFetch('https://example.com/missing.png');
  assert.equal(res.ok, false);
  assert.equal(res.error, 'HTTP 404 Not Found');
});

test('__cairnFetch resolves with a real error when the native side never answers (no dead wait)', async () => {
  const env = makeEnv();
  install(env);
  env.native.postMessage = () => { /* native never responds */ };
  const t0 = Date.now();
  const res = await env.window.__cairnFetch('https://example.com/slow.png', { timeoutMs: 300 });
  const dt = Date.now() - t0;
  assert.equal(res.ok, false);
  assert.ok(res.error.includes('timed out'), `got: ${res.error}`);
  assert.ok(dt < 5000, `must resolve via its own timeout (took ${dt} ms)`);
});
