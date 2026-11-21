import Foundation

/// JS injected at documentEnd. Defines window.__cairnNativeSaver (feature-detected
/// by the web app) and hands over the "Open in Cairn" inbox file to the page.
enum BridgeJS {
    static let source = """
    (function () {
      'use strict';
      if (window.__cairnNativeInstalled) return;
      window.__cairnNativeInstalled = true;
      var mh = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.cairnSave;
      if (!mh) return; // normal Safari: keep the existing download path
      var CHUNK = 1024 * 1024; // 1 MB binary per message (~1.37 MB base64 body).
      // Large bodies (3-4 MB) were silently dropped by WebKit on device: the
      // 'begin'/'finish' messages arrived but every chunk was lost
      // ("Size mismatch: got 0 of N"). So each chunk is now ACKNOWLEDGED by the
      // native app before the next one is sent (flow control), and the chunk
      // size is small enough to pass any per-message limit.

      function b64(buf) {
        var u = new Uint8Array(buf), s = '';
        for (var i = 0; i < u.length; i += 0x8000) {
          s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + 0x8000, u.length)));
        }
        return btoa(s);
      }

      // Streams a Blob to the native app: begin -> (chunk -> ack)* -> finish | abort.
      // Returns true when the native path handled the export.
      window.__cairnNativeSaver = async function (blob, name, onProgress, opts) {
        var NAME = String(name);
        try {
          if (!(blob instanceof Blob)) return false;
          var total = blob.size;
          var chunkBytes = (opts && opts.chunkBytes) || CHUNK;
          var acked = -1, waiter = null, nativeFail = null;
          var onAck = function (ev) {
            var d = (ev && ev.detail) || {};
            if (String(d.name) === NAME) {
              acked = Math.max(acked, d.index | 0);
              // resolve(true): the waiter resolves the waitAck promise — calling
              // it with NO argument resolved to undefined (falsy) and even a
              // successful ACK was treated as "did not confirm chunk N".
              if (waiter) { var w = waiter; waiter = null; w(true); }
            }
          };
          // If the native app reports a failure while we are waiting for an ack,
          // resolve the waiter immediately with the real reason (no 15 s dead wait).
          var onFail = function (ev) {
            var d = (ev && ev.detail) || {};
            if (String(d.name) === NAME && !nativeFail) {
              nativeFail = String(d.message || 'save failed');
              if (waiter) { var w = waiter; waiter = null; w(false); }
            }
          };
          window.addEventListener('cairnsaveack', onAck);
          window.addEventListener('cairnsavefail', onFail);
          var waitAck = function (index) {
            return new Promise(function (resolve) {
              // A native failure may have arrived before we started waiting
              // (it is dispatched synchronously with the message on the mock
              // and can race the microtask in the app) — never wait 15 s for it.
              if (nativeFail) { resolve(false); return; }
              if (acked >= index) { resolve(true); return; }
              waiter = resolve;
              var t = setTimeout(function () { if (waiter === resolve) { waiter = null; resolve(false); } }, 15000);
              if (t && typeof t.unref === 'function') { t.unref(); } // don't pin the page/test-runner to a settled wait
            });
          };
          try {
            mh.postMessage({ kind: 'begin', name: NAME, size: total });
            var off = 0, idx = 0, lastPct = 0;
            while (off < total) {
              var end = Math.min(off + chunkBytes, total);
              var buf = await blob.slice(off, end).arrayBuffer();
              // NOTE: every message carries the file name — the native side keys
              // its sessions by name, and a chunk without one used to be looked
              // up under the default ("export.zip"), failing every transfer
              // ("No active session for export.zip").
              mh.postMessage({ kind: 'chunk', name: NAME, index: idx, data: b64(buf) });
              var ok = await waitAck(idx);
              if (!ok) {
                throw new Error(nativeFail
                  ? ('the app reported: ' + nativeFail)
                  : ('the app did not confirm chunk ' + idx + ' — transfer stopped'));
              }
              off = end; idx++;
              if (onProgress) { try { onProgress(off, total); } catch (e) {} }
              if (total > 0) {
                var pct = Math.floor((off / total) * 100);
                if (pct >= lastPct + 25) {
                  lastPct += 25;
                  try { window.dispatchEvent(new CustomEvent('cairnsaveprogress', { detail: { name: NAME, pct: Math.min(pct, 100) } })); } catch (e) {}
                }
              }
            }
            if (total === 0) {
              mh.postMessage({ kind: 'chunk', name: NAME, index: 0, data: '' });
              var ok0 = await waitAck(0);
              if (!ok0) {
                throw new Error(nativeFail
                  ? ('the app reported: ' + nativeFail)
                  : 'the app did not confirm the empty file');
              }
            }
            mh.postMessage({ kind: 'finish', name: NAME });
            return true;
          } finally {
            window.removeEventListener('cairnsaveack', onAck);
            window.removeEventListener('cairnsavefail', onFail);
          }
        } catch (e) {
          var msg = String(e && e.message || e);
          // Native may have already shown the reason (cairnsavefail) — avoid a
          // second, less precise toast for the same failure.
          try { if (!nativeFail) window.dispatchEvent(new CustomEvent('cairnsavefail', { detail: { name: NAME, message: msg } })); } catch (e2) {}
          try { mh.postMessage({ kind: 'abort', name: NAME, error: msg }); } catch (e3) {}
          return false;
        }
      };

      // Phone files: list / re-share / remove files saved in Documents/Exports.
      var reqId = 0, pending = {};
      window.addEventListener('cairnfiles', function (ev) {
        var d = ev && ev.detail || {};
        if (d.req && pending[d.req]) { pending[d.req](d); delete pending[d.req]; }
      });
      window.__cairnFiles = {
        list: function () {
          return new Promise(function (resolve) {
            var r = ++reqId; pending[r] = resolve;
            try { mh.postMessage({ kind: 'list', req: r }); } catch (e) { delete pending[r]; resolve({ files: [] }); }
            setTimeout(function () { if (pending[r]) { delete pending[r]; resolve({ files: [] }); } }, 4000);
          });
        },
        share: function (name) { try { mh.postMessage({ kind: 'share', name: String(name) }); } catch (e) {} },
        del: function (name) { try { mh.postMessage({ kind: 'delete', name: String(name) }); } catch (e) {} }
      };

      // Native HTTP fetch for the "Images from a link" feature. The page's CSP
      // blocks web-side network access by design, so this request goes out
      // through the app instead — only when the page asks for it, only for
      // http(s) URLs, with a hard byte cap enforced natively.
      var fetchReq = 0, fetchPending = {};
      window.addEventListener('cairnfetch', function (ev) {
        var d = ev && ev.detail || {};
        if (d.req && fetchPending[d.req]) { fetchPending[d.req](d); delete fetchPending[d.req]; }
      });
      window.__cairnFetch = function (url, opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
          var r = ++fetchReq; fetchPending[r] = resolve;
          try {
            mh.postMessage({ kind: 'fetch', req: r, url: String(url), maxBytes: opts.maxBytes || 8 * 1024 * 1024 });
          } catch (e) {
            delete fetchPending[r];
            resolve({ ok: false, error: 'bridge send failed' });
            return;
          }
          var t = setTimeout(function () {
            if (fetchPending[r]) { delete fetchPending[r]; resolve({ ok: false, error: 'timed out after ' + ((opts.timeoutMs || 45000) / 1000) + ' s' }); }
          }, opts.timeoutMs || 45000);
          if (t && typeof t.unref === 'function') { t.unref(); }
        });
      };

      // Hand over the "Open in Cairn" inbox file (same-origin alias, so CSP holds).
      fetch('cairn://app/inbox/current').then(function (r) {
        if (!r.ok) return null;
        return r.blob();
      }).then(function (blob) {
        if (!blob || blob.size === 0) return;
        var name = 'inbox-' + new Date().toISOString().replace(/[:.]/g, '-') + '.ipa';
        var file = new File([blob], name, { type: 'application/octet-stream' });
        var tries = 0;
        (function tryOpen() {
          if (typeof window.__cairnOpenFiles === 'function') {
            window.__cairnOpenFiles([file]);
          } else if (++tries < 20) {
            setTimeout(tryOpen, 250);
          }
        })();
      }).catch(function () { /* no inbox file */ });
    })();
    """
}
