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
      var CHUNK = 3 * 1024 * 1024; // 3 MB chunks (spec: 1-4 MB)

      function b64(buf) {
        var u = new Uint8Array(buf), s = '';
        for (var i = 0; i < u.length; i += 0x8000) {
          s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + 0x8000, u.length)));
        }
        return btoa(s);
      }

      // Streams a Blob to the native app: begin -> chunk* -> finish | abort.
      // Returns true when the native path handled the export.
      window.__cairnNativeSaver = async function (blob, name, onProgress) {
        try {
          if (!(blob instanceof Blob)) return false;
          var total = blob.size;
          var totalChunks = Math.max(1, Math.ceil(total / CHUNK));
          mh.postMessage({ kind: 'begin', name: String(name), size: total, totalChunks: totalChunks });
          var off = 0;
          while (off < total) {
            var end = Math.min(off + CHUNK, total);
            var buf = await blob.slice(off, end).arrayBuffer();
            mh.postMessage({ kind: 'chunk', index: Math.floor(off / CHUNK), data: b64(buf) });
            off = end;
            if (onProgress) { try { onProgress(off, total); } catch (e) {} }
          }
          if (total === 0) {
            mh.postMessage({ kind: 'chunk', index: 0, data: '' });
          }
          mh.postMessage({ kind: 'finish', name: String(name) });
          return true;
        } catch (e) {
          try { mh.postMessage({ kind: 'abort', name: String(name), error: String(e && e.message || e) }); } catch (e2) {}
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
