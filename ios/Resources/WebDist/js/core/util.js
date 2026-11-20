// Shared helpers. Pure ES module: runs in browsers, Web Workers and Node >= 20.

export class AppError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.details = details;
  }
}

export const te = new TextEncoder();
export const td = new TextDecoder('utf-8');

export function formatBytes(n) {
  if (n == null || Number.isNaN(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? String(n) : n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)) + ' ' + u[i];
}

export function toHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}

export async function readRange(blob, start, end) {
  const e = Math.min(end, blob.size);
  if (e <= start) return new Uint8Array(0);
  return new Uint8Array(await blob.slice(start, e).arrayBuffer());
}

export function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export function extOf(name) {
  const base = name.split('/').filter(Boolean).pop() || '';
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase() : '';
}

export function baseName(path) {
  return path.split('/').filter(Boolean).pop() || path;
}

export function latin1(u8, start = 0, end = u8.length) {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(u8[i]);
  return s;
}

export function cstr(u8, start, max = 1024) {
  let e = start;
  const lim = Math.min(u8.length, start + max);
  while (e < lim && u8[e] !== 0) e++;
  return latin1(u8, start, e);
}

/** Read a ReadableStream to the end (or maxBytes), calling onChunk for each chunk. Works without async iteration (Safari). */
export async function readStream(stream, { onChunk, maxBytes, signal } = {}) {
  const reader = stream.getReader();
  let total = 0;
  try {
    for (;;) {
      if (signal && signal.aborted) throw new AppError('aborted', 'Operation cancelled.');
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (onChunk) await onChunk(value);
      if (maxBytes != null && total >= maxBytes) {
        try { await reader.cancel(); } catch { /* ignore */ }
        return { total, truncated: true };
      }
    }
  } catch (err) {
    try { await reader.cancel(); } catch { /* ignore */ }
    throw err;
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
  return { total, truncated: false };
}

export function isUnsafePath(name) {
  if (!name) return true;
  if (name.startsWith('/') || /^[A-Za-z]:[\\/]/.test(name) || name.includes('\0') || name.includes('\\')) return true;
  return name.split('/').some((p) => p === '..');
}

export function throttle(fn, ms) {
  let last = 0;
  return (...a) => {
    const now = Date.now();
    if (now - last >= ms) { last = now; fn(...a); }
  };
}
