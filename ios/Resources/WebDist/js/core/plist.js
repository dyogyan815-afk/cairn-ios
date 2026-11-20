// Property-list decoding (binary bplist00 + XML), no DOM needed. Also a JSON-safe XML serializer for previews.
import { td, latin1 } from './util.js';

export function isBinaryPlist(u8) { return u8.length > 8 && latin1(u8, 0, 8) === 'bplist00'; }

export function parseBinaryPlist(u8) {
  if (!isBinaryPlist(u8)) throw new Error('Not a binary plist');
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const t = u8.length - 32;
  const offSize = u8[t + 6], refSize = u8[t + 7];
  const num = Number(dv.getBigUint64(t + 8)), top = Number(dv.getBigUint64(t + 16)), tableOff = Number(dv.getBigUint64(t + 24));
  const uint = (o, n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + u8[o + i]; return v; };
  const offs = [];
  for (let i = 0; i < num; i++) offs.push(uint(tableOff + i * offSize, offSize));
  const cache = new Map();
  const lenAt = (o, info) => {
    if (info !== 0xf) return { n: info, p: o + 1 };
    const sz = 1 << (u8[o + 1] & 0xf);
    return { n: uint(o + 2, sz), p: o + 2 + sz };
  };
  const read = (idx, depth = 0) => {
    if (depth > 64) throw new Error('plist nesting too deep');
    if (cache.has(idx)) return cache.get(idx);
    const o = offs[idx], m = u8[o], hi = m >> 4, lo = m & 0xf;
    let v;
    if (hi === 0) v = lo === 8 ? false : lo === 9 ? true : null;
    else if (hi === 1) { const n = 1 << lo; v = n <= 6 ? uint(o + 1, n) : Number(dv.getBigInt64(o + 1)); if (n === 8) v = Number(dv.getBigInt64(o + 1)); }
    else if (hi === 2) v = lo === 2 ? dv.getFloat32(o + 1) : dv.getFloat64(o + 1);
    else if (hi === 3) v = { $date: new Date(Date.UTC(2001, 0, 1) + dv.getFloat64(o + 1) * 1000).toISOString() };
    else if (hi === 4) { const { n, p } = lenAt(o, lo); v = { $data: u8.slice(p, p + n) }; }
    else if (hi === 5) { const { n, p } = lenAt(o, lo); v = latin1(u8, p, p + n); }
    else if (hi === 6) { const { n, p } = lenAt(o, lo); let s = ''; for (let i = 0; i < n; i++) s += String.fromCharCode(dv.getUint16(p + i * 2)); v = s; }
    else if (hi === 8) v = { $uid: uint(o + 1, lo + 1) };
    else if (hi === 0xa || hi === 0xc) { const { n, p } = lenAt(o, lo); v = []; cache.set(idx, v); for (let i = 0; i < n; i++) v.push(read(uint(p + i * refSize, refSize), depth + 1)); }
    else if (hi === 0xd) {
      const { n, p } = lenAt(o, lo); v = {}; cache.set(idx, v);
      for (let i = 0; i < n; i++) v[String(read(uint(p + i * refSize, refSize), depth + 1))] = read(uint(p + (n + i) * refSize, refSize), depth + 1);
    } else throw new Error('Unknown plist marker 0x' + m.toString(16));
    cache.set(idx, v);
    return v;
  };
  return read(top);
}

const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&apos;': "'" };
const unent = (s) => s.replace(/&(lt|gt|amp|quot|apos);|&#(x?[0-9a-fA-F]+);/g, (m, n, c) => n ? ENT[m] : String.fromCodePoint(c[0] === 'x' ? parseInt(c.slice(1), 16) : parseInt(c, 10)));

export function parseXmlPlist(text) {
  const re = /<(\/?)([A-Za-z]+)([^>]*?)(\/?)>([^<]*)/g;
  const stack = []; let root, key = null, cur = null;
  const put = (v) => {
    if (!cur) { root = v; return; }
    if (Array.isArray(cur.c)) cur.c.push(v); else { cur.c[key] = v; key = null; }
  };
  const start = text.indexOf('<plist');
  re.lastIndex = start < 0 ? 0 : start;
  let m;
  while ((m = re.exec(text))) {
    const [, close, tag, , self, body] = m;
    if (tag === 'plist' || tag === 'xml') continue;
    if (close) { if (tag === 'dict' || tag === 'array') cur = stack.pop() || null; continue; }
    if (tag === 'dict' || tag === 'array') {
      const c = tag === 'dict' ? {} : [];
      if (self) { put(c); continue; }
      put(c); stack.push(cur); cur = { c };
      continue;
    }
    if (tag === 'key') { key = unent(body); continue; }
    let v;
    if (tag === 'true') v = true; else if (tag === 'false') v = false;
    else if (tag === 'integer') v = Number(body.trim());
    else if (tag === 'real') v = parseFloat(body);
    else if (tag === 'date') v = { $date: body.trim() };
    else if (tag === 'data') { const b = atobSafe(body.replace(/\s+/g, '')); v = { $data: b }; }
    else if (tag === 'string') v = unent(body);
    else continue;
    if (tag === 'key') continue;
    put(v);
  }
  return root;
}
function atobSafe(s) {
  if (typeof atob === 'function') { const b = atob(s); const o = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i); return o; }
  return new Uint8Array(Buffer.from(s, 'base64'));
}

export function parsePlist(u8) {
  if (isBinaryPlist(u8)) return { format: 'binary', value: parseBinaryPlist(u8) };
  const text = td.decode(u8);
  if (/<plist[\s>]/.test(text)) return { format: 'xml', value: parseXmlPlist(text) };
  throw new Error('Not a recognised property list (neither bplist00 nor XML).');
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
export function plistToXml(v, ind = '') {
  const n = ind + '\t';
  if (v === null || v === undefined) return `${ind}<string></string>`;
  if (typeof v === 'boolean') return `${ind}<${v}/>`;
  if (typeof v === 'number') return Number.isInteger(v) ? `${ind}<integer>${v}</integer>` : `${ind}<real>${v}</real>`;
  if (typeof v === 'string') return `${ind}<string>${esc(v)}</string>`;
  if (Array.isArray(v)) return v.length ? `${ind}<array>\n${v.map((x) => plistToXml(x, n)).join('\n')}\n${ind}</array>` : `${ind}<array/>`;
  if (v.$date) return `${ind}<date>${v.$date}</date>`;
  if (v.$data) return `${ind}<data>${bytesB64(v.$data)}</data>`;
  if (v.$uid !== undefined) return `${ind}<dict><key>CF$UID</key><integer>${v.$uid}</integer></dict>`;
  const ks = Object.keys(v);
  return ks.length ? `${ind}<dict>\n${ks.map((k) => `${n}<key>${esc(k)}</key>\n${plistToXml(v[k], n)}`).join('\n')}\n${ind}</dict>` : `${ind}<dict/>`;
}
function bytesB64(u8) { let s = ''; for (const b of u8) s += String.fromCharCode(b); return typeof btoa === 'function' ? btoa(s) : Buffer.from(u8).toString('base64'); }
export function plistDocument(v) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!-- Converted for display by Cairn; the original file is unchanged. -->\n<plist version="1.0">\n${plistToXml(v)}\n</plist>\n`;
}
