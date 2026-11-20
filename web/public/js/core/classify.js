// File classification + signature sniffing. Unknown types are never hidden; they get category "other".
import { extOf, latin1 } from './util.js';

const MIME = { json: 'application/json', xml: 'application/xml', plist: 'application/x-plist', strings: 'text/x-strings', stringsdict: 'application/x-plist', txt: 'text/plain', md: 'text/markdown', html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', heic: 'image/heic', pdf: 'application/pdf', ttf: 'font/ttf', otf: 'font/otf', woff: 'font/woff', woff2: 'font/woff2', mp3: 'audio/mpeg', m4a: 'audio/mp4', caf: 'audio/x-caf', wav: 'audio/wav', aac: 'audio/aac', mp4: 'video/mp4', mov: 'video/quicktime', m4v: 'video/mp4', car: 'application/x-assets-car', nib: 'application/x-nib', storyboardc: 'application/x-storyboardc', mobileprovision: 'application/x-apple-provision', swift: 'text/x-swift', m: 'text/x-objc', h: 'text/x-c-header', mm: 'text/x-objcpp', c: 'text/x-c', cpp: 'text/x-c++', db: 'application/x-sqlite3', sqlite: 'application/x-sqlite3', momd: 'application/x-coredata-model', mom: 'application/x-coredata-model', metallib: 'application/x-metal-library', dylib: 'application/x-mach-binary' };
export const TEXT_EXT = new Set(['json', 'xml', 'plist', 'strings', 'stringsdict', 'txt', 'md', 'html', 'htm', 'css', 'js', 'mjs', 'svg', 'swift', 'm', 'mm', 'h', 'c', 'cpp', 'hpp', 'modulemap', 'swiftinterface', 'yaml', 'yml', 'csv', 'ts', 'entitlements', 'xcconfig', 'pbxproj', 'podspec', 'sh', 'py', 'rb', 'java', 'kt', 'cfg', 'ini', 'log', 'license', 'readme']);
export const IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 'bmp', 'ico', 'heic']);
const SOURCE_EXT = new Set(['swift', 'm', 'mm', 'c', 'cpp', 'cc', 'hpp', 'kt', 'java', 'js', 'ts', 'py', 'rb', 'rs', 'go', 'cs']);

export function mimeOf(path) { return MIME[extOf(path)] || ''; }

export function classify(path, isDir) {
  const p = path.replace(/\/$/, '');
  const ext = extOf(p), base = p.split('/').pop(), lower = p.toLowerCase();
  if (/\.dsym(\/|$)/i.test(p) || ext === 'bcsymbolmap' || ext === 'dsym') return 'symbols';
  if (lower.includes('/_codesignature/') || base === 'embedded.mobileprovision' || base === 'archived-expanded-entitlements.xcent' || ext === 'entitlements' || ext === 'mobileprovision' || lower.endsWith('/_codesignature')) return 'signing';
  if (/\/plugins\/[^/]+\.appex(\/|$)/i.test(p) || /\/extensions\/[^/]+\.appex(\/|$)/i.test(p)) return 'extension';
  if (/\.framework(\/|$)/i.test(p) || /\/frameworks\//i.test(p) || ext === 'dylib') return 'framework';
  if (/^swiftsupport\//i.test(p) || /\/swiftsupport\//i.test(p)) return 'framework';
  if (ext === 'lproj' || /\.lproj\//i.test(p) || ext === 'strings' || ext === 'stringsdict') return 'localization';
  if (['h', 'hpp', 'modulemap', 'swiftmodule', 'swiftinterface', 'swiftdoc'].includes(ext) || /\.swiftmodule\//i.test(p)) return 'headers';
  if (SOURCE_EXT.has(ext) && ext !== 'js' && ext !== 'ts') return 'source';
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'heic', 'bmp', 'ico', 'pdf'].includes(ext)) return 'image';
  if (ext === 'car') return 'ui';
  if (['ttf', 'otf', 'woff', 'woff2', 'ttc'].includes(ext)) return 'font';
  if (['mp3', 'm4a', 'caf', 'wav', 'aac', 'aif', 'aiff', 'ogg', 'flac'].includes(ext)) return 'audio';
  if (['mp4', 'mov', 'm4v', 'avi', 'webm'].includes(ext)) return 'video';
  if (['nib', 'storyboardc', 'storyboard', 'xib', 'momd', 'mom', 'xcmappingmodel', 'metallib', 'scnassets', 'usdz'].includes(ext) || /\.(nib|storyboardc)\//i.test(p)) return 'ui';
  if (['plist', 'json', 'xml', 'yaml', 'yml', 'xcconfig', 'cfg', 'ini', 'html', 'htm', 'css', 'js', 'mjs'].includes(ext)) return 'config';
  if (/^payload\/[^/]+\.app\/[^/]+$/i.test(p) && !ext && !isDir) return 'executable';
  if (/\.app\/[^/]+$/i.test(p) && !ext && !isDir && /^payload\/[^/]+\.app\/[^/]+$/i.test(p)) return 'executable';
  return 'other';
}

export const CATEGORY_LABELS = { executable: 'Main executable', framework: 'Frameworks & libraries', extension: 'App extensions', image: 'Images & icons', font: 'Fonts', audio: 'Audio', video: 'Video', ui: 'UI resources / interface metadata', config: 'Configuration & plists', localization: 'Localization', signing: 'Signing metadata', symbols: 'Debug symbols', headers: 'Headers & module interfaces', source: 'Original source files', other: 'Other / unclassified' };

/** Identify a file from its first bytes. */
export function sniff(u8) {
  const n = u8.length;
  const is = (...b) => b.every((v, i) => u8[i] === v);
  if (n >= 8 && is(0x89, 0x50, 0x4e, 0x47)) return { sig: 'PNG image', cgbi: latin1(u8, 12, 16) === 'CgBI' };
  if (n >= 3 && is(0xff, 0xd8, 0xff)) return { sig: 'JPEG image' };
  if (n >= 4 && is(0x47, 0x49, 0x46, 0x38)) return { sig: 'GIF image' };
  if (n >= 12 && latin1(u8, 0, 4) === 'RIFF' && latin1(u8, 8, 12) === 'WEBP') return { sig: 'WebP image' };
  if (n >= 5 && latin1(u8, 0, 5) === '%PDF-') return { sig: 'PDF document' };
  if (n >= 8 && latin1(u8, 0, 8) === 'bplist00') return { sig: 'Binary property list' };
  if (n >= 4 && is(0x50, 0x4b, 3, 4)) return { sig: 'ZIP archive' };
  if (n >= 2 && is(0x1f, 0x8b)) return { sig: 'gzip data' };
  if (n >= 16 && latin1(u8, 0, 15) === 'SQLite format 3') return { sig: 'SQLite database' };
  if (n >= 8 && latin1(u8, 0, 8) === 'BOMStore') return { sig: 'Apple BOM store (Assets.car / compiled asset catalog)' };
  if (n >= 4 && (is(0, 1, 0, 0) || latin1(u8, 0, 4) === 'true')) return { sig: 'TrueType font' };
  if (n >= 4 && latin1(u8, 0, 4) === 'OTTO') return { sig: 'OpenType font' };
  if (n >= 4 && latin1(u8, 0, 4) === 'wOFF') return { sig: 'WOFF font' };
  if (n >= 4 && latin1(u8, 0, 4) === 'wOF2') return { sig: 'WOFF2 font' };
  if (n >= 8 && latin1(u8, 4, 8) === 'ftyp') return { sig: 'MP4/MOV/HEIC container' };
  if (n >= 4 && latin1(u8, 0, 4) === 'caff') return { sig: 'Core Audio Format' };
  if (n >= 3 && latin1(u8, 0, 3) === 'ID3') return { sig: 'MP3 audio (ID3)' };
  if (n >= 8 && latin1(u8, 0, 8) === '!<arch>\n') return { sig: 'ar static library' };
  if (n >= 4 && is(0xfa, 0xde, 0x0c, 0xc0)) return { sig: 'Apple code-signature blob' };
  if (n >= 4) {
    const m = ((u8[0] << 24) | (u8[1] << 16) | (u8[2] << 8) | u8[3]) >>> 0;
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m)) return { sig: 'Mach-O binary' };
    if (m === 0xcafebabe && u8[7] < 32 && u8[7] > 0) return { sig: 'Universal (fat) Mach-O binary' };
  }
  if (n >= 5 && latin1(u8, 0, 5) === '<?xml') return { sig: 'XML text' };
  return { sig: '' };
}

export function looksText(u8) {
  const n = Math.min(u8.length, 4096);
  if (!n) return true;
  let bad = 0;
  for (let i = 0; i < n; i++) { const b = u8[i]; if (b === 0) return false; if (b < 7 || (b > 13 && b < 32 && b !== 27)) bad++; }
  return bad / n < 0.02;
}
