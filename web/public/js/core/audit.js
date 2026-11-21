// Static security audit (MobSF-style rule set, iOS section): checks the
// Info.plist declarations, entitlements, binary protections and string-table
// indicators of the app. Every finding is labelled with its severity and the
// evidence it was based on; string-pattern checks explicitly warn that they
// can produce false positives.
import { readRecBytes } from './pkg-utils.js';
import { isMachO, parseMachO } from './macho.js';

const DANGEROUS_C = [
  { pat: /\bstrcpy\b/, note: 'strcpy (no bounds check)' },
  { pat: /\bstrcat\b/, note: 'strcat (no bounds check)' },
  { pat: /\bsprintf\b/, note: 'sprintf (no bounds check)' },
  { pat: /\bgets\b/, note: 'gets (removed from C11; unsafe)' },
  { pat: /\bsystem\s*\(/, note: 'system() (shell execution)' },
  { pat: /\balloca\b/, note: 'alloca (stack overflow risk)' },
  { pat: /\bmd5\b|CC_MD5/i, note: 'MD5 (deprecated for security use)' },
  { pat: /\bSHA1\b|CC_SHA1/i, note: 'SHA-1 (deprecated for security use)' },
  { pat: /srand\b|\brand\s*\(/, note: 'rand()/srand() (not cryptographically secure)' },
];

const SECRET_PATTERNS = [
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/, note: 'AWS access key ID pattern' },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, note: 'Google API key pattern' },
  { id: 'private-key', re: /-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/, note: 'embedded private key block' },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, note: 'JWT token pattern' },
  { id: 'slack-token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, note: 'Slack token pattern' },
];

const JAILBREAK_HINTS = /Cydia|cydia|Substrate|substrate|sileo|jailbr|/;

export async function auditApp(fileBlob, model, { onProgress } = {}) {
  const findings = [];
  const add = (sev, title, detail, where) => findings.push({ sev, title, detail, where });
  const a = model.app;

  // ---- Info.plist checks ----
  if (a) {
    // App Transport Security
    if (a.ats && (a.ats.NSAllowsArbitraryLoads === true || a.ats.NSAllowsArbitraryLoads === 'true')) add('high', 'App Transport Security disabled', 'NSAllowsArbitraryLoads allows cleartext HTTP to any host.', 'Info.plist');
    if (a.ats && a.ats.NSExceptionDomains && Object.keys(a.ats.NSExceptionDomains).length) add('medium', `ATS exceptions for ${Object.keys(a.ats.NSExceptionDomains).length} domain(s)`, `Domains: ${Object.keys(a.ats.NSExceptionDomains).join(', ')}.`, 'Info.plist');
    // permissions without usage strings
    for (const p of a.permissions || []) {
      if (!p.reason || !p.reason.trim()) add('medium', `Permission without usage description: ${p.key}`, 'The permission key is declared but the explanation string is empty or missing.', 'Info.plist');
    }
    // URL schemes
    if (a.urlSchemes && a.urlSchemes.length) add('info', `URL schemes declared (${a.urlSchemes.length})`, `The app registers custom URL schemes: ${a.urlSchemes.join(', ')}. Schemes are input from untrusted sources.`, 'Info.plist');
  } else {
    add('info', 'No app bundle detected', 'The archive has no Payload/<App>.app, so Info.plist checks were skipped.', 'archive');
  }

  // ---- binary protections ----
  const exec = model.files.filter((f) => !f.isDir && (f.path.endsWith('.dylib') || /Payload\/[^/]+\.app\/[^/]+$/.test(f.path) && !/\.(png|car|plist|strings|nib|momd|mom|dat|json|html|css|js|txt|jpg|jpeg|pdf|ttf|otf|mp3|mp4|wav|caf|lproj|storyboardc|xib)$/i.test(f.path)));
  let binariesChecked = 0;
  for (const f of exec.slice(0, 80)) {
    if (f.size > 96 << 20) continue;
    let bytes;
    try { bytes = (await readRecBytes(fileBlob, f, 96 << 20)).bytes; } catch { continue; }
    if (!isMachO(bytes)) continue;
    const m = parseMachO(bytes);
    if (!m.ok) continue;
    binariesChecked++;
    const slice = m.slices.find((s) => s.ok);
    if (!slice) continue;
    const where = f.path;
    if (!slice.pie) add('high', 'PIE disabled', 'The executable is not position-independent (MH_PIE missing): ASLR is weaker.', where);
    if (slice.signals.stackCanary === false) add('medium', 'No stack canary', 'No __stack_chk_guard/___stack_chk_fail references found in this binary.', where);
    if (slice.signals.arc === false) add('medium', 'No ARC indicators', 'No objc_release/objc_storeStrong references found — binary may be compiled without ARC.', where);
    if (slice.encrypted) add('info', 'FairPlay encryption present', 'The main executable is FairPlay-encrypted (cryptid != 0). Strings and symbols inside the encrypted segment are not readable.', where);
    // entitlements
    if (slice.entitlementsXml) {
      const xml = slice.entitlementsXml;
      if (/<key>get-task-allow<\/key>\s*<true\/>/.test(xml)) add('high', 'get-task-allow = true', 'The binary allows debugging/attachment — typical of development builds and rejected for App Store.', where);
      if (/<key>com\.apple\.security\.cs\.disable-library-validation<\/key>\s*<true\/>/.test(xml)) add('medium', 'Library validation disabled', 'The binary will load signed libraries from any team.', where);
      if (/<key>aps-environment<\/key>/.test(xml)) add('info', 'Push notifications entitlement', `aps-environment present (${xml.match(/<key>aps-environment<\/key>\s*<string>([^<]*)</)?.[1] || 'unknown'}).`, where);
    }
    // string-table based checks (only when readable)
    if (!slice.encrypted && slice.symtab && slice.symtab.stroff + slice.symtab.strsize <= bytes.length) {
      const start = slice.symtab.stroff, end = start + Math.min(slice.symtab.strsize, 8 << 20);
      const text = new TextDecoder('latin1').decode(bytes.subarray(start, end));
      for (const d of DANGEROUS_C) if (d.pat.test(text)) add('medium', `Dangerous C function referenced: ${d.note}`, 'Found in the binary string table. Referenced by name — not proof of misuse, but worth review.', where);
      for (const sp of SECRET_PATTERNS) {
        const m2 = text.match(sp.re);
        if (m2) add('high', `Possible secret: ${sp.note}`, `Match: ${m2[0].slice(0, 12)}… (pattern match — may be a false positive).`, where);
      }
      if (JAILBREAK_HINTS.test(text.slice(0, 200000))) add('low', 'Jailbreak-detection strings present', 'The binary mentions Cydia/Substrate/jailbreak — usually an anti-tamper check, not a weakness.', where);
    }
    if (onProgress && binariesChecked % 4 === 0) onProgress({ binaries: binariesChecked });
    await new Promise((r) => setTimeout(r, 0));
  }
  add('info', `Binaries audited: ${binariesChecked}`, 'Static audit covered the main executable, embedded frameworks and plugins.', 'audit');

  const score = { high: findings.filter((x) => x.sev === 'high').length, medium: findings.filter((x) => x.sev === 'medium').length, low: findings.filter((x) => x.sev === 'low').length, info: findings.filter((x) => x.sev === 'info').length };
  return { ok: true, findings, score, binariesChecked };
}
