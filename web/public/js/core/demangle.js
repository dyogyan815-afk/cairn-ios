// Symbol demangling (practical subset). Real demangling of the symbol families
// that dominate iOS symbol tables:
//   1. Swift _Tt... names (ObjC-bridged Swift types, incl. So/SC ObjC/Cocoa names)
//   2. Swift _$s... mangled names — best-effort identifier path extraction
//   3. Itanium C++ _Z... nested names
// Full signature-accurate Swift demangling needs the compiler's own demangler;
// this module says so and never pretends to be more than it is.
const SO_SC = { // common Objective-C / CoreFoundation substitutions inside _Tt names
  So: 'Objective-C class', SC: 'CoreFoundation type',
};

const PREDEF = { // predefined substitutions in the _$s mangling (stable, documented set)
  Sa: 'Swift.Array', SD: 'Swift.Dictionary', Sb: 'Swift.Bool', SS: 'Swift.String',
  Si: 'Swift.Int', Su: 'Swift.UInt', Sf: 'Swift.Float', Sd: 'Swift.Double',
  Sq: 'Swift.Optional', Sp: 'Swift.UnsafeMutablePointer', Sv: 'Swift.UnsafeMutableRawPointer',
  SV: 'Swift.UnsafeRawPointer', Sc: 'Swift.UnsafeContinuation', Sy: 'Swift.Void',
  Sg: 'Swift.LazySequence', So: 'ObjectiveC', SC: 'CoreFoundation', SB: 'Swift.Character',
  Sj: 'Swift.Dictionary.Index', St: 'Swift.StringProtocol',
};

function lenWord(s, i) {
  // length-prefixed identifier: <digits><that many chars>
  let j = i;
  while (j < s.length && s[j] >= '0' && s[j] <= '9') j++;
  if (j === i) return null;
  const n = parseInt(s.slice(i, j), 10);
  if (!n || j + n > s.length) return null;
  return { word: s.slice(j, j + n), next: j + n };
}

/** _Tt names: _TtC6Module5Class, _TtCC…, _TtV…, _TtO…, _TtP…, _TtGC… */
export function demangleTT(name) {
  if (!name.startsWith('_Tt')) return null;
  let s = name.slice(3), kind = 'type', parts = [], note = '';
  const KINDS = { C: 'class', CC: 'class (nested)', CCC: 'class (nested)', V: 'struct', O: 'enum', P: 'protocol', VV: 'struct (nested)', OO: 'enum (nested)', G: 'generic' };
  // generic marker G then the base type kind letter
  if (s[0] === 'G') { kind = 'generic'; s = s.slice(1); }
  if (s[0] === 'C' && s[1] === 'C') { kind = 'class (nested)'; s = s.slice(2); }
  else if (s[0] === 'V' && s[1] === 'V') { kind = 'struct (nested)'; s = s.slice(2); }
  else if (s[0] === 'O' && s[1] === 'O') { kind = 'enum (nested)'; s = s.slice(2); }
  else if (KINDS[s[0]]) { kind = KINDS[s[0]]; s = s.slice(1); }
  while (s.length) {
    if (s[0] === 'S' && (s[1] === 'o' || s[1] === 'C')) {
      const tag = s.slice(0, 2); s = s.slice(2);
      const w = lenWord(s, 0);
      if (!w) break;
      parts.push(w.word); note = note || SO_SC[tag]; s = s.slice(w.next);
    } else {
      const w = lenWord(s, 0);
      if (!w) { if (s.length < 4) { note = note || `remains: "${s}"`; } break; }
      parts.push(w.word); s = s.slice(w.next);
    }
  }
  if (!parts.length) return { kind: 'swift (bridged)', demangled: name, note: 'unparsed' };
  return { kind: `swift ${kind}`, demangled: parts.join('.'), note: note || undefined, family: 'swift-tt' };
}

/** _$s names — best-effort: pull the length-prefixed identifier path and the
 * predefined substitutions; strip the trailing function-type encoding. */
export function demangleSS(name) {
  let s = name;
  if (s.startsWith('_$s')) s = s.slice(3);
  else if (s.startsWith('_$')) s = s.slice(2);
  else return null;
  const words = [], predef = [];
  let i = 0, sawF = false;
  while (i < s.length) {
    // predefined substitution like Si / SS / SD (two letters, not followed by digits)
    if (s[i] === 'S' && PREDEF[s.slice(i, i + 2)]) {
      predef.push(PREDEF[s.slice(i, i + 2)]);
      i += 2;
      continue;
    }
    const w = lenWord(s, i);
    if (w) { words.push(w.word); i = w.next; continue; }
    const ch = s[i];
    if (ch === 'F') sawF = true;
    i += 1; // skip type/function grammar we do not reconstruct
  }
  if (!words.length && !predef.length) return { kind: 'swift', demangled: name, note: 'unparsed', family: 'swift-s' };
  const path = words.join('.');
  const out = (path ? path : '') + (predef.length && !path ? predef.join(', ') : '') + (sawF ? '()' : '');
  return { kind: `swift${sawF ? ' function' : ''}`, demangled: out || name, note: 'best-effort form', family: 'swift-s' };
}

/** Itanium C++ nested names: _ZN3foo3barE… → foo::bar()
 * Handles leading qualifiers (K const / V volatile / r restrict), the common
 * substitutions (St → std, Ss → std::string, Sa → std::allocator) and nested
 * length-prefixed names. Practical subset — complex template names stay
 * verbatim rather than being guessed. */
export function demangleCXX(name) {
  const m = name.match(/^_Z(.*)$/);
  if (!m) return null;
  let s = m[1], parts = [];
  if (s.startsWith('N')) s = s.slice(1);
  while (s.length && 'KVrR'.includes(s[0])) s = s.slice(1);
  if (s.startsWith('Ss')) { parts.push('std::string'); s = s.slice(2); }
  else if (s.startsWith('Sa')) { parts.push('std::allocator'); s = s.slice(2); }
  else if (s.startsWith('St')) { parts.push('std'); s = s.slice(2); }
  while (s.length && /^[0-9]/.test(s)) {
    const w = lenWord(s, 0);
    if (!w) break;
    parts.push(w.word); s = s.slice(w.next);
  }
  if (!parts.length) return null;
  const isFn = s.startsWith('v') || s.includes('Ev');
  return { kind: `c++ ${isFn ? 'function' : 'symbol'}`, demangled: parts.join('::') + (isFn ? '()' : ''), family: 'cxx' };
}

/** Demangle one symbol. Returns { kind, demangled, family } or null. */
export function demangle(name) {
  if (!name || typeof name !== 'string') return null;
  if (name.startsWith('_Tt')) return demangleTT(name);
  if (name.startsWith('_$s')) return demangleSS(name);
  if (name.startsWith('_Z')) return demangleCXX(name);
  return null;
}
