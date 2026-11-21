// Disassembler: Capstone engine (WASM) — genuine machine-code disassembly for
// ARM64 / ARM / Thumb / x86 / x86_64 code found in Mach-O binaries.
// The engine is vendored (js/vendor/capstone.wasm, BSD licence) and runs fully
// on-device inside this page. It reads bytes; it never writes anything.
import { AppError } from './util.js';

let cap = null; // loaded module
let loading = null;

function vendorDir() {
  // Resolve the vendored engine next to this module, in browsers and Node.
  let url = '';
  try { url = import.meta.url || ''; } catch { /* very old engines */ }
  if (!url) return './';
  return url.slice(0, url.lastIndexOf('/') + 1).replace(/core\/$/, 'vendor/');
}

export async function loadDisasm() {
  if (cap) return cap;
  if (loading) return loading;
  loading = (async () => {
    const base = vendorDir();
    const m = await import('../vendor/capstone.mjs');
    await m.loadCapstone({ locateFile: (p) => base + p });
    cap = m;
    return m;
  })();
  return loading;
}

export function disasmAvailable() { return !!cap; }

const ARCHS = {
  arm64: { arch: () => cap.Const.CS_ARCH_ARM64, mode: () => cap.Const.CS_MODE_LITTLE_ENDIAN },
  arm64e: { arch: () => cap.Const.CS_ARCH_ARM64, mode: () => cap.Const.CS_MODE_LITTLE_ENDIAN },
  arm: { arch: () => cap.Const.CS_ARCH_ARM, mode: () => cap.Const.CS_MODE_ARM },
  thumb: { arch: () => cap.Const.CS_ARCH_ARM, mode: () => cap.Const.CS_MODE_THUMB },
  x86: { arch: () => cap.Const.CS_ARCH_X86, mode: () => cap.Const.CS_MODE_32 },
  x86_64: { arch: () => cap.Const.CS_ARCH_X86, mode: () => cap.Const.CS_MODE_64 },
};

export const DISASM_LIMITS = { maxBytesPerRun: 256 * 1024, maxInstructions: 8000 };

/** Disassemble bytes into instructions.
 * data: Uint8Array, arch: key of ARCHS, address: VM address of first byte. */
export async function disasm(data, archName, address, { count = 0, onChunk } = {}) {
  if (!data || !data.length) throw new AppError('empty', 'No bytes to disassemble.');
  const spec = ARCHS[archName];
  if (!spec) throw new AppError('arch', `No disassembler for "${archName}".`);
  const m = await loadDisasm();
  const slice = data.length > DISASM_LIMITS.maxBytesPerRun ? data.subarray(0, DISASM_LIMITS.maxBytesPerRun) : data;
  const cs = new m.Capstone(spec.arch(), spec.mode());
  try {
    // Feed in bounded batches so progress callbacks fire and memory stays flat.
    const insns = [];
    let off = 0, addr = address;
    while (off < slice.length && (!count || insns.length < count)) {
      const end = Math.min(slice.length, off + 4096);
      let batch;
      try {
        batch = cs.disasm(slice.subarray(off, end), { address: addr, count: count ? Math.min(count - insns.length, end - off) : 0 });
      } catch {
        batch = null; // an undecodable byte stopped the batch: skip one byte and retry
      }
      if (batch && batch.length) {
        for (const i of batch) {
          insns.push({ address: Number(i.address), size: i.size, bytes: [...(i.bytes || [])].map((b) => (b || 0).toString(16).padStart(2, '0')).join(' '), mnemonic: i.mnemonic || '', op: (i.opStr || '').replace(/\s+/g, ' ').trim() });
        }
        const last = batch[batch.length - 1];
        off += Number(last.address) + last.size - addr;
        addr = Number(last.address) + last.size;
      } else {
        off += 1; addr += 1; // skip an undecodable byte (data section inside text etc.)
      }
      if (onChunk && insns.length % 512 < 64) onChunk(insns.length, slice.length);
      await new Promise((r) => setTimeout(r, 0)); // yield to the UI
    }
    return { ok: true, arch: archName, address, instructions: insns, stoppedEarly: slice.length < data.length };
  } finally {
    cs.close();
  }
}

/** Convenience: disassemble a chunk of a Mach-O slice's __text section.
 * u8: full binary bytes; slice: parsed slice with sections[]. */
export async function disasmTextSection(u8, slice, { offset, size, onChunk } = {}) {
  const text = (slice.sections || []).find((s) => s.sect === '__text' && s.seg === '__TEXT');
  const start = offset !== undefined ? offset : text ? text.offset : 0;
  const len = size !== undefined ? size : Math.min(text ? text.size : slice.size, DISASM_LIMITS.maxBytesPerRun);
  if (start >= u8.length || len <= 0) throw new AppError('range', 'Nothing readable at that offset.');
  return disasm(u8.subarray(start, Math.min(u8.length, start + len)), slice.arch, slice.vmaddrOfText !== undefined ? slice.vmaddrOfText : text ? slice.segments.find((s) => s.name === '__TEXT')?.vmaddr + (start - slice.segments.find((s) => s.name === '__TEXT')?.fileoff) : start, { onChunk });
}
