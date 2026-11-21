// Shared small helpers for the toolchain modules. Kept separate so node tests
// and browser code can import them without pulling the whole UI.
import { entryBytes } from './zip-reader.js';
import { td } from './util.js';

/** Read one zip file record as text (bounded). fileBlob = the opened IPA blob. */
export async function readEntryText(fileBlob, rec, limit = 2 << 20) {
  const { bytes } = await entryBytes(fileBlob, rec.entry, limit);
  return td.decode(bytes);
}

/** Read one zip file record as bytes (bounded). Returns {bytes, truncated, size}. */
export async function readRecBytes(fileBlob, rec, limit = 2 << 20) {
  return entryBytes(fileBlob, rec.entry, limit);
}

/** makeReader(fileBlob) → async (rec, cap) => {bytes, truncated}; the bounded
 * byte accessor handed to the analysis modules. */
export function makeReader(fileBlob) {
  return async (rec, cap = 2 << 20) => readRecBytes(fileBlob, rec, cap);
}
