// "Production build": copies public/ to dist/ (no compiler needed), leaving out the browser test page.
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist'); fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(path.join(root, 'public'), out, { recursive: true, filter: (s) => !s.includes('_test') });
console.log('Built ->', out, '(upload this folder to any static host)');
