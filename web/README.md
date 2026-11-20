# Cairn IPA Studio

Private, browser-only IPA inspector and extraction studio. **Nothing is uploaded**: parsing, hashing and ZIP building run in the page,
and the Content-Security-Policy blocks outbound connections. No accounts, keys, analytics or paid services.

## Run
```
node server.mjs 8080        # then open http://localhost:8080   (Node >= 20, no npm install needed)
python3 scripts/make-fixtures.py   # (once) the 24 MB fixture is not shipped in the zip
npm test                    # 16 automated tests (extraction, hashes, export, damaged archives, Mach-O, plist, CgBI)
npm run build               # copies public/ -> dist/ for static hosting
python3 scripts/make-fixtures.py   # regenerates synthetic test IPAs
```

## Use it on iPhone
Safari needs **HTTPS** (or localhost) for some APIs, so host `dist/` on a free static host, e.g. Cloudflare Pages, GitHub Pages or Netlify Drop
(drag the `dist` folder in). Then: open the site -> *Browse Files* -> pick the IPA from Files/iCloud -> Inspector / File Explorer / ZIP Downloads.

## What it does
- Reads the IPA read-only (ZIP, ZIP64, data descriptors, UTF-8/CP437 names). Every central-directory entry is listed; duplicates, unsafe paths, damaged or unsupported entries are **flagged, never dropped**.
- Hashes every file (SHA-256) and checks CRC-32 while reading.
- Exports **raw-copy** the original compressed bytes, so extracted contents are byte-identical to the IPA. Each export is re-opened and verified (size + CRC, optionally SHA-256) before download.
- Downloads: `ORIGINAL_IPA_CONTENTS.zip`, `RECONSTRUCTED_APPLICATION_PROJECT.zip`, `AVAILABLE_SOURCE_AND_RESOURCES.zip`, `APPLICATION_ANALYSIS_REPORT.zip`, selected files/folders as ZIP, single file, original IPA, `manifest.json/.csv`, `SHA256SUMS.txt`.
- Metadata: Info.plist (binary/XML), bundle id, version, min iOS, devices, architectures, URL schemes, privacy permissions, frameworks, extensions, provisioning profile, code signature, entitlements; Mach-O load commands, PIE/ARC/stack-canary hints, FairPlay `cryptid`.

## Honest limits
- **No source recovery.** An IPA contains compiled machine code. Nothing is decompiled or AI-generated; `Source/` is filled only if the IPA literally shipped source files. FairPlay-encrypted executables are labelled and **not decrypted**.
- The reconstructed `.xcodeproj` is a *resource-only* container; it will not compile into an app.
- Memory: exports reference the original file instead of copying it, but multi-GB IPAs can still exceed what an iPhone allows. If so, export selected folders.
- Heavy work runs on the main thread using streams (no Web Worker yet); the UI stays responsive via yielding but very large archives scan slowly.
- Tested here with synthetic IPAs (small, 1,500 files, 24 MB, nested frameworks, 4 extensions, fat + encrypted flag, odd names, truncated/corrupt/duplicate archives) in Node and in headless Chromium. **Not yet tested on a real iPhone or with real App Store IPAs** — please try yours and report problems.
- Stack: dependency-free ES modules (no Next.js/Tailwind), by choice, so it deploys anywhere with no build tooling.

## Layout
`public/js/core/` zip-reader, zip-writer, inflate, crc32, sha256, plist, macho, cgbi, classify, ipa (scan + metadata + tree), exporter · `public/js/ui/app.js` · `tests/`
