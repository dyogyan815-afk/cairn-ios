# Cairn IPA Studio — native iOS app

Cairn is a private, fully local IPA inspector and extraction studio: the engine
is a dependency-free browser app; this repo wraps it in a native iOS shell
(SwiftUI + WKWebView) and builds an **unsigned** IPA in GitHub Actions.

- **Nothing is uploaded.** Parsing, hashing, ZIP building run inside the page.
  The shell adds no networking, no analytics, no SDKs, no permissions prompts.
- **You sign the IPA yourself** with your own certificate. This pipeline never
  touches Apple credentials.

| Path | What it is |
|---|---|
| `web/` | The web engine (uploaded zip, unmodified except documented app.js bridge hooks — see `docs/DECISIONS.md`) |
| `ios/` | Native wrapper: Swift sources, unit tests, `project.yml` (XcodeGen) |
| `ios/Sources/SchemeHandler.swift` | `cairn://` scheme: bundled web app + inbox file with HTTP Range |
| `ios/Sources/SaveBridge.swift` | Chunked native save bridge (`cairnSave` message channel) |
| `ios/Sources/ContentView.swift` | WKWebView, navigation policy, `WKDownloadDelegate` fallback |
| `ios/project.yml` | XcodeGen project — **bundle ID defined here, in one place** |
| `.github/workflows/build-ipa.yml` | Cloud build: web tests → iOS tests → unsigned IPA → GitHub Release |
| `docs/BUILD_FROM_IPHONE.md` | How to run the build and get the IPA, from an iPhone |
| `docs/DECISIONS.md` | Every engineering decision, with reasons |

## Toolchain — 45-tool analysis workspace

Opening an IPA automatically runs the full compatible analysis pipeline and
populates the **Toolchain** tab with real, on-device results:

- **Mach-O engine** (otool/MachOView/LIEF class): load commands, segments,
  sections, UUID, platform, FairPlay status for every binary.
- **Symbol engine** (nm): the full `LC_SYMTAB` walk with classification.
- **Demangler** (swift-demangle subset + LLVM-style C++): `_Tt` ObjC-bridged
  Swift types, `_$s` paths (best-effort), Itanium nested names.
- **Dependency engine** (otool -L / Dependency Walker): every link in every
  binary classified **system / embedded / MISSING**.
- **ObjC names** (class-dump class): classes, methods, method types, strings.
- **Disassembly** (Capstone 5, vendored WASM, BSD): genuine ARM64/ARM/Thumb/
  x86/x86_64 disassembly, auto-sample plus interactive per-binary runs.
- **Signature scanner** (binwalk): magic scan of every readable file.
- **Package managers**: Podfile.lock / Cartfile.resolved / Package.resolved.
- **Security audit** (MobSF-style iOS static rules): ATS, permissions,
  entitlements (get-task-allow), PIE/ARC/canary, dangerous C APIs,
  secret-pattern scan (false positives are labelled as such).

Every one of the 45 requested tools has a registry entry with an honest
status: `active` (core function ran on this file), `partial` (stated subset
ran) or `desktop` (genuinely cannot run inside an iOS app — reason given,
never simulated). The per-file execution record (status, duration, counts)
is shown in the Toolchain tab.

## Quick start (maintainer)

```
bash scripts/prepare-webdist.sh     # web tests + build + copy into iOS resources
python3 scripts/make-icon.py        # regenerate the original app icon
cd ios && xcodegen generate         # after changing project.yml
```

## CI pipeline

Every push to `main` (and every manual run) executes:

1. **web-tests** — fixture generation + 21 engine tests + build.
2. **ios-tests** — XcodeGen, unit tests on simulator (MIME types, path-traversal
   rejection, Range responses, save-bridge temp-file logic), launch smoke test.
3. **build-ipa** — Release build for device (`CODE_SIGNING_ALLOWED=NO`),
   package `Payload/` → `Cairn-unsigned.ipa`, validate (Info.plist, arm64 via
   `lipo`, WebDist files, bundle id).
4. **release** — publishes `Cairn-unsigned.ipa` as a GitHub Release asset.

## v1.1 — hidden-image recovery

New engine module `web/public/js/core/carve.js`: recovers **complete, fully valid
PNG / Apple CgBI PNG / JPEG streams embedded inside compiled containers**
(`Assets.car`, nib archives, opaque data files). UI entry points: the
**Extraction** tab ("Find hidden images", scans the largest containers with a
progress bar and Cancel) and the file preview for binary files
("Find images in this file"). Carved images can be exported as one ZIP
(`CARVED_IMAGES.zip`) with a MANIFEST.txt recording container, byte offset,
size and kind for every image.

Guarantees (same as the rest of Cairn): the original file is never modified;
nothing is fabricated — a carved image must parse completely (signature + full
chunk/marker structure) before it is reported; best-effort by design; limits
are shown in the UI (first 300 images / 96 MB per container, scanning stops
early with an honest notice). No source code is recovered anywhere: compiled
machine code stays unreadable, exactly as before.

Latest release: see the **Releases** section of this repo.
From an iPhone? Follow `docs/BUILD_FROM_IPHONE.md`.

## Honest limits

- No source recovery: IPAs contain compiled machine code; nothing is
  decompiled or fabricated; FairPlay-encrypted executables are labelled, never
  decrypted (engine guarantees, unchanged).
- Multi-GB IPAs can exceed what an iPhone allows; export selected folders then.
- The iOS shell has been verified in CI (unit tests + launch smoke); real-device
  ergonomics (picker, iCloud, share sheet) still need hands-on testing.
