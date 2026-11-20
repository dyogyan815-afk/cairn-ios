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

## Quick start (maintainer)

```
bash scripts/prepare-webdist.sh     # web tests + build + copy into iOS resources
python3 scripts/make-icon.py        # regenerate the original app icon
cd ios && xcodegen generate         # after changing project.yml
```

## CI pipeline

Every push to `main` (and every manual run) executes:

1. **web-tests** — fixture generation + 16 engine tests + build.
2. **ios-tests** — XcodeGen, unit tests on simulator (MIME types, path-traversal
   rejection, Range responses, save-bridge temp-file logic), launch smoke test.
3. **build-ipa** — Release build for device (`CODE_SIGNING_ALLOWED=NO`),
   package `Payload/` → `Cairn-unsigned.ipa`, validate (Info.plist, arm64 via
   `lipo`, WebDist files, bundle id).
4. **release** — publishes `Cairn-unsigned.ipa` as a GitHub Release asset.

Latest release: see the **Releases** section of this repo.
From an iPhone? Follow `docs/BUILD_FROM_IPHONE.md`.

## Honest limits

- No source recovery: IPAs contain compiled machine code; nothing is
  decompiled or fabricated; FairPlay-encrypted executables are labelled, never
  decrypted (engine guarantees, unchanged).
- Multi-GB IPAs can exceed what an iPhone allows; export selected folders then.
- The iOS shell has been verified in CI (unit tests + launch smoke); real-device
  ergonomics (picker, iCloud, share sheet) still need hands-on testing.
