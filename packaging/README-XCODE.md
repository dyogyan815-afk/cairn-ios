# Cairn IPA Studio — Xcode Source (v1.5.0)

## Kurdish / کوردی

ئەمە سۆرسی تەواوی ئەپەکەیە: پڕۆژەی Xcode (Swift) + وێب ئێنجینەکە (JavaScript).

**بنای بنان (build) لەسەر ماک:**
1. Xcode 15+ لەسەر ماک دابمەزرێنە.
2. لە Terminal: `brew install xcodegen`
3. لەناو فۆڵدەری `ios`: `xcodegen generate` — ئەمە `Cairn.xcodeproj` دروست دەکات.
4. `Cairn.xcodeproj` بکەرەوە بە Xcode → لە Signing & Capabilities هەڵبژاردەی Apple ID خۆت دابنێ → ئایفۆنەکەت پەیوەست بکە → Run.

**بنای بە کلاود (بێ ماک):** فۆڵدەرەکە بخەرە ناو repo یەک GitHub ی خۆت — workflow ی `.github/workflows/build-ipa.yml` خۆکارانە IPA ی unsigned بڵاو دەکاتەوە وەک Release، هەمان ئەو ڕێگەیە کە Cairn ی ئێستا پێ دروستکراوە.

**Bundle ID:** لە `ios/project.yml` بە یەک شوێنی بەڵگەدارکراو دانراوە (`PRODUCT_BUNDLE_IDENTIFIER`). پێش signکردن بە certificate ی خۆت بیگۆڕە.

**گۆڕینی ئێنجین:** فۆڵدەری `ios/Resources/WebDist` بەرزکراوەی بنیاتنراوی وێب ئێنجینەکەیە. بۆ گۆڕانکاری: `cd web && bash ../scripts/prepare-webdist.sh` (تێست + build + کۆپی دەکات).

---

## English

This archive is the complete, buildable source of Cairn IPA Studio v1.5.0 — the same commit CI built the published IPA from:

```
Cairn-Xcode-Source/
├── ios/
│   ├── project.yml          XcodeGen project definition (single source of truth)
│   ├── Sources/             Swift app: WKWebView shell + bridges
│   │   ├── CairnApp.swift, ContentView.swift
│   │   ├── BridgeJS.swift       JS→native message bridge (chunked, ACK-flow-controlled)
│   │   ├── SaveBridge.swift     cairnSave: chunked file export to the phone
│   │   ├── FetchBridge.swift    native HTTP fetch for "Images from a link" (no CORS)
│   │   ├── SchemeHandler.swift  app:// virtual host for the web engine
│   │   └── InboxStore.swift     inbox for IPAs/zips opened from other apps
│   ├── Tests/               XCTest suites (bridges, scheme handler, fetch)
│   └── Resources/           Assets.xcassets, Info.plist, WebDist/ (prebuilt engine v1.5.0)
├── web/                     The 45-tool analysis engine (plain ES modules, no framework)
│   ├── public/js/core/      ipa, zip, macho, plist, symbols, disasm+capstone, audit,
│   │                        toolchain, packages, signatures, webimages harvester,
│   │                        allinone (one-file-per-app complete package)…
│   ├── tests/               74 tests (`npm test`; fixtures regenerate via make-fixtures.py)
│   └── scripts/             build.mjs, make-fixtures.py
├── scripts/prepare-webdist.sh   tests + builds web/ and installs it into ios/Resources/WebDist
├── .github/workflows/build-ipa.yml  the exact CI that produced the published unsigned IPA
├── packaging/README-XCODE.md  this file (Kurdish + English build guide)
├── docs/                    BUILD_FROM_IPHONE.md, DECISIONS.md
└── README.md                repository overview
```

### Build on a Mac

Requirements: macOS with Xcode 15+, [Homebrew](https://brew.sh), Node.js 20 (only if you change the engine — WebDist is already built).

```bash
brew install xcodegen
cd ios
xcodegen generate          # creates Cairn.xcodeproj from project.yml
open Cairn.xcodeproj
```

In Xcode: select the Cairn target → Signing & Capabilities → add your Apple ID team (free personal team works for device installs) → connect your iPhone → Run.

### Build in the cloud (no Mac)

1. Create your own GitHub repository and push this folder.
2. The included workflow runs web tests → iOS tests on a macOS runner → generates the Xcode project with XcodeGen → builds an **unsigned** IPA → publishes it as a Release asset (`unsigned-v<N>`).
3. Download the unsigned IPA and self-sign it on-device with your tool of choice.

### Key settings (all in `ios/project.yml`)

| Setting | Value | Note |
| --- | --- | --- |
| Bundle ID | `com.example.cairnipastudio` | Change before signing with your own certificate — documented in exactly one place |
| Deployment target | iOS 16.0 | |
| `CFBundleShortVersionString` | 1.4.0 | Written literally in the Info properties (XcodeGen ignores the build setting when emitting the plist) |
| Code signing | Manual, disabled | The published IPA is intentionally unsigned; enable when signing yourself |
| App Transport Security | `NSAllowsArbitraryLoads` | Used only by FetchBridge at the moment you paste a link into "Images from a link"; no other network use |

### Regenerating WebDist after engine changes

```bash
bash scripts/prepare-webdist.sh    # runs make-fixtures.py, npm test, npm run build, copies to ios/Resources/WebDist
```

Then re-run `xcodegen generate` if files were added/removed inside WebDist (folder reference — usually not needed).
