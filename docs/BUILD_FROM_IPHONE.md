# Build the Cairn IPA from your iPhone (no Mac, no PC)

Everything happens in GitHub Actions in the cloud. You only need Safari and the
Files app.

## 1. Run the build

1. Open `https://github.com/<owner>/cairn-ios` in Safari (request desktop site
   works best: tap **aA** → *Request Desktop Website*).
2. Tap the **Actions** tab.
3. Pick **Build Cairn IPA** in the workflow list (left side).
4. Tap **Run workflow** → keep branch `main` → tap the green **Run workflow** button.
5. Wait. The whole pipeline takes roughly 10-20 minutes:
   - *Web engine tests* (16 tests) → *iOS unit tests + launch smoke* → *Build unsigned IPA* → *Publish GitHub Release*.

If a job turns red: open the job, scroll to the first red step, and read the log
lines right above the error. Push a fix to `main` and the workflow starts again
automatically (it also runs on every push).

## 2. Download the IPA

1. On the repo page, tap **Releases** (right side, under *About*).
2. Open the newest release — it is named `unsigned-v<build number>`.
3. Tap **Cairn-unsigned.ipa** to download it into Files.

You can also grab it from the finished *Build unsigned IPA* job's **Artifacts**
section — but note GitHub wraps artifacts in an extra ZIP; the Release asset is
the clean, byte-exact `.ipa`.

## 3. Sign it yourself

You already have your own signer and certificate — hand
`Cairn-unsigned.ipa` to it, exactly like your other apps.

## Where to change things

| What | Where |
|---|---|
| **Bundle ID** (change before re-signing if you need to) | `ios/project.yml` → `PRODUCT_BUNDLE_IDENTIFIER` — this is the *only* place it is defined |
| App display name | `ios/project.yml` → `info.properties.CFBundleDisplayName` |
| App version | `ios/project.yml` → `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` |
| Web app files (engine) | `web/public/` |
| Native shell (WKWebView, save bridge, scheme handler) | `ios/Sources/` |
| Icon | `scripts/make-icon.py` (regenerates `ios/Resources/Assets.xcassets`) |
| Workflow | `.github/workflows/build-ipa.yml` |

## Reading build logs

Each workflow run lists four jobs. Open the failed job, tap the failed step
(red), and scroll to the bottom of the log — the real error is usually the last
few lines. Compiler errors look like
`ios/Sources/Foo.swift:12:5: error: ...` and name the exact file and line.

## Local development (for the maintainer, not needed on iPhone)

```
bash scripts/prepare-webdist.sh   # web tests + build + copy into ios/Resources/WebDist
python3 scripts/make-icon.py      # regenerate the icon
cd ios && xcodegen generate       # only if project.yml changed
```
