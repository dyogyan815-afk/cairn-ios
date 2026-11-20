#!/usr/bin/env bash
# Builds the web app and copies dist/ into the iOS resources as WebDist.
# CI runs this; locally: bash scripts/prepare-webdist.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT/web"
python3 scripts/make-fixtures.py
npm test
npm run build

rm -rf "$ROOT/ios/Resources/WebDist"
cp -R "$ROOT/web/dist" "$ROOT/ios/Resources/WebDist"
find "$ROOT/ios/Resources/WebDist" -type d -name .git | true
echo "WebDist prepared: $(find "$ROOT/ios/Resources/WebDist" -type f | wc -l | tr -d ' ') files"
