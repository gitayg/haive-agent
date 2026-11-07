#!/bin/bash
# Builds the agent version in Cargo.toml into IT-AI.app and two release assets in macos/dist:
#   IT-AI.dmg        the app and a link to Applications, for installing (by hand or by the hub's install command)
#   IT-AI-macos.zip  the app alone, which IT-AI.app's /update installs (crates/agent/src/appbundle.rs)
# The app is signed with the hardened runtime, notarized and stapled, then the image the same way, so both open
# on another Mac without a warning. Publishes nothing.
# Notarization: with APP_STORE_CONNECT_KEY_IDENTIFIER, APP_STORE_CONNECT_ISSUER_ID and APP_STORE_CONNECT_PRIVATE_KEY
# set (Codemagic), an App Store Connect API key; otherwise the notarytool keychain profile NOTARY_PROFILE (default
# "itai": xcrun notarytool store-credentials itai). Signing identity: see signing.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
TARGET=aarch64-apple-darwin
BUILD=macos/build
DIST=macos/dist
APP="$BUILD/IT-AI.app"
. macos/signing.sh

notarize() {
  if [ -n "${APP_STORE_CONNECT_KEY_IDENTIFIER:-}" ]; then
    local key="$BUILD/AuthKey.p8"
    printf '%s\n' "$APP_STORE_CONNECT_PRIVATE_KEY" > "$key"
    xcrun notarytool submit "$1" --key "$key" --key-id "$APP_STORE_CONNECT_KEY_IDENTIFIER" \
      --issuer "$APP_STORE_CONNECT_ISSUER_ID" --wait
    rm -f "$key"
  else
    xcrun notarytool submit "$1" --keychain-profile "${NOTARY_PROFILE:-itai}" --wait
  fi
}

mkdir -p "$BUILD" "$DIST"
rustup target add "$TARGET" >/dev/null 2>&1 || true
cargo build --release --target "$TARGET" -p it-ai-agent --bin it-ai

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
sed "s/__VERSION__/$VERSION/g" macos/Info.plist > "$APP/Contents/Info.plist"
cp "target/$TARGET/release/it-ai" "$APP/Contents/MacOS/it-ai"
cp macos/icon/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --force --options runtime --entitlements macos/it-ai.entitlements --timestamp --sign "$IDENTITY" "$APP"
codesign --verify --strict "$APP"

# The app is notarized and stapled on its own first, so the copy in the update zip and one dragged out of the
# image both open offline.
rm -f "$BUILD/notarize.zip"
ditto -c -k --keepParent "$APP" "$BUILD/notarize.zip"
notarize "$BUILD/notarize.zip"
rm -f "$BUILD/notarize.zip"
xcrun stapler staple "$APP"

rm -f "$DIST/IT-AI-macos.zip"
ditto -c -k --keepParent "$APP" "$DIST/IT-AI-macos.zip"

STAGE="$BUILD/dmg"
rm -rf "$STAGE" "$DIST/IT-AI.dmg"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/IT-AI.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "IT-AI $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO "$DIST/IT-AI.dmg"
rm -rf "$STAGE"
codesign --force --timestamp --sign "$IDENTITY" "$DIST/IT-AI.dmg"
notarize "$DIST/IT-AI.dmg"
xcrun stapler staple "$DIST/IT-AI.dmg"

spctl --assess --type execute -vv "$APP"
spctl --assess --type open --context context:primary-signature -vv "$DIST/IT-AI.dmg"
echo "made $DIST/IT-AI.dmg and $DIST/IT-AI-macos.zip ($VERSION)"
