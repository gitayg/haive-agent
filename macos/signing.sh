# Sourced by dmg.sh. Picks the Developer ID that signs IT-AI.app, as RubberMAC's signing.sh does.
# On a Mac: put the certificate's name (or a part only it has) in macos/.signing-identity, ignored by git,
# or set SIGNING_IDENTITY. On Codemagic, where the keychain holds just the one certificate, the first
# "Developer ID Application" identity is used.
NAME="${SIGNING_IDENTITY:-$(cat "$(dirname "${BASH_SOURCE[0]}")/.signing-identity" 2>/dev/null || true)}"
[ -n "$NAME" ] || [ -z "${CI:-}" ] || NAME="Developer ID Application"
[ -n "$NAME" ] || { echo "No signing identity: put your Developer ID certificate's name in macos/.signing-identity"; exit 1; }
IDENTITY=$(security find-identity -v -p codesigning | awk -v name="$NAME" 'index($0, name) {print $2; exit}')
[ -n "$IDENTITY" ] || { echo "No certificate on this Mac matches '$NAME'"; exit 1; }
