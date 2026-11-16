#!/usr/bin/env bash
# Install the OMEGA Hermes plugin into ~/.hermes/plugins/ (or $HERMES_HOME/plugins/).
# Records THIS repo's absolute location into the plugin so the tools resolve
# the OMEGA installation deterministically - no directory guessing anywhere.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/omega"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST="${HERMES_HOME:-$HOME/.hermes}/plugins"

if [ ! -f "$SRC/plugin.yaml" ] || [ ! -f "$SRC/__init__.py" ]; then
  echo "error: $SRC does not look like a plugin package" >&2
  exit 1
fi

# Pin the actual repo location into the installed plugin copy.
printf '%s\n' "$REPO_ROOT" > "$SRC/_omega_home.txt"

mkdir -p "$DEST"
rm -rf "$DEST/omega"
cp -r "$SRC" "$DEST/"

echo "Installed OMEGA plugin -> $DEST/omega"
echo "Pinned OMEGA repo      -> $REPO_ROOT"
echo
echo "Next steps:"
echo "  1. Restart Hermes (or start a new session) so the plugin loader picks it up."
echo "  2. Verify the plugin list shows 'omega' with the eight tools:"
echo "     omega_scan, omega_assault, omega_validate, omega_followup,"
echo "     omega_chains, omega_sessions, omega_report, omega_stats."
echo "  3. Optional overrides: OMEGA_HOME=/path/to/omega (env) beats the pinned path."
echo "  4. omega_scan / omega_assault require scope_ack=true per call - it asserts"
echo "     operator authorization."
