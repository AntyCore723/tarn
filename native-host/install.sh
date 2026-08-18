#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# install.sh — installs the Tarn native messaging host
# Usage: ./install.sh [extension_id]
#
# What this does:
#   1. Detects Python 3
#   2. (Optionally) downloads the wireproxy binary for your OS/arch
#   3. Writes the native-messaging manifest pointing at tarn_host.py
#   4. Tells you where it was installed
set -e

EXT_ID="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PY="$SCRIPT_DIR/tarn_host.py"
APP_DIR="$HOME/.tarn-tunnel"
BIN_DIR="$APP_DIR/bin"
mkdir -p "$BIN_DIR"

chmod +x "$HOST_PY" 2>/dev/null || true

# ---- 1. python3 ----
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then
  echo "ERROR: python3 not found. Install Python 3.8+." >&2
  exit 1
fi
echo "✓ Python: $PY"

# ---- 2. wireproxy ----
WP="$BIN_DIR/wireproxy"
need_download=1
if [ -x "$WP" ]; then
  if "$WP" --version >/dev/null 2>&1 || "$WP" -h >/dev/null 2>&1; then
    echo "✓ wireproxy already installed: $WP"
    need_download=0
  fi
fi
if [ "$need_download" = "1" ]; then
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "WARN: unsupported arch $ARCH — download wireproxy manually from https://github.com/windtf/wireproxy/releases" >&2 ;;
  esac
  # wireproxy release file naming (all assets are .tar.gz archives)
  case "$OS-$ARCH" in
    linux-amd64)  FNAME="wireproxy_linux_amd64.tar.gz" ;;
    linux-arm64)  FNAME="wireproxy_linux_arm64.tar.gz" ;;
    darwin-amd64) FNAME="wireproxy_darwin_amd64.tar.gz" ;;
    darwin-arm64) FNAME="wireproxy_darwin_arm64.tar.gz" ;;
    *) FNAME="" ;;
  esac
  # Pinned SHA-256 of the extracted wireproxy binary per platform
  # (keep in sync with WIREPROXY_SHA256 in tarn_host.py; v1.1.3).
  case "$OS-$ARCH" in
    linux-amd64)  WPHASH="70ae5e52223dac7974af8d98a321f14a0e1689d2b14655ebc8dadfa1ec69466d" ;;
    linux-arm64)  WPHASH="5852e32671afb8918c39c59330b85f833c187ed41b6b1f683c90b6bfd320f3fa" ;;
    darwin-amd64) WPHASH="1e76b051e47fa34d40904712484ae94b82d9a9ee01afe0a5ceb8f7eac555c7b4" ;;
    darwin-arm64) WPHASH="37889c2f0ea4a9f2f59fc1bfefc372b24ffc4e56e2e34a0188aabe3a4e8c1ec3" ;;
    *) WPHASH="" ;;
  esac
  if [ -n "$FNAME" ]; then
    URL="https://github.com/windtf/wireproxy/releases/download/v1.1.3/$FNAME"
    echo "↓ Downloading wireproxy from $URL ..."
    if curl -fsSL "$URL" -o "$WP.tmp" || wget -qO "$WP.tmp" "$URL"; then
      # Extract, then verify the binary's SHA-256 against the pinned hash
      # before installing it (supply-chain check).
      if tar -xzf "$WP.tmp" -C "$BIN_DIR" wireproxy 2>/dev/null; then
        ACTUAL=$(sha256sum "$WP" 2>/dev/null | awk '{print $1}')
        if [ -z "$ACTUAL" ]; then ACTUAL=$(shasum -a 256 "$WP" 2>/dev/null | awk '{print $1}'); fi
        if [ -n "$ACTUAL" ] && [ "$ACTUAL" = "$WPHASH" ]; then
          chmod +x "$WP"
          rm -f "$WP.tmp"
          echo "✓ wireproxy installed and verified: $WP"
        else
          echo "ERROR: wireproxy SHA-256 mismatch (got '$ACTUAL', expected '$WPHASH'). Refusing to install." >&2
          rm -f "$WP" "$WP.tmp"
          exit 1
        fi
      else
        echo "WARN: could not extract wireproxy from archive. Install manually from:" >&2
        echo "      https://github.com/windtf/wireproxy/releases" >&2
        rm -f "$WP.tmp"
      fi
    else
      echo "WARN: could not download wireproxy. The host will attempt a download on first connect, or install manually from:" >&2
      echo "      https://github.com/windtf/wireproxy/releases" >&2
      rm -f "$WP.tmp"
    fi
  fi
fi

# ---- 3. extension id ----
if [ -z "$EXT_ID" ]; then
  echo ""
  echo "--- Auto-detecting Extension ID ---"
  
  # Try to find from Chrome/Edge Preferences
  for PREFS_FILE in \
    "$HOME/.config/google-chrome/Default/Preferences" \
    "$HOME/.config/google-chrome/Profile 1/Preferences" \
    "$HOME/.config/chromium/Default/Preferences" \
    "$HOME/Library/Application Support/Google/Chrome/Default/Preferences" \
    "$HOME/Library/Application Support/Google/Chrome/Profile 1/Preferences" \
    "$HOME/Library/Application Support/Microsoft Edge/Default/Preferences"; do
    if [ -f "$PREFS_FILE" ]; then
      # Use python to parse JSON and find WG Tunnel extension
      FOUND_ID=$(python3 -c "
import json, sys
try:
    with open('$PREFS_FILE') as f:
        prefs = json.load(f)
    settings = prefs.get('extensions', {}).get('settings', {})
    for ext_id, ext_data in settings.items():
        name = ext_data.get('manifest', {}).get('name', '')
        if name == 'Tarn' or name == 'WG Tunnel':
            print(ext_id)
            break
except: pass
" 2>/dev/null)
      if [ -n "$FOUND_ID" ]; then
        EXT_ID="$FOUND_ID"
        echo "[AUTO-DETECTED] Extension ID: $EXT_ID"
        break
      fi
    fi
  done
  
  if [ -z "$EXT_ID" ]; then
    echo "Could not auto-detect Extension ID."
    echo ""
    echo "Find it on chrome://extensions (Developer mode) -> ID column."
    echo "Re-run: $0 <extension_id>"
    EXT_ID="UNKNOWN_EXTENSION_ID"
  fi
fi

# ---- 4. install native-messaging manifest ----
detect_dir() {
  for d in \
    "$HOME/.config/google-chrome/NativeMessagingHosts" \
    "$HOME/.config/chromium/NativeMessagingHosts" \
    "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
    "$HOME/.config/Microsoft Edge/NativeMessagingHosts" \
    "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" \
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
    "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"; do
    parent="$(dirname "$d")"
    if [ -d "$parent" ] || [ -d "$d" ]; then
      mkdir -p "$d"; echo "$d"; return
    fi
  done
  echo "$HOME/.config/google-chrome/NativeMessagingHosts"
}

DIR="$(detect_dir)"
mkdir -p "$DIR"
INSTALLED_JSON="$DIR/com.tarn.host.json"

# path points at the script alone: tarn_host.py has a
# #!/usr/bin/env python3 shebang and is chmod +x. The native-messaging
# manifest `path` is exec'd DIRECTLY by the browser (no shell), so a
# two-token value ("python /path/to/host.py") breaks on Linux/macOS.
cat > "$INSTALLED_JSON" <<EOF
{
  "name": "com.tarn.host",
  "description": "Tarn native messaging host",
  "type": "stdio",
  "path": "$HOST_PY",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF

echo ""
echo "✓ Native messaging manifest installed:"
echo "   $INSTALLED_JSON"
echo "   python:   $PY"
echo "   script:   $HOST_PY"
echo "   ext id:   $EXT_ID"
echo "   app dir:  $APP_DIR"
echo ""
echo "Next steps:"
echo "   1. Restart your browser"
echo "   2. Open the extension → Options → Settings → click the host check button"
echo "      (the host check button shows a green status when connected)"
echo "   3. Connect a profile — traffic will now go through WG"
