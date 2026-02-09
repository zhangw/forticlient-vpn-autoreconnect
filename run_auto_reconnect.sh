#!/bin/bash
# run_auto_reconnect.sh
# Launches the hybrid auto-reconnect Frida script against FortiClient.
# Usage: ./run_auto_reconnect.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRIDA_SCRIPT="${SCRIPT_DIR}/forti_auto_reconnect.js"

echo "=== FortiClient VPN Auto-Reconnect Launcher ==="
echo "Attaching to FortiClient with Frida..."
echo "Press Ctrl+C to stop."
echo ""

frida -n "FortiClient" -l "$FRIDA_SCRIPT"
