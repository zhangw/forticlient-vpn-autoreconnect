#!/bin/bash
# vpn_monitor.sh
# External VPN connectivity monitor with one-shot Frida reconnect.
#
# Instead of maintaining a long-running Frida session (which dies across
# Mac sleep/wake), this script polls VPN status externally and only
# attaches Frida briefly when a reconnect is needed.
#
# Usage: ./vpn_monitor.sh

# ── Configuration ────────────────────────────────────────────────────
POLL_INTERVAL=10          # seconds between connectivity checks
RECONNECT_COOLDOWN=30     # seconds to wait after a reconnect attempt
VPN_INTERNAL_HOST=""      # ping target inside VPN (leave empty to skip)
FRIDA_SCRIPT="$(cd "$(dirname "$0")" && pwd)/forti_client_guimessenger_connect_tunnel_invoke.js"
FRIDA_TIMEOUT=15          # seconds before killing a hung frida invocation
# ─────────────────────────────────────────────────────────────────────

last_reconnect_ts=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

cleanup() {
    log "Shutting down VPN monitor."
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Connectivity checks ─────────────────────────────────────────────

check_vpn_ping() {
    # Returns 0 (success) if the VPN-internal host is reachable.
    ping -c1 -W2 "$VPN_INTERNAL_HOST" >/dev/null 2>&1
}

check_utun_interface() {
    # Returns 0 if any utun interface has an inet address assigned.
    ifconfig | grep -A5 "^utun" | grep -q "inet "
}

vpn_is_up() {
    if [[ -n "$VPN_INTERNAL_HOST" ]]; then
        check_vpn_ping
    else
        check_utun_interface
    fi
}

# ── Reconnect via one-shot Frida ─────────────────────────────────────

attempt_reconnect() {
    local now
    now=$(date +%s)
    local elapsed=$(( now - last_reconnect_ts ))

    if (( elapsed < RECONNECT_COOLDOWN )); then
        log "Cooldown active (${elapsed}s/${RECONNECT_COOLDOWN}s). Skipping reconnect."
        return
    fi

    log "VPN down — triggering one-shot Frida reconnect..."
    last_reconnect_ts=$now

    # Run frida with a timeout to prevent hangs.
    # --no-pause: don't pause the target process
    # -q: quiet mode (suppress banner)
    if timeout "$FRIDA_TIMEOUT" frida -n "FortiClient" -l "$FRIDA_SCRIPT" --no-pause -q 2>&1 | while IFS= read -r line; do
        log "  frida: $line"
    done; then
        log "Frida reconnect command completed."
    else
        log "Frida reconnect command failed or timed out."
    fi
}

# ── Main loop ────────────────────────────────────────────────────────

log "VPN Monitor started."
log "  Poll interval : ${POLL_INTERVAL}s"
log "  Cooldown      : ${RECONNECT_COOLDOWN}s"
log "  VPN host check: ${VPN_INTERNAL_HOST:-"(none — using utun detection)"}"
log "  Frida script  : ${FRIDA_SCRIPT}"
log ""

if [[ ! -f "$FRIDA_SCRIPT" ]]; then
    log "ERROR: Frida script not found at ${FRIDA_SCRIPT}"
    exit 1
fi

while true; do
    if vpn_is_up; then
        log "VPN is up."
    else
        log "VPN is down."
        attempt_reconnect
    fi
    sleep "$POLL_INTERVAL"
done
