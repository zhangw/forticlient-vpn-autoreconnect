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
SAML_BROWSER="Google Chrome"    # browser app name for SAML tab auto-close
SAML_URL_PATTERN="127.0.0.1:8020"  # FortiClient's local SAML callback server
FRIDA_SCRIPT="$(cd "$(dirname "$0")" && pwd)/forti_client_guimessenger_connect_tunnel_invoke.js"
FRIDA_TIMEOUT=15          # seconds before killing a hung frida invocation

# Per-user VPN credentials — loaded from vpn_monitor.conf
# Copy vpn_monitor.conf.example to vpn_monitor.conf and fill in your values.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/vpn_monitor.conf"
if [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
else
    echo "ERROR: Config file not found: ${CONF_FILE}"
    echo "Copy vpn_monitor.conf.example to vpn_monitor.conf and fill in your values."
    exit 1
fi
# ─────────────────────────────────────────────────────────────────────

last_reconnect_ts=0
vpn_was_down=false
saml_close_pending=false  # set after script-initiated reconnect; cleared after browser tab close

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

# ── Focus helpers ────────────────────────────────────────────────────

save_focused_app() {
    _saved_app=$(osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true' 2>/dev/null)
}

restore_focused_app() {
    [[ -n "$_saved_app" ]] && osascript -e "tell application \"$_saved_app\" to activate" 2>/dev/null
    _saved_app=""
}

hide_forticlient() {
    osascript -e 'tell application "System Events" to set visible of process "FortiClient" to false' 2>/dev/null
}

# ── SAML browser auto-close ──────────────────────────────────────────

close_saml_browser_window() {
    # Closes the browser tab left open after SAML/SSO auth.
    # Saves and restores the frontmost app so the tab close doesn't steal focus.
    [[ -z "$SAML_URL_PATTERN" ]] && return
    log "Closing SAML browser tab (browser: $SAML_BROWSER, pattern: $SAML_URL_PATTERN)..."
    osascript 2>/dev/null <<OSAEOF
tell application "System Events"
    set prevApp to name of first application process whose frontmost is true
end tell
tell application "$SAML_BROWSER"
    repeat with w in windows
        tell w
            set n to count tabs
            repeat with i from n to 1 by -1
                if URL of tab i contains "$SAML_URL_PATTERN" then
                    close tab i
                end if
            end repeat
        end tell
    end repeat
end tell
tell application prevApp to activate
OSAEOF
    log "SAML browser close done."
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
    saml_close_pending=true

    # Save the focused app before SAML opens the browser.
    save_focused_app

    # Build a temp script: config preamble + core logic.
    # Frida scripts run in isolated scopes, so we concatenate them into one file.
    local tmp_script
    tmp_script=$(mktemp /tmp/frida_reconnect.XXXXXX.js)
    printf 'const userName = %s;\nconst connName = %s;\n' \
        "$(printf '%s' "$VPN_USERNAME" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "$VPN_CONN_NAME" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')" \
        > "$tmp_script"
    cat "$FRIDA_SCRIPT" >> "$tmp_script"

    # Run frida with a timeout to prevent hangs.
    # -q: quiet mode (suppress banner)
    # < /dev/null: feed EOF to stdin so frida exits immediately after the
    #   script finishes instead of waiting in its REPL.  Without this, frida
    #   stays attached to FortiClient for up to FRIDA_TIMEOUT seconds, and
    #   that instrumentation blocks the VPN from actually reconnecting.
    if timeout "$FRIDA_TIMEOUT" frida -n "FortiClient" -l "$tmp_script" -q < /dev/null 2>&1 | while IFS= read -r line; do
        log "  frida: $line"
    done; then
        log "Frida reconnect command completed."
    else
        log "Frida reconnect command failed or timed out."
    fi

    # Give FortiClient a moment to start the tunnel after frida detaches.
    sleep 2

    # Hide FortiClient and restore focus stolen by the SAML browser popup.
    hide_forticlient
    restore_focused_app

    rm -f "$tmp_script"
}

# ── Main loop ────────────────────────────────────────────────────────

log "VPN Monitor started."
log "  Poll interval : ${POLL_INTERVAL}s"
log "  Cooldown      : ${RECONNECT_COOLDOWN}s"
log "  VPN host check: ${VPN_INTERNAL_HOST:-"(none — using utun detection)"}"
log "  VPN username  : ${VPN_USERNAME}"
log "  VPN conn name : ${VPN_CONN_NAME}"
log "  Frida script  : ${FRIDA_SCRIPT}"
log "  SAML browser  : ${SAML_BROWSER}"
log "  SAML pattern  : ${SAML_URL_PATTERN:-"(disabled)"}"
log ""

if [[ ! -f "$FRIDA_SCRIPT" ]]; then
    log "ERROR: Frida script not found at ${FRIDA_SCRIPT}"
    exit 1
fi

while true; do
    if vpn_is_up; then
        if $vpn_was_down; then
            log "VPN is back up."
            vpn_was_down=false
            hide_forticlient
            if $saml_close_pending; then
                # Close SAML tabs now and retry in the background — the tab
                # may not exist yet if the SAML redirect is still in flight.
                close_saml_browser_window
                ( sleep 5;  close_saml_browser_window;
                  sleep 10; close_saml_browser_window ) &
                saml_close_pending=false
            fi
        else
            log "VPN is up."
        fi
    else
        vpn_was_down=true
        log "VPN is down."
        attempt_reconnect
    fi
    sleep "$POLL_INTERVAL"
done
