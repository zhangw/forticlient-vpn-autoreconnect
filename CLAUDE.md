# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**forti_tool** — Auto-reconnect FortiClient VPN on macOS using [Frida](https://frida.re). When the VPN drops (sleep/wake, network change, idle timeout), the tunnel is re-established automatically via FortiClient's native `connectTunnel` function — no password re-entry needed for SAML/SSO connections.

## Running the Monitor

### Recommended: External polling mode (survives sleep/wake)
```bash
# One-time setup
cp vpn_monitor.conf.example vpn_monitor.conf
# Edit vpn_monitor.conf — set VPN_USERNAME and VPN_CONN_NAME

./vpn_monitor.sh
```

### Alternative: Resident hook mode (dies on sleep/wake)
```bash
./run_auto_reconnect.sh
# or directly:
frida -n "FortiClient" -l forti_auto_reconnect.js
```

### Diagnostic scripts (attach to FortiClient and observe)
```bash
frida -n "FortiClient" -l recon_exports.js          # enumerate module exports
frida -n "FortiClient" -l probe_status_functions.js  # intercept 12 status functions
frida -n "FortiClient" -l quick_status_check.js      # one-shot status check
```

## Architecture

### Two-Mode Design

**Mode 1 — External polling** (`vpn_monitor.sh` + `forti_client_guimessenger_connect_tunnel_invoke.js`):
- Shell loop polls VPN status every `POLL_INTERVAL` seconds
- VPN detection: ping a VPN-internal host (`VPN_INTERNAL_HOST`) or fall back to `utun` interface check
- On drop: injects credentials as JS variables, concatenates them with the invoke script into a temp file, runs `frida -n "FortiClient" -l <tmpfile> -q < /dev/null` with a timeout, then cleans up
- Frida attaches only briefly — this is why it survives sleep/wake

**Mode 2 — Resident hook** (`forti_auto_reconnect.js`):
- Hooks `disconnectTunnel`, `VPNCmdDisconnect`, `MessageSender::DisconnectTunnel` for instant event-driven detection
- Tracks `userInitiatedDisconnect` flag so manual disconnects are not auto-reconnected
- Polling fallback via `setInterval` as safety net for network-level drops
- `connectGraceUntil` suppresses polling while a tunnel is coming up

### The `connectTunnel` Invocation

Both modes call the same C-level export from `guimessenger_jyp.node` (FortiClient's Electron native addon at `/Applications/FortiClient.app/Contents/Resources/app.asar.unpacked/assets/js/guimessenger_jyp.node`).

The function signature is `connectTunnel(const std::string&)`. Because Frida scripts can't construct a C++ `std::string` naturally, the scripts manually build the libc++ arm64 `std::string` memory layout (32 bytes: `_M_ptr` at +0, `_M_size` at +8, `_M_capacity`/SSO flag at +16 with high bit `0x8000000000000000` set).

The argument is a JSON blob:
```json
{"connection_name":"<VPN_CONN_NAME>","connection_type":"ssl","password":"","username":"<VPN_USERNAME>","save_username":false,"save_password":"0","always_up":"0","auto_connect":"0","saml_error":1,"saml_type":1}
```

### Configuration

`vpn_monitor.conf` (gitignored, created from `vpn_monitor.conf.example`):
```bash
VPN_USERNAME="you@example.com"
VPN_CONN_NAME="your_vpn"
```

Tunables at the top of `vpn_monitor.sh`: `POLL_INTERVAL`, `RECONNECT_COOLDOWN`, `VPN_INTERNAL_HOST`, `FRIDA_TIMEOUT`.

Tunables in the `CONFIG` object at the top of `forti_auto_reconnect.js`: `userName`, `connName`, `pollIntervalMs`, `reconnectDelayMs`, `reconnectCooldownMs`, `connectGracePeriodMs`, `vpnInternalHost`.

## Prerequisites

- macOS ARM64 (Apple Silicon) — the `std::string` layout is arm64-specific
- `frida-tools` (`pip install frida-tools`)
- FortiClient installed, configured, and its main window open (not just tray) so `guimessenger_jyp.node` is loaded
- SIP adjustments as required by Frida

## Key Symbols in `guimessenger_jyp.node`

| Symbol | Role |
|--------|------|
| `connectTunnel` | Core reconnect function — takes `const std::string&` JSON |
| `disconnectTunnel` | Fires on any disconnect |
| `VPNCmdDisconnect` | Higher-level disconnect command |
| `_ZN13MessageSender16DisconnectTunnelERKN4Napi12CallbackInfoE` | UI-initiated disconnect (marks user intent) |
| `VPNCmdGetStatus`, `setConnectionState`, `getConnectionStateString` | Status observation |

## Reverse Engineering Notes

`dis_forti_client_guimessenger_connect_tunnel.md` contains lldb session transcripts and ARM64 disassembly of `MessageSender::ConnectTunnel` — useful reference if FortiClient updates change the `std::string` layout or function signatures.
