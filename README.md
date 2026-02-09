# forti_tool

Auto-reconnect FortiClient VPN on macOS using [Frida](https://frida.re). When the VPN drops (sleep/wake, network change, idle timeout), the tunnel is re-established automatically via FortiClient's native `connectTunnel` function — no password re-entry needed for SAML/SSO connections.

## How It Works

The toolkit offers two operation modes:

| Mode | Script | How it detects drops | Frida lifetime |
|------|--------|---------------------|----------------|
| **External polling** (recommended) | `vpn_monitor.sh` | Shell loop checks `utun` interface or pings a VPN-internal host | Short-lived — attaches only for the reconnect call, then exits |
| **Resident hook** | `forti_auto_reconnect.js` | Hooks `disconnectTunnel` / `VPNCmdDisconnect` inside FortiClient + polling fallback | Long-lived — stays attached to FortiClient |

**External polling is recommended** because a long-running Frida session dies across Mac sleep/wake cycles, which is exactly when you need reconnection the most.

Both modes call `connectTunnel` in FortiClient's `guimessenger_jyp.node` native module, constructing the required `std::string` argument (a JSON blob with connection name, username, and SAML flags).

## Quick Start

### Prerequisites

- macOS (ARM64 / Apple Silicon)
- [Frida](https://frida.re) CLI tools (`pip install frida-tools`)
- FortiClient installed and configured with at least one VPN connection
- SIP adjustments as required by Frida (see Frida docs)

### Setup

```bash
# 1. Clone
git clone <repo-url> && cd forti_tool

# 2. Create your config
cp vpn_monitor.conf.example vpn_monitor.conf
# Edit vpn_monitor.conf — set VPN_USERNAME and VPN_CONN_NAME

# 3. Run
./vpn_monitor.sh
```

The monitor will poll every 10 seconds and trigger a one-shot Frida reconnect when the VPN is down.

## Scripts Reference

### Core

| File | Description |
|------|-------------|
| `vpn_monitor.sh` | Main entry point. External polling loop that detects VPN drops and runs a one-shot Frida reconnect. |
| `vpn_monitor.conf.example` | Template for per-user config (`VPN_USERNAME`, `VPN_CONN_NAME`). Copy to `vpn_monitor.conf`. |
| `forti_client_guimessenger_connect_tunnel_invoke.js` | Minimal Frida script that calls `connectTunnel` once and exits. Used by `vpn_monitor.sh`. |

### Alternative

| File | Description |
|------|-------------|
| `forti_auto_reconnect.js` | Hybrid auto-reconnect: hooks disconnect events for instant detection + polls as fallback. Stays resident in FortiClient. |
| `run_auto_reconnect.sh` | Convenience launcher for `forti_auto_reconnect.js`. |

### Diagnostic / Experimental

| File | Description |
|------|-------------|
| `probe_status_functions.js` | Intercepts 12 status/connect/disconnect functions to observe their signatures and return values. |
| `quick_status_check.js` | One-shot call of all known status functions to check current VPN state. |
| `recon_exports.js` | Enumerates all exports from `guimessenger_jyp.node`, filtering for interesting symbols. |
| `forti-tray-connect.js` | Experimental: triggers connect via FortiTray's ObjC `AppDelegate`. |
| `forti-tray-disconnect.js` | Experimental: triggers disconnect via FortiTray's ObjC `AppDelegate`. |
| `run_frida_forti_client.sh` | One-liner to attach Frida to FortiClient with the invoke script. |
| `dis_forti_client_guimessenger_connect_tunnel.md` | Reverse-engineering notes: disassembly of `MessageSender::ConnectTunnel`, `std::string` layout, lldb session. |

## Configuration

### vpn_monitor.conf

Created by copying `vpn_monitor.conf.example`. Contains your VPN credentials (gitignored):

```bash
VPN_USERNAME="you@example.com"
VPN_CONN_NAME="your_vpn"
```

### vpn_monitor.sh tunables

Edit the variables at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | `10` | Seconds between connectivity checks |
| `RECONNECT_COOLDOWN` | `30` | Minimum seconds between reconnect attempts |
| `VPN_INTERNAL_HOST` | *(empty)* | IP to ping inside VPN. If empty, falls back to `utun` interface detection. |
| `FRIDA_TIMEOUT` | `15` | Seconds before killing a hung Frida invocation |

### forti_auto_reconnect.js tunables

Edit the `CONFIG` object at the top of the script. Notably, `userName` and `connName` are hardcoded in this mode (not read from `vpn_monitor.conf`).

## Troubleshooting

**Frida can't attach to FortiClient**
Frida requires the ability to attach to processes. On macOS, this may require disabling SIP or using `frida-server`. See the [Frida docs](https://frida.re/docs/macos/).

**"Config file not found" on startup**
Copy the example config: `cp vpn_monitor.conf.example vpn_monitor.conf` and fill in your values.

**VPN reconnects but drops again immediately**
Increase `RECONNECT_COOLDOWN` to give the tunnel more time to stabilize. If using ping-based detection, also increase `POLL_INTERVAL` to avoid triggering reconnects while the tunnel is still negotiating.

**"connectTunnel not found"**
The `guimessenger_jyp.node` module hasn't been loaded yet. Make sure FortiClient's main window is open (not just the tray icon).

**Monitor works but dies on sleep/wake**
This is expected for the resident mode (`forti_auto_reconnect.js`). Use `vpn_monitor.sh` instead — it runs outside FortiClient and survives sleep/wake.
