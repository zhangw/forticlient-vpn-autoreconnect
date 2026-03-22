# Manual Integration Testing

Use these tests against a real FortiClient installation. They are the primary QA path for this repo.

## Test Environment

- macOS Apple Silicon
- FortiClient for macOS `7.2.9.1033`
- A working SAML/SSO VPN profile already configured in FortiClient
- Frida CLI installed and able to attach to `FortiClient`
- FortiClient main window open so `guimessenger_jyp.node` is loaded

## Common Setup

```bash
cp vpn_monitor.conf.example vpn_monitor.conf
# edit vpn_monitor.conf:
#   VPN_USERNAME="you@example.com"
#   VPN_CONN_NAME="your_vpn"

./vpn_monitor.sh
```

Expected startup log:

- `VPN Monitor started.`
- Your configured username and connection name are shown
- No immediate `Config file not found` or `Frida script not found` error

## Test 1: Baseline Connected State

1. Connect the VPN normally from FortiClient.
2. Start `./vpn_monitor.sh`.
3. Let it run for at least two poll cycles.

Expected result:

- The monitor repeatedly logs `VPN is up.`
- No reconnect attempt is triggered while the tunnel remains healthy

## Test 2: Sleep / Wake Reconnect

1. Leave `./vpn_monitor.sh` running.
2. Put the Mac to sleep for long enough that the VPN disconnects.
3. Wake the Mac and unlock it.
4. Watch the monitor logs for 30-60 seconds.

Expected result:

- The monitor logs `VPN is down.`
- A one-shot Frida reconnect is triggered
- The VPN reconnects without manual password re-entry
- After recovery, the monitor logs `VPN is back up.`

## Test 3: Network Interruption Reconnect

1. Leave `./vpn_monitor.sh` running while connected.
2. Disable Wi-Fi or unplug the active network briefly.
3. Re-enable network access.

Expected result:

- The monitor detects the drop and attempts reconnect
- The tunnel comes back automatically once network access returns
- Reconnect attempts are not spammed faster than the configured cooldown

## Test 4: SAML Browser Tab Auto-Close

1. Set `SAML_BROWSER` and `SAML_URL_PATTERN` in `vpn_monitor.conf`.
2. Trigger a reconnect that goes through the browser-based SAML flow.
3. Wait for the VPN to come back up.

Expected result:

- The browser opens for SAML if FortiClient requires it
- Once the VPN is back up, the callback tab matching `SAML_URL_PATTERN` is closed
- Unrelated browser tabs remain open

## Test 5: Manual Disconnect Should Stay Disconnected

This validates the resident hook mode rather than the recommended polling mode.

1. Edit [`forti_auto_reconnect.js`](/Users/vincent/Desktop/forti_tool/forti_auto_reconnect.js) so `CONFIG.userName` and `CONFIG.connName` match your VPN profile.
2. Run `./run_auto_reconnect.sh`.
3. Connect the VPN.
4. Click `Disconnect` in the FortiClient UI.

Expected result:

- The script observes the disconnect hooks
- It marks the disconnect as user-initiated
- It does not auto-reconnect after the manual disconnect

## Test 6: Wrong Connection Name / Version Drift

1. Set an invalid `VPN_CONN_NAME` in `vpn_monitor.conf`.
2. Run `./vpn_monitor.sh`.
3. Trigger a reconnect condition.

Expected result:

- Frida runs, but reconnect does not succeed
- Logs clearly show the reconnect path was attempted
- You can use this case to compare behavior after FortiClient upgrades or symbol changes

## Test 7: Multiple `utun` Interfaces Present

This is important on hosts using Tailscale, WireGuard, or another VPN at the same time.

1. Start another tool that creates its own `utun` interface.
2. Leave FortiClient disconnected.
3. Run `./vpn_monitor.sh` with `VPN_INTERNAL_HOST` unset.

Expected result:

- If the monitor reports `VPN is up.` while FortiClient is actually disconnected, `utun` detection is too broad on this host
- In that case, switch to ping-based detection by setting `VPN_INTERNAL_HOST` to a VPN-internal IP

## Test 8: Ping-Based Detection

1. Set `VPN_INTERNAL_HOST` in [`vpn_monitor.sh`](/Users/vincent/Desktop/forti_tool/vpn_monitor.sh) to a stable IP reachable only through the VPN.
2. Start `./vpn_monitor.sh`.
3. Repeat the sleep/wake and network interruption tests.

Expected result:

- Detection is based on actual reachability through the tunnel
- False positives from unrelated `utun` interfaces are eliminated

## Diagnostic Commands

Use these when a manual test fails:

```bash
frida -n "FortiClient" -l recon_exports.js
frida -n "FortiClient" -l quick_status_check.js
frida -n "FortiClient" -l probe_status_functions.js
```

Use them to answer:

- Is `guimessenger_jyp.node` loaded?
- Does `connectTunnel` still exist in this FortiClient version?
- Do disconnect / status hooks still fire as expected?
