// forti_auto_reconnect.js
// Hybrid approach: hooks disconnectTunnel + VPNCmdDisconnect for instant
// detection, plus polls network (utun/ping) as a safety-net fallback.
// Stays resident inside FortiClient via Frida.
//
// Usage: frida -n "FortiClient" -l forti_auto_reconnect.js
//
// Probe findings (2026-02-10):
//   - disconnectTunnel fires on user-initiated disconnect
//   - VPNCmdDisconnect fires right after, returns 0
//   - servctl::api::is_connected checks IPC not tunnel (always 0), useless
//   - connectTunnel does NOT fire on UI connect (SAML path), but direct
//     invocation via NativeFunction works for reconnecting

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
  moduleName:      'guimessenger_jyp.node',
  userName:        'zw@webull.com',
  connName:        'webull',
  pollIntervalMs:  10000,   // 10s between connectivity checks
  reconnectDelayMs: 5000,   // 5s delay after disconnect detected before reconnect
  reconnectCooldownMs: 30000, // 30s cooldown between reconnect attempts
  connectGracePeriodMs: 30000, // 30s grace after connectTunnel before polling resumes
  // Internal host IP reachable only through VPN.
  // Set to an IP (e.g. '10.x.x.x') for ping-based check (most reliable).
  // Set to null to use utun interface check instead.
  vpnInternalHost: null,
};

// ============================================================
// State
// ============================================================
let lastReconnectTime = 0;
let reconnecting = false;
// Track whether disconnect was user-initiated (via UI) so we don't
// auto-reconnect when the user explicitly disconnects.
// Stays true until the user manually reconnects from the UI.
let userInitiatedDisconnect = false;
// Grace period: when connectTunnel is called, suppress polling for a while
// to let the tunnel come up before checking the utun interface.
let connectGraceUntil = 0;

// ============================================================
// connectTunnel helper (reused from existing logic)
// ============================================================
function callConnectTunnel() {
  const funcAddress = Module.findExportByName(CONFIG.moduleName, 'connectTunnel');
  if (!funcAddress) {
    console.log('[!] connectTunnel not found, cannot reconnect');
    return false;
  }

  const fnConnectTunnel = new NativeFunction(ptr(funcAddress), 'pointer', ['pointer']);

  const connObject = {
    connection_name: CONFIG.connName,
    connection_type: 'ssl',
    password:        '',
    username:        CONFIG.userName,
    save_username:   false,
    save_password:   '0',
    always_up:       '0',
    auto_connect:    '0',
    saml_error:      1,
    saml_type:       1,
  };

  const connJSONStr = JSON.stringify(connObject);
  const utf8buf     = Memory.allocUtf8String(connJSONStr);
  const strLen      = connJSONStr.length;

  // Build libc++ std::string layout (arm64)
  const strControlBase   = 0x8000000000000000n;
  const full64StrControl = strControlBase + (BigInt(strLen) + 1n);
  const uint64StrControl = uint64(full64StrControl.toString());

  const strMem = Memory.alloc(32);
  Memory.writePointer(strMem,        utf8buf);            // _M_ptr
  Memory.writeU64(strMem.add(8),     strLen);             // _M_size
  Memory.writeU64(strMem.add(16),    uint64StrControl);   // _M_capacity + sso flag

  const ret = fnConnectTunnel(strMem);
  const ok  = ret.toInt32() === 0;
  console.log(`[*] connectTunnel returned: ${ok ? 'OK' : 'Failed'}`);
  return ok;
}

// ============================================================
// Reconnect with cooldown guard
// ============================================================
function tryReconnect(reason) {
  const now = Date.now();
  if (reconnecting) {
    console.log('[~] Reconnect already in progress, skipping');
    return;
  }
  if (now - lastReconnectTime < CONFIG.reconnectCooldownMs) {
    const remaining = Math.ceil((CONFIG.reconnectCooldownMs - (now - lastReconnectTime)) / 1000);
    console.log(`[~] Cooldown active, retry in ${remaining}s`);
    return;
  }

  reconnecting = true;
  lastReconnectTime = now;
  console.log(`\n[!] VPN disconnected (${reason}), attempting reconnect...`);

  try {
    callConnectTunnel();
  } catch (e) {
    console.log(`[!] Reconnect error: ${e.message}`);
  } finally {
    reconnecting = false;
  }
}

// ============================================================
// Part A: Hook-based detection (instant, event-driven)
//
// Confirmed by probing:
//   disconnectTunnel  → fires first on disconnect
//   VPNCmdDisconnect  → fires right after, retval 0
// ============================================================
function setupHooks() {
  let hooked = false;

  // --- Hook disconnectTunnel (C-level, fires on any disconnect) ---
  const disconnectTunnelAddr = Module.findExportByName(CONFIG.moduleName, 'disconnectTunnel');
  if (disconnectTunnelAddr) {
    Interceptor.attach(disconnectTunnelAddr, {
      onEnter(args) {
        console.log('[hook] disconnectTunnel called — disconnect detected');
      },
      onLeave(retval) {
        // Schedule reconnect after a delay to let teardown finish.
        // The polling fallback will also catch it if this somehow misses.
        setTimeout(() => {
          if (!userInitiatedDisconnect) {
            tryReconnect('disconnectTunnel hook');
          } else {
            console.log('[hook] Skipping reconnect — user-initiated disconnect');
            // Keep userInitiatedDisconnect = true so polling also skips.
            // It will be reset when the user reconnects from the UI.
          }
        }, CONFIG.reconnectDelayMs);
      },
    });
    console.log(`[+] Hooked disconnectTunnel @ ${disconnectTunnelAddr}`);
    hooked = true;
  } else {
    console.log('[-] disconnectTunnel not found');
  }

  // --- Hook VPNCmdDisconnect (higher-level command) ---
  const vpnCmdDisconnectAddr = Module.findExportByName(CONFIG.moduleName, 'VPNCmdDisconnect');
  if (vpnCmdDisconnectAddr) {
    Interceptor.attach(vpnCmdDisconnectAddr, {
      onEnter(args) {
        console.log('[hook] VPNCmdDisconnect called');
      },
      onLeave(retval) {
        console.log(`[hook] VPNCmdDisconnect returned: ${retval.toInt32()}`);
      },
    });
    console.log(`[+] Hooked VPNCmdDisconnect @ ${vpnCmdDisconnectAddr}`);
    hooked = true;
  }

  // --- Hook MessageSender::DisconnectTunnel (Napi wrapper, UI-initiated) ---
  // When this fires, it means the user clicked "Disconnect" in the UI.
  const msDisconnectAddr = Module.findExportByName(
    CONFIG.moduleName,
    '_ZN13MessageSender16DisconnectTunnelERKN4Napi12CallbackInfoE'
  );
  if (msDisconnectAddr) {
    Interceptor.attach(msDisconnectAddr, {
      onEnter(args) {
        console.log('[hook] MessageSender::DisconnectTunnel (UI) — marking user-initiated');
        userInitiatedDisconnect = true;
      },
    });
    console.log(`[+] Hooked MessageSender::DisconnectTunnel @ ${msDisconnectAddr}`);
  }

  // --- Hook connectTunnel to detect user-initiated reconnect ---
  // Clears the userInitiatedDisconnect flag so auto-reconnect resumes.
  // Also sets a grace period so polling doesn't fire while the tunnel is coming up.
  const connectTunnelAddr = Module.findExportByName(CONFIG.moduleName, 'connectTunnel');
  if (connectTunnelAddr) {
    Interceptor.attach(connectTunnelAddr, {
      onEnter(args) {
        // Suppress polling while the tunnel establishes
        connectGraceUntil = Date.now() + CONFIG.connectGracePeriodMs;
        console.log(`[hook] connectTunnel called — polling suppressed for ${CONFIG.connectGracePeriodMs / 1000}s`);
        if (userInitiatedDisconnect) {
          console.log('[hook] Clearing user-initiated flag, auto-reconnect resumed');
          userInitiatedDisconnect = false;
        }
      },
    });
    console.log(`[+] Hooked connectTunnel @ ${connectTunnelAddr}`);
  }

  return hooked;
}

// ============================================================
// Part B: Polling-based fallback (safety net)
// Catches cases the hooks might miss, e.g. network-level drops
// where the daemon kills the tunnel without going through the
// hooked code paths in the GUI process.
// ============================================================

function checkVpnByPing(host) {
  const systemFn = new NativeFunction(
    Module.findExportByName('libSystem.B.dylib', 'system'),
    'int',
    ['pointer']
  );
  const cmdStr = Memory.allocUtf8String(
    `ping -c 1 -W 2 ${host} > /dev/null 2>&1`
  );
  return systemFn(cmdStr) === 0;
}

function checkVpnByUtun() {
  const systemFn = new NativeFunction(
    Module.findExportByName('libSystem.B.dylib', 'system'),
    'int',
    ['pointer']
  );
  // FortiClient creates a utun interface when the tunnel is up.
  // Check if any utun interface has an inet address assigned.
  const cmdStr = Memory.allocUtf8String(
    'ifconfig | grep -A5 "^utun" | grep -q "inet " && exit 0 || exit 1'
  );
  return systemFn(cmdStr) === 0;
}

function pollConnectivity() {
  let connected;
  if (CONFIG.vpnInternalHost) {
    connected = checkVpnByPing(CONFIG.vpnInternalHost);
  } else {
    connected = checkVpnByUtun();
  }

  if (!connected && !userInitiatedDisconnect && Date.now() > connectGraceUntil) {
    tryReconnect(CONFIG.vpnInternalHost
      ? `ping ${CONFIG.vpnInternalHost} failed`
      : 'utun interface down');
  }
}

// ============================================================
// Main
// ============================================================
console.log('=== FortiClient VPN Auto-Reconnect (Hybrid) ===');
console.log(`  Connection : ${CONFIG.connName}`);
console.log(`  User       : ${CONFIG.userName}`);
console.log(`  Poll interval    : ${CONFIG.pollIntervalMs / 1000}s`);
console.log(`  Reconnect delay  : ${CONFIG.reconnectDelayMs / 1000}s`);
console.log(`  Reconnect cooldown : ${CONFIG.reconnectCooldownMs / 1000}s`);
console.log(`  Connect grace      : ${CONFIG.connectGracePeriodMs / 1000}s`);
console.log('');

const hasHooks = setupHooks();
console.log(`\n[*] Hook-based detection: ${hasHooks ? 'ACTIVE' : 'INACTIVE (no symbol found)'}`);

console.log(`[*] Starting polling fallback (every ${CONFIG.pollIntervalMs / 1000}s)...`);
setInterval(pollConnectivity, CONFIG.pollIntervalMs);

console.log('[*] Auto-reconnect monitor is running. Press Ctrl+C to stop.\n');
