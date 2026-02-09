// probe_status_functions.js
// Probes key VPN status/connect/disconnect functions to determine
// their signatures and return values.
// Usage: frida -n "FortiClient" -l probe_status_functions.js

const moduleName = 'guimessenger_jyp.node';

function resolve(name) {
  const addr = Module.findExportByName(moduleName, name);
  if (!addr) console.log(`  [!] ${name} NOT FOUND`);
  return addr;
}

// Helper: try to read a C string from a pointer (with safety)
function tryReadCString(p) {
  try {
    if (p.isNull()) return '(null)';
    return p.readCString();
  } catch (e) {
    return `(unreadable: ${p})`;
  }
}

// Helper: try to read a std::string from a pointer
function tryReadStdString(p) {
  try {
    if (p.isNull()) return '(null)';
    // libc++ std::string layout on arm64:
    // If SSO (short string optimization): data is inline at p+1, length at byte 0 >> 1
    // If heap-allocated: ptr at p+0, size at p+8
    const firstByte = p.readU8();
    if ((firstByte & 1) === 0) {
      // SSO: length = firstByte >> 1, data starts at p+1
      const len = firstByte >> 1;
      return p.add(1).readUtf8String(len);
    } else {
      // Heap: pointer at p+0 (but masked), size at p+8, data ptr at p+16
      const dataPtr = p.add(16).readPointer();
      const size = p.add(8).readU64();
      return dataPtr.readUtf8String(Number(size));
    }
  } catch (e) {
    return `(std::string read failed: ${e.message})`;
  }
}

console.log('=== Probing VPN Status Functions ===\n');

// ============================================================
// 1. servctl::api::is_connected — likely bool(void)
// ============================================================
console.log('--- 1. servctl::api::is_connected ---');
const isConnectedAddr = resolve('_ZN7servctl3api12is_connectedEv');
if (isConnectedAddr) {
  try {
    const fnIsConnected = new NativeFunction(isConnectedAddr, 'bool', []);
    const result = fnIsConnected();
    console.log(`  Direct call result: ${result} (${typeof result})`);
  } catch (e) {
    console.log(`  Direct call failed: ${e.message}`);
    // Try as int(void)
    try {
      const fnIsConnected2 = new NativeFunction(isConnectedAddr, 'int', []);
      const result2 = fnIsConnected2();
      console.log(`  Retry as int(void): ${result2}`);
    } catch (e2) {
      console.log(`  Retry also failed: ${e2.message}`);
    }
  }
}

// ============================================================
// 2. fctservctl_status — likely int(void) or similar
// ============================================================
console.log('\n--- 2. fctservctl_status ---');
const fctStatusAddr = resolve('fctservctl_status');
if (fctStatusAddr) {
  try {
    const fn = new NativeFunction(fctStatusAddr, 'int', []);
    const result = fn();
    console.log(`  Direct call int(void): ${result}`);
  } catch (e) {
    console.log(`  Direct call failed: ${e.message}`);
  }
}

// ============================================================
// 3. epctl_status — _Z12epctl_statusv  (void suffix = no args)
// ============================================================
console.log('\n--- 3. epctl_status ---');
const epctlStatusAddr = resolve('_Z12epctl_statusv');
if (epctlStatusAddr) {
  try {
    const fn = new NativeFunction(epctlStatusAddr, 'int', []);
    const result = fn();
    console.log(`  Direct call int(void): ${result}`);
  } catch (e) {
    console.log(`  Direct call failed: ${e.message}`);
  }
}

// ============================================================
// 4. Intercept VPNCmdGetStatus to observe args & return
// ============================================================
console.log('\n--- 4. VPNCmdGetStatus (intercepting) ---');
const vpnGetStatusAddr = resolve('VPNCmdGetStatus');
if (vpnGetStatusAddr) {
  Interceptor.attach(vpnGetStatusAddr, {
    onEnter(args) {
      console.log(`  [VPNCmdGetStatus] called`);
      console.log(`    arg0: ${args[0]}`);
      console.log(`    arg1: ${args[1]}`);
      console.log(`    arg2: ${args[2]}`);
      this.arg0 = args[0];
      this.arg1 = args[1];
    },
    onLeave(retval) {
      console.log(`    retval: ${retval} (int: ${retval.toInt32()})`);
    }
  });
  console.log(`  Hook installed, waiting for natural calls...`);
}

// ============================================================
// 5. Intercept VPNCmdConnect to observe args
// ============================================================
console.log('\n--- 5. VPNCmdConnect (intercepting) ---');
const vpnConnectAddr = resolve('VPNCmdConnect');
if (vpnConnectAddr) {
  Interceptor.attach(vpnConnectAddr, {
    onEnter(args) {
      console.log(`  [VPNCmdConnect] called`);
      console.log(`    arg0: ${args[0]}, arg1: ${args[1]}, arg2: ${args[2]}`);
      try { console.log(`    arg0 as CString: ${tryReadCString(args[0])}`); } catch(e) {}
      try { console.log(`    arg1 as CString: ${tryReadCString(args[1])}`); } catch(e) {}
    },
    onLeave(retval) {
      console.log(`    retval: ${retval.toInt32()}`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 6. Intercept VPNCmdDisconnect to observe args
// ============================================================
console.log('\n--- 6. VPNCmdDisconnect (intercepting) ---');
const vpnDisconnectAddr = resolve('VPNCmdDisconnect');
if (vpnDisconnectAddr) {
  Interceptor.attach(vpnDisconnectAddr, {
    onEnter(args) {
      console.log(`  [VPNCmdDisconnect] called`);
      console.log(`    arg0: ${args[0]}, arg1: ${args[1]}, arg2: ${args[2]}`);
    },
    onLeave(retval) {
      console.log(`    retval: ${retval.toInt32()}`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 7. Intercept setConnectionState — called when state changes
// ============================================================
console.log('\n--- 7. setConnectionState (intercepting) ---');
const setConnStateAddr = resolve('setConnectionState');
if (setConnStateAddr) {
  Interceptor.attach(setConnStateAddr, {
    onEnter(args) {
      console.log(`  [setConnectionState] called`);
      console.log(`    arg0: ${args[0]}`);
      console.log(`    arg1: ${args[1]}`);
      try { console.log(`    arg0 as CString: ${tryReadCString(args[0])}`); } catch(e) {}
      try { console.log(`    arg1 as CString: ${tryReadCString(args[1])}`); } catch(e) {}
      try { console.log(`    arg1 as int: ${args[1].toInt32()}`); } catch(e) {}
    },
    onLeave(retval) {
      console.log(`    retval: ${retval}`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 8. Intercept getConnectionStateString
// ============================================================
console.log('\n--- 8. getConnectionStateString (intercepting) ---');
const getConnStateStrAddr = resolve('getConnectionStateString');
if (getConnStateStrAddr) {
  Interceptor.attach(getConnStateStrAddr, {
    onEnter(args) {
      console.log(`  [getConnectionStateString] called`);
      console.log(`    arg0: ${args[0]}, arg1: ${args[1]}`);
      try { console.log(`    arg0 as CString: ${tryReadCString(args[0])}`); } catch(e) {}
    },
    onLeave(retval) {
      console.log(`    retval ptr: ${retval}`);
      try { console.log(`    retval as CString: ${tryReadCString(retval)}`); } catch(e) {}
      try { console.log(`    retval as std::string: ${tryReadStdString(retval)}`); } catch(e) {}
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 9. Intercept request_vpn_status
// ============================================================
console.log('\n--- 9. request_vpn_status (intercepting) ---');
const reqVpnStatusAddr = resolve('request_vpn_status');
if (reqVpnStatusAddr) {
  Interceptor.attach(reqVpnStatusAddr, {
    onEnter(args) {
      console.log(`  [request_vpn_status] called`);
      console.log(`    arg0: ${args[0]}, arg1: ${args[1]}`);
    },
    onLeave(retval) {
      console.log(`    retval: ${retval} (int: ${retval.toInt32()})`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 10. Intercept disconnectTunnel
// ============================================================
console.log('\n--- 10. disconnectTunnel (intercepting) ---');
const disconnectTunnelAddr = resolve('disconnectTunnel');
if (disconnectTunnelAddr) {
  Interceptor.attach(disconnectTunnelAddr, {
    onEnter(args) {
      console.log(`  [disconnectTunnel] called`);
      console.log(`    arg0: ${args[0]}`);
      try { console.log(`    arg0 as std::string: ${tryReadStdString(args[0])}`); } catch(e) {}
    },
    onLeave(retval) {
      console.log(`    retval: ${retval}`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 11. Intercept fctservctl_reconnect to learn its signature
// ============================================================
console.log('\n--- 11. fctservctl_reconnect (intercepting) ---');
const reconnectAddr = resolve('fctservctl_reconnect');
if (reconnectAddr) {
  Interceptor.attach(reconnectAddr, {
    onEnter(args) {
      console.log(`  [fctservctl_reconnect] called`);
      console.log(`    arg0: ${args[0]}, arg1: ${args[1]}, arg2: ${args[2]}`);
    },
    onLeave(retval) {
      console.log(`    retval: ${retval} (int: ${retval.toInt32()})`);
    }
  });
  console.log(`  Hook installed.`);
}

// ============================================================
// 12. Intercept connectTunnel
// ============================================================
console.log('\n--- 12. connectTunnel (intercepting) ---');
const connectTunnelAddr = resolve('connectTunnel');
if (connectTunnelAddr) {
  Interceptor.attach(connectTunnelAddr, {
    onEnter(args) {
      console.log(`  [connectTunnel] called`);
      console.log(`    arg0: ${args[0]}`);
      try { console.log(`    arg0 as std::string: ${tryReadStdString(args[0])}`); } catch(e) {}
    },
    onLeave(retval) {
      console.log(`    retval: ${retval} (int: ${retval.toInt32()})`);
    }
  });
  console.log(`  Hook installed.`);
}

console.log('\n=== Probe setup complete ===');
console.log('Direct call results are shown above.');
console.log('Interceptor hooks are active — interact with FortiClient UI');
console.log('(connect/disconnect VPN) to trigger the hooked functions.');
console.log('Press Ctrl+C to stop.\n');
