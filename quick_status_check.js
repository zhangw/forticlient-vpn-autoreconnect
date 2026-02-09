// quick_status_check.js
// Quick one-shot check of all status functions while VPN is connected.
// Usage: frida -n "FortiClient" -l quick_status_check.js

const moduleName = 'guimessenger_jyp.node';

function resolve(name) {
  return Module.findExportByName(moduleName, name);
}

console.log('=== Quick Status Check (VPN should be connected) ===\n');

// 1. servctl::api::is_connected
const isConnAddr = resolve('_ZN7servctl3api12is_connectedEv');
if (isConnAddr) {
  const fn = new NativeFunction(isConnAddr, 'int', []);
  console.log(`servctl::api::is_connected() = ${fn()}`);
}

// 2. fctservctl_status
const fctStatusAddr = resolve('fctservctl_status');
if (fctStatusAddr) {
  const fn = new NativeFunction(fctStatusAddr, 'int', []);
  console.log(`fctservctl_status() = ${fn()}`);
}

// 3. epctl_status
const epctlAddr = resolve('_Z12epctl_statusv');
if (epctlAddr) {
  const fn = new NativeFunction(epctlAddr, 'int', []);
  console.log(`epctl_status() = ${fn()}`);
}

// 4. Try getConnectionStateString as pointer(void)
const getStateAddr = resolve('getConnectionStateString');
if (getStateAddr) {
  // It might take a tunnel name as arg. Try with no args first.
  try {
    const fn = new NativeFunction(getStateAddr, 'pointer', []);
    const ret = fn();
    console.log(`getConnectionStateString() ptr = ${ret}`);
    if (!ret.isNull()) {
      try { console.log(`  as CString: ${ret.readCString()}`); } catch(e) {}
    }
  } catch(e) {
    console.log(`getConnectionStateString() no-arg failed: ${e.message}`);
  }

  // Try with a std::string arg (tunnel name "webull")
  try {
    const fn2 = new NativeFunction(getStateAddr, 'pointer', ['pointer']);
    const tunnelName = "webull";
    const utf8buf = Memory.allocUtf8String(tunnelName);
    const strLen = tunnelName.length;
    const strControlBase = 0x8000000000000000n;
    const full64 = strControlBase + (BigInt(strLen) + 1n);
    const strMem = Memory.alloc(32);
    Memory.writePointer(strMem, utf8buf);
    Memory.writeU64(strMem.add(8), strLen);
    Memory.writeU64(strMem.add(16), uint64(full64.toString()));
    const ret2 = fn2(strMem);
    console.log(`getConnectionStateString(&"webull") ptr = ${ret2}`);
    if (!ret2.isNull()) {
      try { console.log(`  as CString: ${ret2.readCString()}`); } catch(e) {}
    }
  } catch(e) {
    console.log(`getConnectionStateString(&"webull") failed: ${e.message}`);
  }
}

// 5. Try request_vpn_status
const reqStatusAddr = resolve('request_vpn_status');
if (reqStatusAddr) {
  try {
    const fn = new NativeFunction(reqStatusAddr, 'int', []);
    console.log(`request_vpn_status() = ${fn()}`);
  } catch(e) {
    console.log(`request_vpn_status() no-arg failed: ${e.message}`);
  }
}

// 6. getConnectionIPAddr
const getIPAddr = resolve('getConnectionIPAddr');
if (getIPAddr) {
  try {
    const fn = new NativeFunction(getIPAddr, 'pointer', []);
    const ret = fn();
    console.log(`getConnectionIPAddr() ptr = ${ret}`);
    if (!ret.isNull()) {
      try { console.log(`  as CString: ${ret.readCString()}`); } catch(e) {}
    }
  } catch(e) {
    console.log(`getConnectionIPAddr() failed: ${e.message}`);
  }
}

// 7. getTunnelInfoString
const getTunnelInfoAddr = resolve('getTunnelInfoString');
if (getTunnelInfoAddr) {
  try {
    const fn = new NativeFunction(getTunnelInfoAddr, 'pointer', []);
    const ret = fn();
    console.log(`getTunnelInfoString() ptr = ${ret}`);
    if (!ret.isNull()) {
      try { console.log(`  as CString: ${ret.readCString()}`); } catch(e) {}
    }
  } catch(e) {
    console.log(`getTunnelInfoString() failed: ${e.message}`);
  }
}

// 8. getVPNConnectionListString
const getListAddr = resolve('getVPNConnectionListString');
if (getListAddr) {
  try {
    const fn = new NativeFunction(getListAddr, 'pointer', []);
    const ret = fn();
    console.log(`getVPNConnectionListString() ptr = ${ret}`);
    if (!ret.isNull()) {
      try { console.log(`  as CString: ${ret.readCString()}`); } catch(e) {}
    }
  } catch(e) {
    console.log(`getVPNConnectionListString() failed: ${e.message}`);
  }
}

console.log('\n=== Done ===');
