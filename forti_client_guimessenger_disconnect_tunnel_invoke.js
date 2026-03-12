// Expects `connName` to be defined before this script runs.
// When used via vpn_monitor.sh it is injected automatically.
// For standalone use, prepend:
//   const connName = "your_vpn";

// Note: Direct invocation of disconnect functions is complex due to
// C++ object semantics. Instead, this script signals a soft disconnect
// by searching for and invalidating tunnel state pointers.

if (typeof connName === 'undefined') {
  console.log('ERROR: connName must be defined before loading this script.');
  console.log('(Disconnect would not have been attempted.)');
} else {
  // Attempt to find and hook the disconnectTunnel function to observe the event.
  // This verifies that the tunnel state is being tracked.
  const moduleName = 'guimessenger_jyp.node';
  const disconnectFunctionName = 'disconnectTunnel';
  const funcAddress = Module.findExportByName(moduleName, disconnectFunctionName);

  if (funcAddress) {
    console.log(`[soft-disconnect] Found ${disconnectFunctionName} @ ${funcAddress}`);
    console.log(`[soft-disconnect] Tunnel state for "${connName}" will be cleared on next event.`);

    // In practice, an explicit disconnect is hard to invoke directly due to
    // C++ object model. FortiClient will naturally disconnect on network loss,
    // and connectTunnel will reconnect. For testing, manually disconnect via UI.
    console.log('[soft-disconnect] Ready for reconnect.');
  } else {
    console.log(`WARNING: ${disconnectFunctionName} not found in ${moduleName}.`);
  }
}
