// recon_exports.js
// Usage: frida -n "FortiClient" -l recon_exports.js
// Enumerates all exports from guimessenger_jyp.node to discover
// status/disconnect/callback symbols for hooking.

const moduleName = 'guimessenger_jyp.node';

const exports = Module.enumerateExports(moduleName);
console.log(`\n=== ${moduleName} exports (${exports.length} total) ===\n`);

const interestingPatterns = /disconnect|status|state|connect|tunnel|callback|notify|event|update|check|monitor/i;

const interesting = [];
const others = [];

exports.forEach(exp => {
  if (interestingPatterns.test(exp.name)) {
    interesting.push(exp);
  } else {
    others.push(exp);
  }
});

console.log(`--- Interesting exports (${interesting.length}) ---`);
interesting.forEach(exp => {
  console.log(`  [${exp.type}] ${exp.name} @ ${exp.address}`);
});

console.log(`\n--- All other exports (${others.length}) ---`);
others.forEach(exp => {
  console.log(`  [${exp.type}] ${exp.name} @ ${exp.address}`);
});

console.log('\n=== Done ===');
