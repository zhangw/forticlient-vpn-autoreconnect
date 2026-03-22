# Code Review Findings

Date: `2026-03-22`

Scope: repository-level QA/code review focused on behavioral risk, reconnect correctness, and maintainability of the current FortiClient automation flow.

## Findings

### 1. High: reconnect failure can be reported as success in `vpn_monitor.sh`

File: [`vpn_monitor.sh`](/Users/vincent/Desktop/forti_tool/vpn_monitor.sh#L123)

Problem:

- The reconnect path runs `timeout ... frida ... | while read ...`.
- In Bash, that `if` condition uses the pipeline exit status.
- Without `set -o pipefail`, the pipeline status comes from the last command, which is the `while` loop.
- That means a failed `frida` attach or timeout can still be treated as success if the loop exits cleanly.

Impact:

- Production reconnect failures can be logged as `Frida reconnect command completed.`
- QA and troubleshooting become misleading because the logs do not reflect the real reconnect outcome.
- This can hide version drift, attach failures, missing permissions, and broken symbol resolution.

Recommended fix:

- Preserve and check the actual exit status from `timeout` / `frida`.
- Practical options:
  - Enable `set -o pipefail` for the script.
  - Avoid the pipeline for status handling and log command output through a temporary file or process substitution.
  - Capture `${PIPESTATUS[0]}` immediately after the pipeline and branch on that command’s result.

Validation after fix:

- Force a reconnect failure with a bad process name or invalid symbol path.
- Confirm the monitor logs failure instead of success.

### 2. Medium: `utun`-based VPN detection is too broad

Files:

- [`vpn_monitor.sh`](/Users/vincent/Desktop/forti_tool/vpn_monitor.sh#L54)
- [`forti_auto_reconnect.js`](/Users/vincent/Desktop/forti_tool/forti_auto_reconnect.js#L262)

Problem:

- Both modes currently treat any `utun` interface with an IPv4 address as evidence that FortiClient is connected.
- On macOS, other tools can also create `utun` interfaces, including Tailscale, WireGuard, and other VPN software.

Impact:

- The monitor can incorrectly report `VPN is up.` while FortiClient is actually disconnected.
- Auto-reconnect can be suppressed when it should run.
- The SAML browser close flow can be triggered on the wrong connectivity transition.

Recommended fix:

- Prefer ping-based detection using a stable VPN-internal host whenever possible.
- If `utun` fallback must remain, make it more FortiClient-specific or document it as best-effort detection only.
- Consider making ping-based detection the documented default for multi-VPN hosts.

Validation after fix:

- Run FortiClient alongside another `utun`-creating tool.
- Confirm the tool does not report FortiClient as connected unless the Forti tunnel is actually usable.

### 3. Medium: resident mode has hardcoded user-specific config in source

File: [`forti_auto_reconnect.js`](/Users/vincent/Desktop/forti_tool/forti_auto_reconnect.js#L18)

Problem:

- `CONFIG.userName` and `CONFIG.connName` are hardcoded in the checked-in script.
- The recommended polling mode reads values from `vpn_monitor.conf`, but the resident mode does not.

Impact:

- The two runtime modes can silently drift apart.
- Developers and testers may update the config file and assume both modes use it.
- User-specific identifiers are easier to leak into source control.

Recommended fix:

- Standardize configuration between modes.
- Either generate the resident-mode Frida script with injected config, or load a shared config source before launch.
- At minimum, clearly separate example values from active values and avoid checked-in personal data.

Validation after fix:

- Change the VPN profile in one place and confirm both modes use the same connection details.

## Open Questions

### 1. Is this tool expected to run on hosts with multiple VPN products?

Why this matters:

- If yes, the current `utun` logic is a real correctness bug and should be treated as higher priority.
- If no, it remains a portability risk but may be acceptable as a temporary fallback.

Decision needed:

- Define whether multi-`utun` coexistence is in scope for supported environments.

### 2. Is resident mode expected to be maintained as a real supported mode?

Why this matters:

- The README already treats external polling as the recommended path.
- If resident mode is still supported, its config handling should be brought up to the same standard as the shell monitor.
- If not, it should be documented more explicitly as experimental and lower-priority.

Decision needed:

- Mark resident mode as either:
  - supported and maintained, or
  - experimental / diagnostic only.

## Suggested Priority Order

1. Fix reconnect success/failure reporting in `vpn_monitor.sh`.
2. Decide whether multi-`utun` hosts are supported, then tighten detection accordingly.
3. Unify config handling across polling and resident modes.

## Related QA Docs

- Manual integration testing: [`docs/manual-testing.md`](/Users/vincent/Desktop/forti_tool/docs/manual-testing.md)
- Project overview and compatibility notes: [`README.md`](/Users/vincent/Desktop/forti_tool/README.md)
