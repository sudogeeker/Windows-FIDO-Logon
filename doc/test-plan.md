# Test and release gate

Do not enable enforcement in production until all applicable items pass on the exact Release x64 binaries being deployed. Current CI releases are unsigned, so verify both the published SHA-256 checksum and GitHub provenance before testing.

## Automated

- Build and run `FidoVerifierTests` for normal registration/assertion, strict encoding, flag, signature, origin/RP, credential, and counter-tamper cases.
- Build and run `BrokerProtocolTests` for empty, malformed, wrong-version, oversized, and unauthenticated-pipe requests.
- Run `powershell -ExecutionPolicy Bypass -File tests\security-contract.ps1`.
- Inspect every shipped binary with `dumpbin /imports`; fail if WinHTTP, WinINet, HTTPAPI, URLMon, or a telemetry/update library appears.
- Run the Broker IPC harness as standard user, another user, administrator, and LocalSystem. Cover SID spoofing, other-SID writes, replay, timeout, oversized/malformed messages, concurrent writes, DPAPI failure, and backup recovery.

## Policy and hardware

- Cover zero, one, two, and three credentials; same-device duplicate creation; enable at fewer than two; deletion at the two-key floor; account rename; account deletion; and Broker failure.
- On Windows 10 and Windows 11 x64, test Logon, Unlock, Safe Mode, wrong-password retry, password expiry/change, wrong and locked PIN, cancel, key unplug/replug, and selection among multiple devices.
- With two different vendor/model USB FIDO2 keys, complete: register both, enable MFA, log in with either, add a third using the remaining key, remove a lost key, restart, and unlock.

## Installer

- Cover clean install, same-product upgrade, uninstall, service/provider/filter component failure, and coexistence with the old privacyIDEA product.
- Confirm enforcement is off after install; another registered global Filter blocks enablement; uninstall removes Filter registration before its DLL and stops/removes the Broker.
- Confirm `credentials.dat`, backup, and product registry state are removed on uninstall according to the documented recovery procedure.
