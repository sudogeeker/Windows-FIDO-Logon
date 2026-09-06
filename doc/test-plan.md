# Test and release gate

Do not enable enforcement in production until all applicable items pass on the exact Release x64 binaries being deployed. Current CI releases are unsigned, so verify both the published SHA-256 checksum and GitHub provenance before testing.

## Automated

- Build and run `FidoVerifierTests` for normal registration/assertion, strict encoding, flag, signature, origin/RP, credential, and counter-tamper cases.
- Build and run `BrokerProtocolTests` for empty, malformed, wrong-version, oversized, and unauthenticated-pipe requests.
- Build and run `CredentialUiTests` for blank tile text, Windows error classification, and PIN clearing in both provider state and LogonUI event notifications after errors, success, cancellation, and reset.
- Run `powershell -ExecutionPolicy Bypass -File tests\security-contract.ps1`.
- Inspect every shipped binary with `dumpbin /imports`; fail if WinHTTP, WinINet, HTTPAPI, URLMon, or a telemetry/update library appears.
- Run the Broker IPC harness as standard user, another user, administrator, and LocalSystem. Cover SID spoofing, other-SID writes, replay, timeout, oversized/malformed messages, concurrent writes, DPAPI failure, and backup recovery.

## Policy and hardware

- Cover zero, one, two, and three credentials; same-device duplicate creation; enable with zero (rejected) and one (warning plus confirmation); wrong and correct Windows passwords for both enable and disable; deletion at the one-key floor; account rename; account deletion; and Broker failure.
- On Windows 10 and Windows 11 x64, test Logon, Unlock, Safe Mode, local-account selection, first-submit transition to PIN, wrong-password retry, password expiry/change, wrong and locked PIN, cancel, key unplug/replug, and touch selection among multiple devices.
- In both English and Chinese, confirm the small-text area starts with M02, then each Connect status replaces its prior content without becoming a persistent subtitle. Confirm LogonUI never displays a device-name selector. With multiple keys attached, touch each key in turn and verify only the touched key is subsequently asked for PIN or an assertion; cancelling or timing out must cancel every pending touch request. Wrong-password status must show only the localized password-verification failure in the error area; lockout/disabled-account failures must not be described as a wrong password. Enter a wrong Windows password with a valid key PIN, retry with the correct password, and confirm PIN entry is empty and required again. Also verify no PIN remains after wrong PIN, touch timeout, cancellation, or switching users.
- With two different vendor/model USB FIDO2 keys, complete: register both, enable MFA, log in with either, add a third using the remaining key, remove a lost key, restart, and unlock.

## Installer

- Cover clean install, same-product upgrade, uninstall, service/provider/filter component failure, and coexistence with the old privacyIDEA product.
- Confirm enforcement is off after install; the Windows built-in GenericFilter does not block enablement; an unknown third-party global Filter requires explicit confirmation; installation, repair, upgrade, and uninstall are rejected while MFA is enabled in both interactive and silent setup. After password-authorized disablement, upgrade replaces the existing product and uninstall removes Filter registration before its DLL and stops/removes the Broker.
- Upgrade 1.0.0 and 1.0.1 to 1.0.2 with MFA disabled, and install a rebuilt MSI of the same version. Confirm exactly one Windows FIDO Logon entry remains, registered keys survive upgrade, and older versions cannot replace 1.0.2. MSI audits also check the compiled upgrade range and evaluate the MFA gate for install, repair, upgrade, and uninstall.
- Run ManagerUiTests for worker/UI dispatch, delayed operations, repeated button notifications, close during work, layout separation, and Broker I/O timeout/cancellation. On actual USB hardware, exercise enrollment/test and key removal with Windows-password validation only; enrollment/test still cover cancel, invalid PIN, unplug and touch timeout while moving/resizing the Manager. Policy changes must refresh status without opening a second Manager process.
- Confirm `credentials.dat`, backup, and product registry state are removed on uninstall according to the documented recovery procedure.
