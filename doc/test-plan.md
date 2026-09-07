# Test and release gate

Do not enable enforcement in production until all applicable items pass on the exact Release x64 binaries being deployed. Current CI releases are unsigned, so verify both the published SHA-256 checksum and GitHub provenance before testing.

## Automated

- Build and run `FidoVerifierTests` for normal registration/assertion, strict encoding, flag, signature, origin/RP, credential, and counter-tamper cases.
- Build and run `BrokerProtocolTests` for empty, malformed, wrong-version, oversized, and unauthenticated-pipe requests.
- Build and run `CredentialUiTests` for V2 COM identity/SID binding, native user-array lifecycle and account options, failed/empty enumeration, stale credential rejection, cross-user secret/mode isolation, SID mismatch rejection before Broker I/O, localized prompts, 72×72 embedded logo ownership, Windows error classification, submit-arrow notifications, and secret clearing after cancellation/deselection/reset. These tests require a local Windows account but perform no sign-in or policy writes.
- Run `powershell -ExecutionPolicy Bypass -File tests\security-contract.ps1`.
- Inspect every shipped binary with `dumpbin /imports`; fail if WinHTTP, WinINet, HTTPAPI, URLMon, or a telemetry/update library appears.
- Run the Broker IPC harness as standard user, another user, administrator, and LocalSystem. Cover SID spoofing, other-SID writes, replay, timeout, oversized/malformed messages, concurrent writes, DPAPI failure, and backup recovery.

## Policy and hardware

- Cover zero, one, two, and three credentials; same-device duplicate creation; enable with zero (rejected) and one (warning plus confirmation); wrong and correct Windows passwords for both enable and disable; deletion at the one-key floor; account rename; account deletion; and Broker failure.
- On Windows 10 and Windows 11 x64, test Logon, Unlock, Safe Mode, local-account selection, first-submit transition to PIN, wrong-password retry, password expiry/change, wrong and locked PIN, cancel, key unplug/replug, and touch selection among multiple devices.
- In both English and Chinese, confirm the small-text area starts with M18 for a named user or M02 for "Other user", then each Connect status replaces its prior content without becoming a persistent subtitle. Confirm LogonUI never displays a device-name selector. With multiple keys attached, touch each key in turn and verify only the touched key is subsequently asked for PIN or an assertion; cancelling or timing out must cancel every pending touch request. Wrong-password status must show only the localized password-verification failure in the error area; lockout/disabled-account failures must not be described as a wrong password. Enter a wrong Windows password with a valid key PIN, retry with the correct password, and confirm PIN entry is empty and required again. Also verify no PIN remains after wrong PIN, touch timeout, cancellation, or switching users.
- With two different vendor/model USB FIDO2 keys, complete: register both, enable MFA, log in with either, add a third using the remaining key, remove a lost key, restart, and unlock.

## Installer

- Cover clean install, same-product upgrade, uninstall, service/provider/filter component failure, and coexistence with the old privacyIDEA product.
- Confirm enforcement is off after install; the Windows built-in GenericFilter does not block enablement; an unknown third-party global Filter requires explicit confirmation; installation, repair, upgrade, and uninstall are rejected while MFA is enabled in both interactive and silent setup. After password-authorized disablement, upgrade replaces the existing product and uninstall removes Filter registration before its DLL and stops/removes the Broker.
- Upgrade 1.0.0 and 1.0.1 to 1.0.2 with MFA disabled, and install a rebuilt MSI of the same version. Confirm exactly one Windows FIDO Logon entry remains, registered keys survive upgrade, and older versions cannot replace 1.0.2. MSI audits also check the compiled upgrade range and evaluate the MFA gate for install, repair, upgrade, and uninstall.
- Run ManagerUiTests for worker/UI dispatch, delayed operations, repeated button notifications, close during work, layout separation, and Broker I/O timeout/cancellation. On actual USB hardware, exercise enrollment/test and key removal with Windows-password validation only; enrollment/test still cover cancel, invalid PIN, unplug and touch timeout while moving/resizing the Manager. Policy changes must refresh status without opening a second Manager process.
- Confirm `credentials.dat`, backup, and product registry state are removed on uninstall according to the documented recovery procedure.

- Enroll a first factory-new key, then a second factory-new key with the first unplugged (MFA both enabled and disabled). Only the current Windows password authorizes enrollment; complete the new key's PIN/UV and creation touch without any assertion prompt. Test each key afterward. Confirm wrong passwords, cross-account requests, duplicate credentials, expired/replayed sessions, and exceeding the credential limit are rejected.

## Native LogonUI acceptance matrix

Run on isolated Windows 10 and Windows 11 x64 machines, in both English and Simplified Chinese, at 100%, 150% and 200% scaling. Do not treat callback tests as evidence of secure-desktop rendering.

- One and multiple local users: native chooser shows system display names and portraits, with no embedded user dropdown or duplicate product heading. Switch users during password, PIN and password-change stages; returning starts with empty secrets, password focus and no retained authorization.
- Logon, unlock, Fast User Switching and Safe Mode: honor the user array supplied for the scenario; never select the first SAM account as a fallback. Hidden/disabled users must not be reintroduced through a separate enumeration.
- Enable/disable the Windows policy that hides the last username. Where Windows supplies `CPAO_EMPTY_LOCAL`, show "Other user" with username focus, accept local account syntax, and reject domain/UPN syntax. Verify changing the typed username clears password/PIN. No anonymous tile should be invented when Windows does not request one.
- Custom portrait, no custom portrait, forced default account-picture policy, and missing default-picture resource: compare against the Windows native account tile on that OS. Confirm the provider does not substitute its logo or a hard-coded BMP for the portrait. Restore test policy/resources after each case.
- Sign-in options: verify the 72×72 provider logo and localized label; verify changing authentication stages keeps the arrow beside the active input. With filtering enabled, alternate providers must remain filtered.
- Correct/incorrect Windows passwords, wrong/locked PIN, touch cancellation/timeout, unplug/replug, password expiration/change, and Broker failure: preserve the existing enforcement and retry behavior. Confirm cancellation or switching users cannot serialize an earlier user's credentials.

### Implementation verification record — 2026-09-07

- Passed: `build.ps1 -Configuration Release -SkipDependencies -SkipMsi` completed the Release x64 build, `FidoVerifierTests`, `BrokerProtocolTests`, `ManagerUiTests`, `CredentialUiTests`, security contracts, and runtime import/hardening checks using the existing pinned static dependencies. MSI packaging was not requested or run.
- Not executed in this workspace: the Windows 10/11 secure-desktop acceptance matrix, avatar-policy visual comparisons, physical USB-key login/unlock/expiry scenarios, and Safe Mode. These remain manual acceptance items; no provider was installed and no login policy was changed.
