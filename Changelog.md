# Changelog

## 1.0.2

- Block installation, upgrade, repair, and uninstall while MFA is enabled, including silent setup.
- Keep the MSI UpgradeCode and component identities stable; replace older releases and equal-version rebuilds instead of installing duplicate products.
- Keep the LogonUI small-text area blank, shorten English and Chinese prompts, and report password rejection only for a Windows wrong-password result.
- Clear the security-key PIN from provider memory and the LogonUI input after use, retry, cancellation, and device changes.
- Include Windows error codes in Broker password-validation failures and distinguish local-account resolution errors.
- Add credential UI regression coverage and verify that Manager password prompts preserve Unicode and whitespace across the UI/worker boundary.

## 1.0.1

- Require the current Windows password for both MFA enablement and disablement, reject normal uninstall while MFA is active, harden installed component ACLs, and restart the Broker after service failure.
- Batch Manager control repositioning and invalidate all child controls to prevent lower-button paint artifacts while resizing vertically.
- Run Manager broker and USB operations in the background, reject duplicate button notifications, and bound Broker I/O waits.
- Apply MFA policy in the elevated Manager without launching a second process; refresh status on completion.
- Remove runtime WinTrust validation and recognize the Windows GenericFilter by its CLSID and system COM server path.
- Remove the header logo, separate the key list from button rows, and size input dialogs for DPI and text length.
- Add Win32 responsiveness, cancellation, layout, Filter recognition, and pipe timeout regression tests.

## 1.0.0

- Replaced the server-backed authentication client with a local FIDO core and Named Pipe Broker.
- Removed HTTP, OTP, Push, polling, server challenge, realm/UPN, domain-account, and server offline-cache code.
- Added per-machine RP identity, machine-DPAPI credential vault, replay-resistant 120-second ceremonies, ES256 verification, UP/UV checks, and signature-counter enforcement.
- Added multiple-key management, proof-of-possession enrollment, an at-least-one-key enforcement floor, and password plus existing-key authorization for changes.
- Added new Credential Provider and Filter GUIDs, independent MSI UpgradeCode, and `HKLM\SOFTWARE\WindowsFidoLogon` configuration.
- Pinned static libfido2 1.17.0 dependencies through vcpkg.
- Added a hash-pinned local-only libfido2 overlay with Windows Hello, PC/SC, and NFC disabled, plus static-link/import auditing.
- Added strict UTF-8/Base64URL validation, bounded Broker sessions and credential counts, LocalSystem pipe-server verification, and fail-closed registry/vault policy reconciliation.
- Added reproducible GitHub Actions MSI packaging, unsigned tag releases without certificate secrets, SHA-256 sidecars, and build-provenance attestations.
