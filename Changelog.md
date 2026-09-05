# Changelog

## 1.0.0

- Replaced the server-backed authentication client with a local FIDO core and Named Pipe Broker.
- Removed HTTP, OTP, Push, polling, server challenge, realm/UPN, domain-account, and server offline-cache code.
- Added per-machine RP identity, machine-DPAPI credential vault, replay-resistant 120-second ceremonies, ES256 verification, UP/UV checks, and signature-counter enforcement.
- Added multiple-key management, proof-of-possession enrollment, two-key enforcement floor, and password plus existing-key authorization for changes.
- Added new Credential Provider and Filter GUIDs, independent MSI UpgradeCode, and `HKLM\SOFTWARE\WindowsFidoLogon` configuration.
- Pinned static libfido2 1.17.0 dependencies through vcpkg.
- Added a hash-pinned local-only libfido2 overlay with Windows Hello, PC/SC, and NFC disabled, plus static-link/import auditing.
- Added strict UTF-8/Base64URL validation, bounded Broker sessions and credential counts, LocalSystem pipe-server verification, and fail-closed registry/vault policy reconciliation.
- Added reproducible GitHub Actions MSI packaging, unsigned tag releases without certificate secrets, SHA-256 sidecars, and build-provenance attestations.
