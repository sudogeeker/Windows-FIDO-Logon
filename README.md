# Windows FIDO Logon

Windows FIDO Logon is a local-only Windows 10/11 x64 Credential Provider for local SAM accounts. An enforced account must complete both its normal Windows password and an assertion from any registered USB FIDO2 security key. The Windows password is never stored and is sent only to Windows LSA after the local FIDO assertion succeeds.

There is no server, HTTP client, OTP, Push, telemetry, update checker, remote realm, domain-account flow, or offline server cache in the runtime. The only IPC endpoint is the versioned local named pipe `\\.\pipe\WindowsFidoLogon.Broker.v1`.

## Components

- `FidoCore`: USB HID/CTAP2 device access, ES256 registration/assertion validation, local-account resolution, Broker client, and DPAPI vault.
- `WindowsFidoLogonBroker`: LocalSystem service that owns challenges, SID authorization, signature counters, policy, and atomic vault writes.
- `WindowsFidoLogonCredentialProvider`: Local Logon/Unlock password flow with fail-closed FIDO MFA for enforced SIDs.
- `WindowsFidoLogonFilter`: Shows only the Windows FIDO Logon tile for local Logon/Unlock while at least one SID is enforced, and hides the Windows FIDO Logon tile when enforcement is disabled.
- `WindowsFidoLogonManager`: Post-login UI for adding, testing, listing, and removing keys, and for elevated policy changes.

Read [architecture](doc/architecture.md), [security boundary](doc/security-model.md), and the [test plan](doc/test-plan.md) before deploying it.

## Build

Requirements:

- Visual Studio 2022 with Desktop development with C++ and Windows 10/11 SDK
- v143 toolset and x64 target
- WiX Toolset 3.14.1 (the patched final WiX v3 maintenance release)
- vcpkg at commit `d015e31e90838a4c9dfa3eed45979bc70d9357fc` (CI bootstraps this exact revision)

For a verified local package, run:

```powershell
.\build.ps1 -Configuration Release -WixRoot C:\path\to\wix314
```

The script restores the pinned vcpkg graph, builds all projects with the static CRT and Control Flow Guard, runs verifier and source-contract tests, checks PE imports/ASLR/DEP/CFG, builds the MSI, audits its tables, and writes the MSI plus SHA-256 file to `dist`. A source-hash-pinned overlay builds libfido2 1.17.0 with Windows Hello, PC/SC, and NFC disabled; all runtime dependencies use `x64-windows-static`, so the Credential Provider, Broker, and Manager do not ship writable-directory dependency DLLs.

GitHub Actions runs the same path for pushes and pull requests. A tag such as `v1.0.0` must match `versioning/version.h`, `vcpkg.json`, and `WiXSetup/Config.wxi`. Tagged releases publish the tested MSI and checksum without requiring a signing certificate; the workflow also creates a GitHub artifact provenance attestation. See [release process](doc/release.md).

Current CI releases are not Authenticode-signed and Windows may show an unknown-publisher warning. Do not install them or enable enforced MFA on a real account until you have verified the checksum/provenance and the binaries pass the hardware and recovery tests in `doc/test-plan.md`. Enabling requires at least one registered USB key; the Manager shows an explicit lockout warning when only one key is present. There is deliberately no password-only fallback, recovery code, or emergency administrator path.

## Scope

Supported: local console Logon, workstation Unlock, and Safe Mode when the installed Broker SafeBoot entry is honored.

Not supported: RDP, CredUI, domain/Entra/MSA accounts, Windows Hello, synchronized/phone passkeys, NFC, or passkey-only login.

Credential Provider filtering controls LogonUI tiles; it is not a custom LSA Authentication Package and is not a complete system authentication boundary.

## License

Apache License 2.0. This is a new product identity and is not a privacyIDEA product. See [NOTICE.md](NOTICE.md) for retained upstream attribution.
