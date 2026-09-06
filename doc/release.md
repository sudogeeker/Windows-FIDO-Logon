# Build and release

## Local build

Install Visual Studio 2022 with the v143 x64 C++ toolset and a Windows 10/11 SDK. Obtain the official WiX 3.14.1 binary archive and verify its SHA-256 is `6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31`, then run:

```powershell
.\build.ps1 -Configuration Release -WixRoot C:\tools\wix314
```

`build.ps1` is the canonical build entry point used by CI. It restores `x64-windows-static` dependencies from the locked vcpkg baseline and hash-pinned libfido2 1.17.0 overlay, builds the runtime and test projects, runs tests, checks binary imports and mitigations, compiles/audits the MSI, and creates `dist\WindowsFidoLogon-<version>-x64.msi` with a SHA-256 sidecar. CI bootstraps vcpkg itself from the same pinned commit instead of relying on the moving hosted-runner checkout.

## Installer identity and upgrades

The MSI product family uses the permanent UpgradeCode `842EA4D9-6E63-4D18-9217-A4DBD1ED8728`. Do not change it or existing component GUIDs for routine releases. ProductCode and PackageCode are generated for each build; `AllowSameVersionUpgrades="yes"` makes equal-version rebuilds replace the existing product as well. Keep `VERSION_REVISION` at zero and increment the three-part version for releases because MSI ignores a fourth version field.

Starting with 1.0.2, disable MFA in Manager before installation, upgrade, repair, or uninstall. Both the launch condition and execute-sequence guard reject active MFA; upgrade is no longer exempt. Upgrades use the existing product family and preserve the credential data component. See the [WiX major-upgrade documentation](https://docs.firegiant.com/wix3/xsd/wix/majorupgrade/) for equal-version detection semantics.

## GitHub Actions

`.github/workflows/build-release.yml` runs on every push, pull request, manual dispatch, and `v*` tag. Action dependencies are pinned to immutable commits. The workflow downloads the official WiX archive and validates its hash before use.

The tag must exactly equal the three-part source version, for example `v1.0.0`. A tag build runs the same tests and audits as other builds, creates a GitHub artifact provenance attestation, and publishes the MSI and checksum with GitHub CLI. No signing secrets or Authenticode certificate are required.

All current CI artifacts, including tag releases, are unsigned. Windows can therefore display an unknown-publisher warning. Treat them as test artifacts until you have independently verified the published SHA-256 checksum and GitHub provenance, completed the hardware/recovery test plan, and accepted the unsigned-code deployment risk. The provenance attestation identifies the GitHub workflow build; it is not an Authenticode signature and does not make Windows trust the binaries.
