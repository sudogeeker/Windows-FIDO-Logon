# Architecture

## Login path

1. LogonUI supplies its user array to the V2 Credential Provider and owns the native user chooser, display names and account pictures. The provider offers one SID-bound credential for each supplied local identity. When Windows requests `CPAO_EMPTY_LOCAL`, an anonymous "Other user" credential accepts a local username and password. The provider does not force a default user or enumerate a separate account list.
2. Each credential owns separate password, PIN, mode and authentication state. The provider resolves the account through local SAM APIs and obtains its SID; a named tile must match its bound SID. UPN and non-local domain syntax are rejected. Deselecting/disconnecting, changing an anonymous username, or replacing the user array clears secrets and authorization. Credentials retained from an old enumeration cannot authenticate or serialize.
3. The provider asks the LocalSystem Broker for a one-use authentication challenge over the local Named Pipe.
4. If the SID is not enforced, the provider immediately serializes the password for Windows LSA. The Credential Provider Filter hides this provider while enforcement is disabled so the system's native password provider remains the only local sign-in option.
5. If enforced, the provider enumerates only CTAP2 ES256 USB HID devices, allows device selection, requests PIN/user verification and touch, and returns the assertion to the Broker. The first password submission transitions directly to this step without a second confirmation click.
6. The Broker validates the session owner, 120-second expiry, challenge, HTTPS origin, RP ID hash, UP, UV, credential/SID ownership, ES256 signature, and signature counter.
7. Only after success does the provider serialize the original password to LSA. A Windows password error invalidates the FIDO state and requires a new ceremony.

## Native LogonUI presentation

`ICredentialProviderSetUserArray` and `ICredentialProviderCredential2` associate this sign-in method with Windows user tiles. `IConnectableCredentialProviderCredential` remains available for the FIDO ceremony. A missing/empty user array does not trigger independent SAM enumeration or invent an anonymous tile. Connected identity providers are excluded. Account options and enumeration errors never publish a partial list.

Windows renders custom/default user avatars and applies the default-picture policy. The provider does not read or replace `user.bmp`, `user.jpg`, account-picture registry entries, or per-profile image caches. Its embedded `tileimage.bmp` supplies a 72×72 **sign-in method icon**, marked `CPFG_CREDENTIAL_PROVIDER_LOGO`, with a separate localized `CPFG_CREDENTIAL_PROVIDER_LABEL`. It does not replace the user's portrait. Windows controls the exact appearance on each OS version.

The duplicate product heading is hidden. Named tiles focus the password field; "Other user" focuses the username field. Status text is replaced as authentication progresses, and the submit arrow follows the password, key PIN or confirmation-password field. Provider filtering and Broker enforcement are unchanged; V2 integration does not re-enable alternate password/Hello methods when filtering is active. The legacy `no_default` setting no longer changes selection: this provider always lets LogonUI choose the user.

## Local state

The Broker creates one stable RP ID per installation: `wfl-<128-bit machine id>.login.local`, with origin `https://<rp-id>`. It does not derive this value from the computer name.

The vault is `%ProgramData%\Windows FIDO Logon\credentials.dat`. Its JSON payload is protected using machine-scope DPAPI. The Broker writes a protected temporary file, flushes it, keeps the last valid backup, and performs a write-through replace. File ACLs permit only SYSTEM and Administrators.

Each credential stores the owning SID, credential ID, exact COSE public key, algorithm `-7`, AAGUID, label, creation time, and signature counter. Passwords, PINs, private keys, and challenges are not stored.

## Management ceremonies

Adding any key requires only the current local account's Windows password for authorization. The new key creates a discoverable credential with PIN/UV and touch, and the Broker verifies the registration response and saves it directly. No existing-key assertion or additional new-key assertion is requested. With `none` attestation, the Broker validates the registration fields but does not independently verify possession of the private key during enrollment.

Removal requires the current Windows password; it does not require a security key or PIN. Enabling or disabling MFA also requires the current Windows password, and the Broker binds the change to the elevated caller's local SID. Enforced accounts must retain at least one credential. The Manager runs elevated and sends policy changes directly to the Broker; it does not launch another elevated copy. When only one key is registered, it presents a single-key warning. The Windows GenericFilter is recognized by its CLSID and registered System32/credprovs.dll path, without loading the DLL or validating Authenticode signatures. Other global Credential Provider Filters require explicit administrator confirmation. Both Manager and Broker use the same recognition helper. This identifies an administrator-controlled registration; it does not establish publisher trust.

The per-machine installer disables partial maintenance, applies explicit SYSTEM-owned write access to runtime files, policy state, the vault, and the Broker service, and configures Broker restart-on-failure. A normal full uninstall is rejected while MFA is enabled; MFA must first be disabled with the current Windows password. Major upgrades are excluded from this uninstall guard so that the protected state survives a supported upgrade.

The Manager runs broker calls, Filter inspection, USB enumeration and FIDO ceremonies on a single background operation. Dialogs and controls are dispatched to the UI thread. Commands are disabled until completion, and only BN_CLICKED notifications from the expected button start operations. Closing during an active call defers window destruction until the call completes. Broker reads/writes time out after 15 seconds; USB opens/capability queries use a 5-second timeout, while touch ceremonies retain their 120-second timeout.
