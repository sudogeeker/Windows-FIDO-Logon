# Architecture

## Login path

1. LogonUI lets the user choose a local account from an embedded list and enter its Windows password in the custom Credential Provider.
2. The provider resolves the account through local SAM APIs and obtains its SID. UPN and non-local domain syntax are rejected.
3. The provider asks the LocalSystem Broker for a one-use authentication challenge over the local Named Pipe.
4. If the SID is not enforced, the provider immediately serializes the password for Windows LSA. The Credential Provider Filter hides this provider while enforcement is disabled so the system's native password provider remains the only local sign-in option.
5. If enforced, the provider enumerates only CTAP2 ES256 USB HID devices, allows device selection, requests PIN/user verification and touch, and returns the assertion to the Broker. The first password submission transitions directly to this step without a second confirmation click.
6. The Broker validates the session owner, 120-second expiry, challenge, HTTPS origin, RP ID hash, UP, UV, credential/SID ownership, ES256 signature, and signature counter.
7. Only after success does the provider serialize the original password to LSA. A Windows password error invalidates the FIDO state and requires a new ceremony.

## Local state

The Broker creates one stable RP ID per installation: `wfl-<128-bit machine id>.login.local`, with origin `https://<rp-id>`. It does not derive this value from the computer name.

The vault is `%ProgramData%\Windows FIDO Logon\credentials.dat`. Its JSON payload is protected using machine-scope DPAPI. The Broker writes a protected temporary file, flushes it, keeps the last valid backup, and performs a write-through replace. File ACLs permit only SYSTEM and Administrators.

Each credential stores the owning SID, credential ID, exact COSE public key, algorithm `-7`, AAGUID, label, creation time, and signature counter. Passwords, PINs, private keys, and challenges are not stored.

## Management ceremonies

The first key requires the current Windows password. Once a key exists, adding a key requires the password plus an assertion from an existing key. Every registration is followed by an assertion from the newly created credential before the Broker commits it, which makes `none` attestation safe without an online metadata service.

Removal requires the current Windows password; it does not require a security key or PIN. Enforced accounts must retain at least one credential. The Manager runs elevated and sends policy changes directly to the Broker; it does not launch another elevated copy. When only one key is registered, it presents a single-key warning. The Windows GenericFilter is recognized by its CLSID and registered System32/credprovs.dll path, without loading the DLL or validating Authenticode signatures. Other global Credential Provider Filters require explicit administrator confirmation. Both Manager and Broker use the same recognition helper. This identifies an administrator-controlled registration; it does not establish publisher trust.

The Manager runs broker calls, Filter inspection, USB enumeration and FIDO ceremonies on a single background operation. Dialogs and controls are dispatched to the UI thread. Commands are disabled until completion, and only BN_CLICKED notifications from the expected button start operations. Closing during an active call defers window destruction until the call completes. Broker reads/writes time out after 15 seconds; USB opens/capability queries use a 5-second timeout, while touch ceremonies retain their 120-second timeout.
