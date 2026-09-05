# Security model and limitations

## Enforced properties

- Broker sessions are random, caller-S SID-bound, valid for at most 120 seconds, and consumed before validation to prevent replay.
- The Named Pipe ACL allows authenticated users to connect, while every operation is authorized using Named Pipe impersonation. Cross-SID management requires an elevated administrator where explicitly supported.
- Registration accepts only discoverable CTAP2 ES256 credentials with UP and UV. Both `none` and `packed` attestation objects are parsed locally; `packed` signatures are verified, and every format must pass immediate new-key proof of possession.
- Assertions bind challenge, origin, RP ID, credential ID, and account SID. A non-zero signature counter that does not increase is rejected.
- An enforced SID fails closed if the Broker, vault, USB device, PIN/UV, touch, or signature verification is unavailable.
- The runtime has no TCP/HTTP listener or outbound-network feature.

## Boundary

The Filter hides other LogonUI providers for local Logon and Unlock. A Credential Provider is not an LSA authentication package, so this does not cover RDP, network logon, CredUI, service logon, scheduled tasks, or another direct LSA path. A local administrator or an attacker with offline disk-write capability can disable or replace Credential Providers and is outside this boundary.

There is no emergency administrator, recovery code, or password-only fallback. Losing both keys for an enforced account requires offline WinRE repair or reinstall. Operational recovery procedures and signed rescue media must be prepared before rollout.
