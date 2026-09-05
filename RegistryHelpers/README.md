# Manual registration reference

The MSI is the supported registration path. It installs these x64 COM classes:

- Credential Provider: `{A95D1C6B-8D9C-4E0F-A60D-CA6B569E28AD}`
- Credential Provider Filter: `{54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1}`

It also registers the `WindowsFidoLogonBroker` LocalSystem auto-start service and adds that service to both SafeBoot `Minimal` and `Network` service lists. Enforcement remains disabled until an elevated manager request succeeds with at least one registered key; the Manager warns before enabling with only one key.

Do not use the obsolete privacyIDEA registration GUIDs or DLL names. Manual registration is intentionally not automated here because a partial provider/filter/service registration can lock users out.
