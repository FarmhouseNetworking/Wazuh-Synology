# Changelog

## 1.0.0 - 2026-10-01

Initial release.

- Installer with pre-checks, backup, validation, `wazuh-logtest` self-test and automatic rollback.
- `status` and `uninstall` actions.
- Decoders for DSM 7 `Connection:` and `... Event:` (file activity) syslog lines.
- Rules 127500-127512: sign-in success and failure, brute force, auto-block, built-in admin sign-in, file events, deletions and mass deletion.
- Test suite that runs against a fake Wazuh tree.
- Tested on Wazuh 4.14.8 with a DSM 7 NAS sending BSD (RFC 3164) syslog over TCP.
