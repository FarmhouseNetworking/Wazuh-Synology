# Changelog

## 1.1.0 - 2026-10-01

- Added `superops/synology-wazuh-install-superops.sh`, a SuperOps RMM edition driven by runtime variables. It writes timestamped output to the run log and exits 1 on any failure or warning.
- Added `tools/build-superops.py`, which generates the SuperOps edition from the command-line script. The test suite fails if the two are out of step.
- Test suite extended to cover the SuperOps edition (50 checks).

## 1.0.0 - 2026-10-01

Initial release.

- Installer with pre-checks, backup, validation, `wazuh-logtest` self-test and automatic rollback.
- `status` and `uninstall` actions.
- Decoders for DSM 7 `Connection:` and `... Event:` (file activity) syslog lines.
- Rules 127500-127512: sign-in success and failure, brute force, auto-block, built-in admin sign-in, file events, deletions and mass deletion.
- Test suite that runs against a fake Wazuh tree.
- Tested on Wazuh 4.14.8 with a DSM 7 NAS sending BSD (RFC 3164) syslog over TCP.
