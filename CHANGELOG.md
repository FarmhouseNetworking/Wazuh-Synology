# Changelog

## 1.2.0 - 2026-10-12

- **New System decoder.** DSM System events (`System <user>:<TAB><message>`) were previously dropped. They now decode, with 33 new rules (127520-127554) for account, privilege, logging, remote-access, network, time, package, shared folder, storage, power and hardware events. Every System event is kept at level 3 at minimum.
- **Fixed:** failed sign-ins with a blank username were not decoded.
- **Fixed:** `Host [ip] failed to connect via [SMB] due to [SMB1 not permitted]` lines were not decoded.
- **Fixed:** SMB share-access lines (`from [HOSTNAME(ip)]`) would have put the hostname into `srcip`. `srcip` now gets the address and `src_hostname` the name.
- **Changed:** SMB1/NTLMv1 refusals now raise their own rule (127506) and no longer count toward the brute-force rule.
- **New:** rule 127508 for Log Center's "Send test log", and 127507 for SMB share access.
- **New:** `--watch-users` / `SynologyWatchUsers` raises a level 10 alert (127509) on every sign-in by named accounts, for break-glass accounts.
- The logtest self-test now covers 16 lines, including System events. `tests/sample-logs.txt` holds 53 lines, each labelled with where its format came from.
- The rule range is now 127500-127554; 127555-127564 are reserved for backup job rules.

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
