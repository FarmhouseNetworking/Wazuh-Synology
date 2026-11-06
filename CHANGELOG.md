# Changelog

## 1.3.1 - 2026-11-05

- **Fixed:** Active Backup for Business's CBT fallback message ("Failed to retrieve the changed blocks (CBT) for virtual machine X. A full backup will be performed.") raised rule 127559 at level 10 although the backup then went on to succeed (127558, 127557). It is now rule 127565 at level 4, group `backup`.
- 127565 is a child of 127559, not a sibling: Wazuh tries a parent's children from the highest level down, so a lower-level sibling of 127559 can never match first. It matches only when the fallback sentence is the whole message. 127559 itself is unchanged, so cancelled, failed and partially completed tasks, and lines that mention CBT and then report a real failure, still alert at level 10.
- README: documents that a missed Hyper Backup is detected by the absence of rule 127562 in 26 hours (127557 for Active Backup), not by the failure alerts. This also covers both USB drives being missing on the same day. New tests `tests/both-drives-fail.txt` and `tests/stale-check.py` prove it.
- Tests: 164 checks (was 131). `tests/sample-logs.txt` holds 84 lines (was 78); the logtest self-test covers 24 (was 23). Checks for the level of each backup alert, for renumbering of the new rule, and a guard test showing why 127565 cannot be a lower-level sibling.
- The SuperOps edition is regenerated from the command-line script (`tools/build-superops.py`, no change to the builder).
- The rule range is now 127500-127565 (`--rule-base` uses `N` to `N+65`).

## 1.3.0 - 2026-10-14

- **Backup job logging.** New decoders for Active Backup for Business (`ActiveBackup[pid]:`) and Hyper Backup (`Hyper_Backup:`) lines, which carry a Wazuh program name and so were not picked up by the System decoder. Rules 127555-127564 cover task start, completion, per-VM success, cancellation and failure. All are in the `backup` group, with `backup_success` / `backup_failure` where they apply.
- Hyper Backup "destination does not exist" failures are level 5 (127563) rather than 10, so a routinely rotated-out USB drive does not raise a high alert every night. Every other Hyper Backup failure is level 10 (127564).
- README documents Active Backup for Business's own Log Forwarding setting, which must use the same protocol as the listener.
- The logtest self-test now covers 23 lines; `tests/sample-logs.txt` holds 78.
- The rule range is now 127500-127564.

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
