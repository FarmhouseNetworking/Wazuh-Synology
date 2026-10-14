# Wazuh-Synology

Send **Synology DSM** sign-in, file activity, system change, storage, hardware and **backup job** logs (Active Backup for Business and Hyper Backup) into a **self-hosted Wazuh manager** with one script. The script adds a syslog listener that only accepts the NAS, installs decoders and rules written against real DSM 7 log lines, and proves them with `wazuh-logtest` before it restarts anything.

Wazuh does not ship Synology decoders, so without this the NAS's syslog arrives and is silently dropped as "no decoder matched".

```
 Synology NAS  --syslog TCP 514 (BSD / RFC 3164)-->  wazuh-remoted  -->  9999_synology_decoders.xml
 (Log Center)                                        on the manager      9999_synology_rules.xml  -->  alerts
```

| File | Purpose |
|---|---|
| `synology-wazuh-install.sh` | Installer, status check and uninstaller for the command line. Self-contained: it can be copied to the manager on its own. |
| `superops/synology-wazuh-install-superops.sh` | The same installer, set up for SuperOps RMM runtime variables |
| `decoders/9999_synology_decoders.xml` | Reference copy of the decoders (the installer writes them for you) |
| `rules/9999_synology_rules.xml` | Reference copy of the rules, with the default IDs |
| `tests/sample-logs.txt` | Real DSM log lines (names and addresses replaced) and the rule each one must hit |
| `tests/run-tests.sh` | Test suite that runs both editions of the installer against a fake Wazuh tree |
| `tools/build-superops.py` | Generates the SuperOps edition from the command-line script, so the two cannot drift apart |
| `docs/TROUBLESHOOTING.md` | Every problem hit while building this, with cause and fix |

---

## What the installer does

1. Checks the server first: running as root, Wazuh manager present, rule IDs free, no other syslog listener on the same port and protocol, no other Synology ruleset already installed. **If any check fails it stops before changing anything.**
2. Backs up `ossec.conf` (and any earlier copy of its own files) to `/root/synology-wazuh-backup-<timestamp>/` and confirms the backup matches.
3. Records the current output of `wazuh-analysisd -t`, so warnings your server already had are not blamed on this install.
4. Adds a `<remote>` syslog listener to `ossec.conf` that accepts **only the NAS address(es) you give it**. The block is wrapped in marker comments so later runs and uninstall can find it.
5. Writes `/var/ossec/etc/decoders/9999_synology_decoders.xml` and `/var/ossec/etc/rules/9999_synology_rules.xml`.
6. Runs `wazuh-remoted -t` and `wazuh-analysisd -t`. A failure, or any **new** warning, triggers an automatic rollback.
7. Feeds six real DSM log lines through `wazuh-logtest` and checks each one lands on the expected rule. A miss triggers a rollback.
8. Opens the host firewall (ufw or firewalld) for the NAS address only.
9. Restarts `wazuh-manager` and confirms the listener is up.
10. Prints the settings to enter on the NAS.

You can run it again safely. A second run replaces the listener block and both files in place.

---

## Requirements

- Wazuh manager **4.x**. Tested on **4.14.8**. It must be the manager, not an agent.
- Synology **DSM 7.x** with Log Center.
- The NAS must be able to reach the manager on the listener port. If they are on different VLANs, allow that on your router or firewall.
- `python3` on the manager. The installer uses the copy bundled with Wazuh when it is there.

---

## Step 1a: Run it from the command line

On the Wazuh manager:

```bash
git clone https://github.com/FarmhouseNetworking/Wazuh-Synology.git
cd Wazuh-Synology
sudo ./synology-wazuh-install.sh --nas-ip 192.0.2.10
```

Replace `192.0.2.10` with your NAS's address. For more than one NAS, separate the addresses with commas.

| Option | Default | Meaning |
|---|---|---|
| `--nas-ip LIST` | (required) | NAS address or addresses, IPv4 or IPv4/CIDR, comma-separated |
| `--port N` | `514` | Port the manager listens on |
| `--protocol P` | `tcp` | `tcp` or `udp`. Must match the NAS's **Transfer protocol** |
| `--rule-base N` | `127500` | First rule ID. The ruleset uses `N` to `N+64` |
| `--watch-users LIST` | | Accounts whose every successful sign-in raises a level 10 alert, comma-separated. Use it for break-glass or emergency accounts |
| `--no-listener` | | Do not add a `<remote>` block. Use when the NAS is already allowed in an existing syslog listener |
| `--no-firewall` | | Leave ufw / firewalld alone |
| `--no-restart` | | Install and test, but do not restart `wazuh-manager` |
| `--force` | | Install even if other Synology rules or decoders already exist |

Every option also has an environment variable (`NAS_IP`, `SYSLOG_PORT`, `SYSLOG_PROTO`, `RULE_BASE`, `WATCH_USERS`, `ADD_LISTENER`, `OPEN_FIREWALL`, `RESTART`, `FORCE`), which is useful when running from an RMM.

The default rule range starts at 127500 so that it does not collide with [Duo-Wazuh-LogSync](https://github.com/FarmhouseNetworking/Duo-Wazuh-LogSync), which uses 120000–120039.

---

## Step 1b: Run it from SuperOps RMM

1. In SuperOps, go to **Scripts → New Script**, choose language **Bash** and platform **Linux**, and paste in `superops/synology-wazuh-install-superops.sh`.
2. Create these **runtime variables**. The names must match exactly:

| Variable | Required | Example |
|---|---|---|
| `SynologyNasIp` | yes, for install | `192.0.2.10` (comma-separated for more than one NAS) |
| `SynologyAction` | no | `install` (default), `status` or `uninstall` |
| `SynologyPort` | no | `514` |
| `SynologyProtocol` | no | `tcp` (default) or `udp` |
| `SynologyRuleBase` | no | `127500` |
| `SynologyAddListener` | no | `yes` (default) or `no` when the NAS is already allowed in an existing syslog listener |
| `SynologyOpenFirewall` | no | `yes` (default) or `no` |
| `SynologyRestart` | no | `yes` (default) or `no` to install and test without restarting the manager |
| `SynologyForce` | no | `no` (default) or `yes` |
| `SynologyWatchUsers` | no | `backup-admin` (accounts whose every sign-in alerts, comma-separated) |

3. Run the script **as root** against the Wazuh manager asset.
4. The script exits `0` on success and `1` on any failure or warning, so SuperOps marks a broken install as failed. All output appears in the run log, including the NAS settings for Step 2.

Tip: after the NAS is configured, run the script again with `SynologyAction` set to `status` to see the listener, the installed files and the latest Synology alerts in the run log. Scheduled weekly, that doubles as a health check for compliance reporting.

---

## Step 2: Configure the NAS

**Log Center → Log Sending → Location**

| Setting | Value |
|---|---|
| Send logs to a syslog server | Ticked |
| Server | The Wazuh manager's IP |
| Port | `514` |
| Transfer protocol | **TCP**. Check this one: if it is left on UDP nothing arrives. |
| Log format | **BSD (RFC 3164)** |
| Enable secure connection (TLS/SSL) | Unticked (see [Limitations](#limitations)) |

**Log Center → Log Sending → Log Filters**

- Tick the categories you want: at least **Connection**, **SMB** and **File Station log**.
- Set priorities to include **Info** and **Notice**. Successful sign-ins and file events are sent at Info priority. Without it, only failed sign-ins reach Wazuh.

**Active Backup for Business → Log → Settings → Log Forwarding** (only if you use Active Backup for Business)

Active Backup for Business does not go through Log Center. It has its own syslog client, set separately:

| Setting | Value |
|---|---|
| Send logs to a syslog server | Ticked |
| Server | The Wazuh manager's IP |
| Port | `514` |
| Transfer protocol | **TCP**, the same as Log Center. If it is left on UDP, a capture on the manager shows the lines arriving, but Wazuh never receives them, because nothing listens on UDP 514 |
| Log messages format | BSD (RFC 3164) |

Click **Send Test Log**, then OK.

Hyper Backup needs no extra setting: its job results go through Log Center's **Hyper Backup** category.

**Control Panel → File Services → SMB**

- Tick **Enable Transfer Log**, then use **Log Settings** to choose which file events are recorded.

Click **Apply** on each page, then **Send test log** on the Location tab. The test log raises rule 127508, so it also proves decoding works.

---

## Step 3: Verify

On the manager, watch for the NAS's traffic. The filter matches either protocol, so a TCP/UDP mismatch cannot hide:

```bash
sudo tcpdump -i any -nn -A 'port 514 and host 192.0.2.10' -c 10
```

Sign in to DSM once with a wrong password and once correctly, and upload then delete a file in File Station. Then:

```bash
sudo ./synology-wazuh-install.sh status
```

From SuperOps, run the script with `SynologyAction` set to `status` instead.

`status` shows the listener block, the installed files, the listening socket and the last ten Synology alerts. You should see rules 127508 (test log), 127502, 127501, 127510 and 127511.

To check System events, create a disabled scheduled task in **Control Panel → Task Scheduler** and delete it again. That logs two System entries, which raise rule 127530. Not every DSM setting change writes a log entry, so a missing alert after some other change is not necessarily a fault: check DSM's own **Log Center → Logs** first.

In the Wazuh dashboard, filter on `rule.groups: synology`.

---

## Rules

The "Evidence" column says how far each rule has been proven:

- **Live:** fired on a production Wazuh manager from a real NAS.
- **Wire:** the exact line format was captured from a real NAS; rule proven with the test suite.
- **Export:** message text taken from a real DSM 7 Log Center export, in the captured wire format.
- **Sample:** a published third-party DSM 7.0 sample; not yet seen on a tested NAS.
- **Loads:** loads without warnings; no sample line yet.

**Connection and file activity**

| ID | Level | Fires on | Evidence |
|---|---|---|---|
| 127500 | 3 | Any connection event not matched below, including "passed the first authentication of 2FA" | Live |
| 127501 | 3 | Successful sign-in | Live |
| 127502 | 5 | Failed sign-in, including blank usernames and SSH | Live |
| 127503 | 10 | Brute force: 6 failed sign-ins from one address in 120 seconds | Loads |
| 127504 | 10 | DSM auto-block triggered | Loads |
| 127505 | 8 | Sign-in by a built-in `admin`, `administrator` or `root` account | Export |
| 127506 | 5 | SMB1 or NTLMv1 connection refused (not counted as a failed sign-in) | Export |
| 127507 | 3 | SMB share accessed | Sample |
| 127508 | 3 | Log Center "Send test log" received | Wire |
| 127509 | 10 | Sign-in by an account named in `--watch-users` (only written when set) | Export |
| 127510 | 3 | File event (upload, write, rename and so on) | Live |
| 127511 | 3 | File deleted | Live |
| 127512 | 12 | Mass deletion: 50 deletes by one user in 60 seconds | Loads |

**System: security-relevant changes**

| ID | Level | Fires on | Evidence |
|---|---|---|---|
| 127520 | 3 | Any System event not matched below | Wire |
| 127521 | 8 | User created | Export |
| 127522 | 8 | User deleted | Sample |
| 127523 | 5 | User disabled | Export |
| 127524 | 10 | User added to `administrators` | Export |
| 127525 | 5 | Password changed | Export |
| 127526 | 5 | App privilege changed | Export |
| 127527 | 10 | Audit logging reduced (SMB log level or a transfer log disabled) | Export |
| 127528 | 10 | QuickConnect started (DSM may be reachable from the internet) | Export |
| 127529 | 8 | SSH, Telnet, FTP, SFTP, TFTP, SNMP, rsync or WebDAV service started | Sample |
| 127530 | 5 | Scheduled task created, removed or renamed | Wire |
| 127531 | 5 | Package installed or uninstalled (updates stay at 127520) | Export |
| 127532 | 8 | Shared folder deleted or renamed | Sample |
| 127533 | 5 | Recycle bin emptied | Export |
| 127534 | 5 | Certificate added or assigned | Export |
| 127535 | 5 | IP, subnet mask, DNS or server name changed | Export |
| 127536 | 8 | Date, time or NTP setting changed | Sample |
| 127537 | 5 | SSL/TLS setting changed | Sample |
| 127538 | 10 | Auto block disabled | Loads (DSM's wording not yet seen) |

**System: storage, power and hardware**

| ID | Level | Fires on | Evidence |
|---|---|---|---|
| 127540 | 12 | Storage pool degraded | Export |
| 127541 | 8 | Drive deactivated | Export |
| 127542 | 12 | iSCSI LUN full and read-only | Export |
| 127543 | 7 | iSCSI LUN nearly full (soft limit) | Export |
| 127544 | 8 | Low storage space on a volume | Export |
| 127545 | 10 | Power supply stopped | Export |
| 127546 | 5 | Running on UPS battery | Export |
| 127547 | 8 | Booted after an improper shutdown | Export |
| 127548 | 8 | IP address conflict | Export |
| 127549 | 7 | Email notification failed (the NAS's own alerts are not being delivered) | Export |
| 127550 | 5 | External device removed without ejecting | Export |
| 127551 | 5 | External disk connected | Export |
| 127552 | 3 | Network link down | Export |
| 127553 | 8 | Links flapping: 10 link-down events in 10 minutes | Loads |
| 127554 | 5 | Reboot or shutdown started | Export |

Fields extracted:

- **Connection events:** `dstuser`, `srcip`, `src_hostname` (SMB), `service` (for example `DSM`, `SSH`, `SMB`), `syno_reason`, `syno_share`.
- **File events:** `syno_action`, `file_path`, `file_type`, `file_size`, `dstuser`, `srcip`.
- **System events:** `srcuser` (who made the change, or `SYSTEM`), `syno_event` (the full message), `syno_object` (the first bracketed name in it).

Level 3 is Wazuh's default alert threshold, so every sign-in, file event and System event is kept as an audit record. On a busy file server that is a lot of alerts: check your retention and disk space, and think before enabling `read` events in DSM's transfer log settings.

**Backup jobs**

| ID | Level | Fires on | Evidence |
|---|---|---|---|
| 127555 | 3 | Any Active Backup for Business line not matched below (per-VM progress, transfer sizes, test log) | Wire |
| 127556 | 3 | Active Backup task started | Wire |
| 127557 | 3 | Active Backup task completed | Wire |
| 127558 | 3 | A VM backed up successfully | Wire |
| 127559 | 10 | Active Backup task or VM cancelled, failed or partially completed | Wire (cancel); failure wording not yet seen |
| 127560 | 3 | Any Hyper Backup line not matched below (integrity checks, version rotation, task settings) | Export |
| 127561 | 3 | Hyper Backup task started or resumed | Wire |
| 127562 | 3 | Hyper Backup task finished successfully | Export |
| 127563 | 5 | Hyper Backup task did not run because its destination is missing (for example the USB drive for that task is not attached) | Export |
| 127564 | 10 | Hyper Backup task failed for any other reason, was cancelled or suspended, or was skipped | Wire and export |

127563 is kept at level 5 on purpose. With two Hyper Backup tasks rotating between two USB drives, the task whose drive is away fails every night with "destination does not exist". That is expected. The failure that matters is no task succeeding at all, and Wazuh rules cannot alert on something not happening: check for it in a scheduled report (no 127562 in the last 26 hours) instead.

Fields: Active Backup gives `syno_task`, `syno_event` and `syno_vm`; Hyper Backup gives `srcuser`, `syno_task` and `syno_event`. All backup rules are in the `backup` group, with `backup_success` and `backup_failure` added where they apply.

**Not covered:** Snapshot Replication. Its logs did not reach syslog in testing, and no Synology setting to send them has been found. See [Limitations](#limitations).

---

## Log formats this was written against

```
Connection: User [jdoe] from [203.0.113.25] failed to sign in to [DSM] via [password] due to authorization failure.
Connection: User [jdoe] from [203.0.113.25] has successfully passed the first authentication of 2FA via [password]
Connection: User [jdoe] from [203.0.113.25] signed in to [DSM] successfully via [password].
FileStation Event: upload, Path: /Shared/Quarterly report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
FileStation Event: rename, Path: /Shared/Quarterly report.docx -> /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
FileStation Event: delete, Path: /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
System Test message from Synology Syslog Client from (192.0.2.1)
System jdoe:<TAB>Scheduled Task [wazuh-test] was created.
```

These are real lines captured from a DSM 7 NAS, with the hostname, user and addresses replaced. Each starts after `<priority>Mon dd hh:mm:ss HOSTNAME `. System lines have a tab after the colon. The full set, including lines taken from Log Center exports and published samples, is in `tests/sample-logs.txt`.

---

## Limitations

- **Some formats come from published samples only.** SMB file events (`WinFileService Event: ...`) and SMB share access lines match published DSM 7.0 samples, but had not been captured from a tested NAS when this was published. The "Evidence" column in [Rules](#rules) shows which. If a line does not decode, see [Troubleshooting](docs/TROUBLESHOOTING.md#a-log-line-arrives-but-no-alert-appears) and please open an issue with a sample line.
- **Snapshot Replication logs are not sent.** Nothing arrived from Snapshot Replication during testing, and the only published report found (SynoForum, DSM 7.0) says its logs reach neither Log Center nor a remote syslog server. If snapshots are part of your backup evidence, you need another source for them.
- **Active Backup for Business sends some lines twice.** In testing, task and VM start and finish lines arrived twice and progress lines once. The rules fire on each copy, so counts of those alerts are doubled.
- **No TLS.** Wazuh's built-in syslog listener does not accept TLS, so the NAS's logs cross the network in plain text, including file paths and usernames. Keep the NAS and the manager on a trusted internal network. If you need encryption in transit, put an rsyslog TLS listener in front and have Wazuh read the file it writes.
- **IPv4 only** for the NAS address.
- **Timestamps.** BSD syslog carries no time zone. Wazuh stamps each alert with its own receive time, so alerts are correct, but the timestamp inside the raw log line is the NAS's local time.

---

## Compliance notes

For NIST SP 800-171 / CMMC Level 2, these logs support **3.3.1** (create and retain audit records) and **3.3.2** (trace actions to individual users) for the NAS. Rules 127503, 127504 and 127512 are the ones worth adding to a regular log review. Keep the NAS on the same time source as the manager for **3.3.7**.

---

## Uninstall

```bash
sudo ./synology-wazuh-install.sh uninstall
```

From SuperOps, run the script with `SynologyAction` set to `uninstall`.

This backs up `ossec.conf`, removes the listener block, both files and the firewall rule, validates the configuration and restarts the manager. Then turn off **Send logs to a syslog server** on the NAS.

---

## Testing without a Wazuh server

```bash
sudo tests/run-tests.sh
```

The suite builds a fake Wazuh tree in a temp directory and checks installation, re-runs, uninstall, rule renumbering, every refusal path, both rollback paths and the SuperOps edition. Its stand-in for `wazuh-logtest` imitates how Wazuh selects decoders and rules, which checks the regular expressions in the XML, but it is not Wazuh. The installer's own self-test, run on a real manager, is the check that counts.

---

## Lessons learned

Each of these cost time while building this. Details and fixes are in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

1. **A decoder without `<program_name>` is never tried against a log that has a program name.** `Connection:` lines are pre-decoded with program name `Connection`, so a prematch-only decoder silently never runs.
2. **DSM only forwards the priorities you select.** With Info and Notice unticked, failed sign-ins arrive and nothing else does.
3. **A Wazuh syslog listener takes one protocol.** A TCP listener will not see a NAS that is sending UDP.
4. **`action` and `dstuser` are static fields.** They cannot be matched with `<field name="...">`.
5. **Two listener blocks on the same port and protocol cannot both bind.**
6. **Rule IDs collide across integrations.** Check before you write.
7. **Wazuh tries a parent's children highest level first, not in file order.** Two children at the same level are tried in file order. A rule meant to pre-empt another must be at a higher level, or at the same level and earlier in the file.
8. **Not every DSM setting change writes a log entry.** Check DSM's local Log Center before assuming forwarding is broken.
9. **Active Backup for Business has its own syslog setting.** It does not use Log Center, and it has its own TCP/UDP choice that must match the listener.

---

## License

MIT. See [LICENSE](LICENSE).

Built by [Farmhouse Networking](https://www.farmhousenetworking.com).
