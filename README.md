# Wazuh-Synology

Send **Synology DSM** sign-in, auto-block and file activity logs into a **self-hosted Wazuh manager** with one script. The script adds a syslog listener that only accepts the NAS, installs decoders and rules written against real DSM 7 log lines, and proves them with `wazuh-logtest` before it restarts anything.

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
| `--rule-base N` | `127500` | First rule ID. The ruleset uses 13 IDs, `N` to `N+12` |
| `--no-listener` | | Do not add a `<remote>` block. Use when the NAS is already allowed in an existing syslog listener |
| `--no-firewall` | | Leave ufw / firewalld alone |
| `--no-restart` | | Install and test, but do not restart `wazuh-manager` |
| `--force` | | Install even if other Synology rules or decoders already exist |

Every option also has an environment variable (`NAS_IP`, `SYSLOG_PORT`, `SYSLOG_PROTO`, `RULE_BASE`, `ADD_LISTENER`, `OPEN_FIREWALL`, `RESTART`, `FORCE`), which is useful when running from an RMM.

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

**Control Panel → File Services → SMB**

- Tick **Enable Transfer Log**, then use **Log Settings** to choose which file events are recorded.

Click **Apply** on each page, then **Send test log** on the Location tab.

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

`status` shows the listener block, the installed files, the listening socket and the last ten Synology alerts. You should see rules 127502, 127501, 127510 and 127511.

In the Wazuh dashboard, filter on `rule.groups: synology`.

---

## Rules

| ID | Level | Fires on | Seen firing on a live manager |
|---|---|---|---|
| 127500 | 3 | Any connection event not matched below, including "passed the first authentication of 2FA" | Yes |
| 127501 | 3 | Successful sign-in | Yes |
| 127502 | 5 | Failed sign-in | Yes |
| 127503 | 10 | Brute force: 6 failed sign-ins from one address in 120 seconds | No |
| 127504 | 10 | DSM auto-block triggered | No |
| 127505 | 8 | Sign-in by a built-in `admin`, `administrator` or `root` account | No |
| 127510 | 3 | File event (upload, rename and so on) | Yes |
| 127511 | 3 | File deleted | Yes |
| 127512 | 12 | Mass deletion: 50 deletes by one user in 60 seconds | No |

The four rules marked "No" load without warnings and use the same decoders, but had not been triggered by real events when this was published.

Fields extracted:

- **Connection events:** `dstuser`, `srcip`, `service` (for example `DSM`).
- **File events:** `syno_action`, `file_path`, `file_type`, `file_size`, `dstuser`, `srcip`.

Level 3 is Wazuh's default alert threshold, so every sign-in and file event is kept as an audit record. On a busy file server that is a lot of alerts: check your retention and disk space, and think before enabling `read` events in DSM's transfer log settings.

---

## Log formats this was written against

```
Connection: User [jdoe] from [203.0.113.25] failed to sign in to [DSM] via [password] due to authorization failure.
Connection: User [jdoe] from [203.0.113.25] has successfully passed the first authentication of 2FA via [password]
Connection: User [jdoe] from [203.0.113.25] signed in to [DSM] successfully via [password].
FileStation Event: upload, Path: /Shared/Quarterly report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
FileStation Event: rename, Path: /Shared/Quarterly report.docx -> /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
FileStation Event: delete, Path: /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
```

These are real lines captured from a DSM 7 NAS, with the hostname, user and addresses replaced.

---

## Limitations

- **SMB file events are not yet confirmed.** The file decoder matches on the `Event: <action>, Path: ..., File/Folder: ...` layout rather than the service name, so SMB transfer logs should decode the same way as File Station ones, but only File Station events had been captured when this was published. If yours do not decode, see [Troubleshooting](docs/TROUBLESHOOTING.md#a-log-line-arrives-but-no-alert-appears) and please open an issue with a sample line.
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

---

## License

MIT. See [LICENSE](LICENSE).

Built by [Farmhouse Networking](https://www.farmhousenetworking.com).
