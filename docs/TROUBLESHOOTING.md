# Troubleshooting

Work down this page in order. Each section says how to tell whether it applies, why it happens, and how to fix it.

- [Nothing arrives from the NAS](#nothing-arrives-from-the-nas)
- [Only failed sign-ins arrive](#only-failed-sign-ins-arrive)
- [Active Backup lines show in a capture but never alert](#active-backup-lines-show-in-a-capture-but-never-alert)
- [A DSM change produced no alert](#a-dsm-change-produced-no-alert)
- [A log line arrives but no alert appears](#a-log-line-arrives-but-no-alert-appears)
- [The installer stops: rule ID already used](#the-installer-stops-rule-id-already-used)
- [The installer stops: listener conflict](#the-installer-stops-listener-conflict)
- [Writing your own rules: "Field 'action' is static"](#writing-your-own-rules-field-action-is-static)
- [The installer rolled back](#the-installer-rolled-back)

---

## Nothing arrives from the NAS

**Check.** On the manager, capture without naming a protocol, then click **Send test log** in DSM:

```bash
sudo tcpdump -i any -nn -A 'port 514 and host <NAS_IP>' -c 10
```

**If packets arrive on UDP but the listener is TCP** (or the other way round): the protocols do not match. A Wazuh syslog `<remote>` block accepts exactly one protocol, so a TCP listener ignores UDP traffic. In DSM, set **Log Center → Log Sending → Location → Transfer protocol** to match, or reinstall with `--protocol udp`.

A capture filtered with `tcp port 514` will show nothing at all for a NAS that is sending UDP, which looks like a network problem and is not. Always capture with `port 514`.

**If no packets arrive at all:**

- Confirm the manager is listening: `sudo ss -lntup | grep ':514 '`. If not, the manager has not been restarted since the install.
- Check the host firewall: `sudo ufw status numbered` or `sudo firewall-cmd --list-all`.
- If the NAS and manager are on different subnets, allow the port between them on your router or firewall. Compare the NAS's subnet mask with the manager's address before assuming they are separate.
- Check `/var/ossec/logs/ossec.log` for `Remote syslog allowed from:` lines. The NAS's address must be listed.

---

## Only failed sign-ins arrive

**Cause.** DSM forwards only the log priorities selected under **Log Center → Log Sending → Log Filters**. Failed sign-ins are sent at Warning priority. Successful sign-ins and file events are sent at Info. If Info and Notice are not selected, they never leave the NAS.

**Fix.** Select all priorities from Info to Emergency, tick the categories you want, and click Apply.

**How to tell DSM is not sending, rather than Wazuh not decoding.** Run the capture above while signing in successfully. If no packet appears, the NAS did not send it and no change on the manager will help.

---

## Active Backup lines show in a capture but never alert

**Cause.** Active Backup for Business has its own syslog client, set in **Active Backup for Business → Log → Settings → Log Forwarding**, with its own transfer protocol. If that is UDP and the Wazuh listener is TCP, `tcpdump` on the manager still shows every line, because it sees packets before any program does. Wazuh never receives them, because nothing listens on UDP 514.

**Check.** `sudo ss -lnu | grep ':514 '` prints nothing when there is no UDP listener.

**Fix.** Set Active Backup's transfer protocol to TCP, click **Send Test Log**, and look for rule 127555.

---

## A DSM change produced no alert

**Check DSM first.** Open **Log Center → Logs**, choose the **System** log (it may be labelled General) and look for the change. Not every setting change writes a log entry: for example, toggling Log Center's own archive settings writes nothing.

**Prove the path with a change that always logs.** Start a capture on the manager, then create a disabled scheduled task in **Control Panel → Task Scheduler** and delete it:

```bash
sudo timeout 300 tcpdump -i any -nn -A -l 'port 514 and host <NAS_IP>' 2>/dev/null | grep -a --line-buffered '<NAS hostname>'
```

You should see two lines like `System jdoe:<TAB>Scheduled Task [wazuh-test] was created.` and rule 127530 should fire. Use `grep -a`: System lines contain a tab, and the capture can contain bytes that make plain `grep` treat it as binary.

- **Entry in DSM, line on the wire, no alert:** a decoding problem. See the next section.
- **Entry in DSM, nothing on the wire:** check **Log Filters** has the **System** category and Info priority selected.
- **No entry in DSM:** that action is not logged by DSM. Nothing on the Wazuh side can fix that.

---

## A log line arrives but no alert appears

**Check.** Copy the line from the capture, starting at the month (drop the `<14>` priority prefix), and test it:

```bash
echo 'Oct  1 16:22:41 NAS01 Connection: User [jdoe] from [203.0.113.25] failed to sign in to [DSM] via [password] due to authorization failure.' \
  | sudo /var/ossec/bin/wazuh-logtest
```

Read the three phases:

- **Phase 1** shows whether Wazuh extracted a `program_name`.
- **Phase 2** shows which decoder matched, or `No decoder matched`.
- **Phase 3** shows which rule fired.

**If Phase 2 says "No decoder matched":** this is almost always the program-name rule.

Wazuh keeps two lists of decoders: those that declare `<program_name>` and those that do not. An event that has a program name is checked **only** against the first list. An event without one is checked **only** against the second. So:

| Log line | Program name Wazuh extracts | Decoder must |
|---|---|---|
| `NAS01 Connection: User [...]` | `Connection` | declare `<program_name>` |
| `NAS01 FileStation Event: upload, ...` | none (there is a space before the colon) | **not** declare `<program_name>` |
| `NAS01 System jdoe:<TAB>Scheduled Task ...` | none (a space follows `System`) | **not** declare `<program_name>` |

A prematch-only decoder for a `Connection:` line passes every syntax check, loads without warnings, and is simply never evaluated.

This is in Wazuh's source: `OS_GetFirstOSDecoder()` in [`decoders_list.c`](https://github.com/wazuh/wazuh/blob/v4.14.0/src/analysisd/decoders/decoders_list.c) picks the list, `DecodeEvent()` in [`decoder.c`](https://github.com/wazuh/wazuh/blob/v4.14.0/src/analysisd/decoders/decoder.c) walks it, and the program-name parsing is in [`cleanevent.c`](https://github.com/wazuh/wazuh/blob/v4.14.0/src/analysisd/cleanevent.c).

If your DSM version sends a service this ruleset has not seen, check what Phase 1 reports for it and add a decoder on the matching list. Please open an issue with the sample line.

**If Phase 2 shows another decoder's name:** an existing decoder with a broader pattern claimed the line first. Decoders are tried in load order, not by how specific they are.

**If Phase 3 shows rule 1002 or similar:** the line was not decoded as Synology, so it fell through to Wazuh's generic syslog rules. Fix Phase 2 first.

---

## The installer stops: rule ID already used

**Cause.** Another ruleset on the manager uses an ID in this ruleset's range. Wazuh keeps the first definition and ignores the duplicate, which can silently disable one of the two.

**Fix.** Choose a free range:

```bash
grep -rhoE 'rule id="[0-9]+"' /var/ossec/etc/rules/ | sort -u     # what is taken
sudo ./synology-wazuh-install.sh --nas-ip <NAS_IP> --rule-base 131000
```

---

## The installer stops: listener conflict

**Cause.** `ossec.conf` already has a syslog `<remote>` block on the same port and protocol. Two blocks cannot bind the same socket; the second fails when the manager starts.

**Fix.** Either add the NAS to the existing block yourself and install only the decoders and rules:

```xml
<allowed-ips>192.0.2.10</allowed-ips>
```

```bash
sudo ./synology-wazuh-install.sh --nas-ip <NAS_IP> --no-listener
```

or give the NAS its own port, and set the same port in DSM:

```bash
sudo ./synology-wazuh-install.sh --nas-ip <NAS_IP> --port 5514
```

---

## Writing your own rules: "Field 'action' is static"

**Symptom.** `wazuh-analysisd -t` reports `Failure to read rule ... Field 'action' is static.`

**Cause.** Wazuh has a fixed set of built-in fields (`srcip`, `dstuser`, `action`, `protocol`, `status`, `url` and others). They cannot be tested with `<field name="...">`, which is for dynamic fields only.

**Fix.** Either decode into a field name of your own, as this ruleset does with `syno_action`, or use the dedicated rule elements such as `<action>`, `<user>` and `<srcip>`. For frequency rules, use `<same_user />` and `<same_srcip />` rather than `<same_field>`.

---

## The installer rolled back

The message above the rollback says which check failed. Nothing was left behind and the manager was not restarted.

- **`wazuh-analysisd -t failed or reported new warnings`**: the new warning lines are printed. The full before and after output is in the backup directory (`analysisd-before.txt.raw`, `analysisd-after.txt.raw`).
- **`wazuh-logtest self-test failed`**: one of the sample lines did not reach the expected rule. The usual cause is another decoder on the manager claiming the line first. Run the sample from `tests/sample-logs.txt` through `wazuh-logtest` by hand and read Phase 2.

Backups are kept in `/root/synology-wazuh-backup-<timestamp>/` and are never deleted by the script.
