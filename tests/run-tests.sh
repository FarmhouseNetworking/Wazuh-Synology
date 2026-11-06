#!/usr/bin/env bash
# =============================================================================
#  tests/run-tests.sh
#  Exercises synology-wazuh-install.sh against a throwaway fake Wazuh tree.
#  No Wazuh install is needed and nothing outside a temp directory is touched.
#
#  The fake wazuh-logtest (tests/mock-wazuh/wazuh-logtest.py) imitates how
#  analysisd picks decoders and rules. It checks the installer's logic and the
#  XML's regular expressions; it is not a substitute for testing on a real
#  manager.
#
#  Run as root (the installer refuses to run otherwise):  sudo tests/run-tests.sh
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
SCRIPT="$REPO/synology-wazuh-install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
T="$WORK/ossec"
PASS=0; FAIL=0

mk_tree() {
  rm -rf "$T"; mkdir -p "$T"/{bin,etc/rules,etc/decoders,ruleset/rules,logs/alerts} "$WORK/backups"
  cat >"$T/etc/ossec.conf" <<'X'
<ossec_config>
  <global>
    <logall>no</logall>
  </global>
<remote>
  <connection>syslog</connection>
  <port>5140</port>
  <protocol>tcp</protocol>
  <local_ip>127.0.0.1</local_ip>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/example.log</location>
  </localfile>
</ossec_config>
X
  cp "$T/etc/ossec.conf" "$WORK/orig.conf"
  cat >"$T/bin/wazuh-analysisd" <<'X'
#!/usr/bin/env bash
echo "2026/01/01 00:00:00 wazuh-analysisd: WARNING: pre-existing warning unrelated to this installer"
if [ -n "${MOCK_ANALYSISD_FAIL:-}" ] && [ -f "$(dirname "$0")/../etc/rules/9999_synology_rules.xml" ]; then
  echo "2026/01/01 00:00:01 wazuh-analysisd: CRITICAL: (1220): Error loading the rules"; exit 1
fi
exit 0
X
  printf '#!/usr/bin/env bash\nexit 0\n' >"$T/bin/wazuh-remoted"
  cp "$HERE/mock-wazuh/wazuh-logtest.py" "$T/bin/wazuh-logtest"
  chmod +x "$T"/bin/*
}

run() { OSSEC_DIR="$T" BACKUP_ROOT="$WORK/backups" bash "$SCRIPT" "$@" >"$WORK/out.txt" 2>&1; }

check() {  # check "<description>" <command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); echo "  ok    $desc"
  else FAIL=$((FAIL + 1)); echo "  FAIL  $desc"; sed 's/^/        | /' "$WORK/out.txt" | tail -n 8; fi
}
conf_same()   { cmp -s "$T/etc/ossec.conf" "$1"; }
no_files()    { [ ! -e "$T/etc/decoders/9999_synology_decoders.xml" ] && [ ! -e "$T/etc/rules/9999_synology_rules.xml" ]; }
count_is()    { [ "$(grep -c "$1" "$T/etc/ossec.conf")" -eq "$2" ]; }
out_has()     { grep -q "$1" "$WORK/out.txt"; }
INSTALL=(--nas-ip 192.0.2.10 --no-restart --no-firewall)
lt()      { printf '%s\n' "$1" | "$T/bin/wazuh-logtest" 2>&1; }
lt_id()   { lt "$1" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | tail -n 1; }
lt_lvl()  { lt "$1" | sed -n "s/^[[:space:]]*level: '\([0-9]*\)'.*/\1/p" | tail -n 1; }
rule_is() { [ "$(lt_id "$1")" = "$2" ] && [ "$(lt_lvl "$1")" = "$3" ]; }   # <log line> <rule id> <level>

[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 2; }

echo "Fresh install"
mk_tree
check "installer exits 0"                    run "${INSTALL[@]}"
check "one listener block written"           count_is 'BEGIN synology-wazuh-install' 1
check "self-test passed"                     out_has 'Self-test passed'
check "reference decoders match the script"  cmp -s "$T/etc/decoders/9999_synology_decoders.xml" "$REPO/decoders/9999_synology_decoders.xml"
check "reference rules match the script"     cmp -s "$T/etc/rules/9999_synology_rules.xml" "$REPO/rules/9999_synology_rules.xml"

echo "Sample logs hit the documented rules"
while IFS='|' read -r want line; do
  case "$want" in ''|\#*) continue ;; esac
  got="$(printf '%s\n' "$line" | "$T/bin/wazuh-logtest" 2>&1 | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | tail -n 1)"
  check "rule $want <- ${line:16:50}..." [ "$got" = "$want" ]
done <"$HERE/sample-logs.txt"

echo "Active Backup: the CBT fallback (127565) is not a failure (127559)"
ABB='Nov  2 19:02:57 NAS01 ActiveBackup[21490]: [VM Backup] '
CBT="${ABB}Failed to retrieve the changed blocks (CBT) for virtual machine VM01. A full backup will be performed."
check "CBT fallback line is 127565 at level 4"             rule_is "$CBT" 127565 4
check "a dotted VM name is still 127565"                   rule_is "${CBT/VM01/vm01.example.local}" 127565 4
check "127565 is in group backup, not backup_failure"      bash -c "sed -n '/<rule id=\"127565\"/,/<\\/rule>/p' '$REPO/rules/9999_synology_rules.xml' | grep -q '<group>backup,</group>'"
check "cancelled VM stays 127559 at level 10"             rule_is "${ABB}The backup task of the VM VM01 was canceled." 127559 10
check "cancelled task stays 127559 at level 10"            rule_is "${ABB}The backup task VM Backup was canceled." 127559 10
check "failed VM stays 127559 at level 10"                 rule_is "${ABB}The backup task of the VM VM01 failed." 127559 10
check "partially completed stays 127559 at level 10"       rule_is "${ABB}The backup task VM Backup partially completed." 127559 10
check "other CBT wording is not a failure (127555)"        rule_is "${ABB}Cannot retrieve the changed blocks for device VM01 in task VM Backup. (CBT)" 127555 3
check "CBT sentence plus a real failure stays 127559/10"   rule_is "${CBT% A full backup will be performed.} The backup task failed." 127559 10
check "CBT sentence with extra text after it stays 127559" rule_is "${CBT} Error code 12." 127559 10

echo "Why 127565 is a child of 127559: a lower-level sibling can never win"
mk_tree
check "installer exits 0"                                  run "${INSTALL[@]}"
sed -i '/<rule id="127565"/,/<\/rule>/ s#<if_sid>127559</if_sid>#<if_sid>127555</if_sid>#' "$T/etc/rules/9999_synology_rules.xml"
check "as a level 4 sibling the CBT line is still 127559/10"  rule_is "$CBT" 127559 10

echo "Hyper Backup: both USB drives failing on one day is found by the missing success (127562), not by the failures"
mk_tree
check "installer exits 0"                                  run "${INSTALL[@]}"
STREAM="$WORK/hb-stream.txt"; : >"$STREAM"
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  read -r mon day hms <<<"${line:0:15}"
  ts="$(date -d "$mon $day 2026 $hms" '+%Y-%m-%dT%H:%M:%S')"
  printf '%s|%s|%s\n' "$ts" "$(lt_id "$line")" "$(lt_lvl "$line")" >>"$STREAM"
done <"$HERE/both-drives-fail.txt"
stale()   { python3 "$HERE/stale-check.py" --now "$1" <"${2:-$STREAM}"; }
fresh()   { stale "$@"; }
is_stale(){ ! stale "$@"; }
check "the normal day gives one 127562 and one 127563"     bash -c "[ \"\$(grep -c '^2026-11-02.*|127562|3\$' '$STREAM')\" -eq 1 ] && [ \"\$(grep -c '^2026-11-02.*|127563|5\$' '$STREAM')\" -ge 1 ]"
check "both drives failing: four lines, all 127563 level 5" bash -c "[ \"\$(grep -c '^2026-11-03.*|127563|5\$' '$STREAM')\" -eq 4 ] && [ \"\$(grep -c '^2026-11-03' '$STREAM')\" -eq 4 ]"
check "both drives failing: no 127562 that day"            bash -c "! grep -q '^2026-11-03.*|127562|' '$STREAM'"
check "a normal day is fresh at 20:00"                     fresh 2026-11-02T20:00:00
check "one drive away is fresh the next morning (23.9h)"   fresh 2026-11-03T03:00:00 <(grep '^2026-11-02' "$STREAM")
check "both failed, 25h59m after the last success: fresh"  fresh 2026-11-03T05:04:00
check "both failed, 26h01m after the last success: STALE"  is_stale 2026-11-03T05:06:00
check "both failed, at the 09:00 weekday review: STALE"    is_stale 2026-11-03T09:00:00
printf '2026-11-03T20:00:00|127564|10\n2026-11-03T20:00:01|127563|5\n' >"$WORK/more-failures.txt"
check "more failures do not clear it (still STALE)"        is_stale 2026-11-03T22:00:00 <(cat "$STREAM" "$WORK/more-failures.txt")
printf '2026-11-03T21:00:00|127562|3\n' >"$WORK/recovered.txt"
check "one success from either drive clears it"            fresh 2026-11-03T22:00:00 <(cat "$STREAM" "$WORK/recovered.txt")
check "no alerts at all is reported as MISSING"            is_stale 2026-11-03T22:00:00 /dev/null

echo "Re-run with two NAS addresses"
check "installer exits 0"                    run --nas-ip "192.0.2.10, 192.0.2.11/32" --no-restart --no-firewall
check "still exactly one listener block"     count_is 'BEGIN synology-wazuh-install' 1
check "both addresses allowed"               count_is '<allowed-ips>192.0.2.1' 2

echo "Uninstall"
check "uninstall exits 0"                    run uninstall --no-restart --no-firewall
check "ossec.conf identical to the original" conf_same "$WORK/orig.conf"
check "decoder and rule files removed"       no_files

echo "Custom rule base"
check "installer exits 0 with --rule-base"   run "${INSTALL[@]}" --rule-base 130000
check "rules renumbered"                     grep -q 'id="130012"' "$T/etc/rules/9999_synology_rules.xml"
check "no default IDs left behind"           bash -c "! grep -q '1275[0-6][0-9]' '$T/etc/rules/9999_synology_rules.xml'"
check "renumbered self-test passed"          out_has 'Self-test passed'
check "CBT child follows its parent when renumbered"  grep -q 'if_sid>130059' "$T/etc/rules/9999_synology_rules.xml"
check "CBT fallback is 130065 at level 4 when renumbered"  rule_is "$CBT" 130065 4

echo "Watched accounts"
mk_tree
check "installer exits 0 with --watch-users" run "${INSTALL[@]}" --watch-users "backup-admin, ops.user"
check "watch rule written"                   grep -q 'id="127509"' "$T/etc/rules/9999_synology_rules.xml"
check "dot in a name is escaped"             grep -qF 'ops\.user' "$T/etc/rules/9999_synology_rules.xml"
got="$(printf '%s\n' 'Oct  1 16:36:55 NAS01 Connection: User [Backup-Admin] from [192.0.2.9] signed in to [DSM] successfully via [password].' | "$T/bin/wazuh-logtest" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | tail -n 1)"
check "watched sign-in hits 127509"          [ "$got" = "127509" ]
got="$(printf '%s\n' 'Oct  1 16:36:55 NAS01 Connection: User [jdoe] from [192.0.2.9] signed in to [DSM] successfully via [password].' | "$T/bin/wazuh-logtest" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | tail -n 1)"
check "other sign-ins still hit 127501"      [ "$got" = "127501" ]
check "rejects an unsafe account name"       bash -c "! OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} --watch-users 'bad|name' >'$WORK/out.txt' 2>&1"

echo "Refuses to run when a rule ID is taken"
mk_tree
echo '<group name="x,"><rule id="127510" level="3"><description>x</description></rule></group>' >"$T/etc/rules/other.xml"
check "installer exits non-zero"             bash -c "! OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} >'$WORK/out.txt' 2>&1"
check "ossec.conf untouched"                 conf_same "$WORK/orig.conf"
check "no files written"                     no_files

echo "Refuses to add a second listener on the same port and protocol"
mk_tree
sed -i 's#<port>5140</port>#<port>514</port>#' "$T/etc/ossec.conf"; cp "$T/etc/ossec.conf" "$WORK/conflict.conf"
check "installer exits non-zero"             bash -c "! OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} >'$WORK/out.txt' 2>&1"
check "ossec.conf untouched"                 conf_same "$WORK/conflict.conf"
check "--no-listener installs rules only"    run "${INSTALL[@]}" --no-listener
check "--no-listener leaves ossec.conf alone" conf_same "$WORK/conflict.conf"
check "same port on udp is allowed"          run "${INSTALL[@]}" --protocol udp

echo "Rolls back when wazuh-analysisd -t fails"
mk_tree
check "installer exits non-zero"             bash -c "! MOCK_ANALYSISD_FAIL=1 OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} >'$WORK/out.txt' 2>&1"
check "ossec.conf restored"                  conf_same "$WORK/orig.conf"
check "files removed"                        no_files

echo "Rolls back when the logtest self-test fails"
mk_tree
check "installer exits non-zero"             bash -c "! MOCK_LOGTEST_BREAK=1 OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} >'$WORK/out.txt' 2>&1"
check "ossec.conf restored"                  conf_same "$WORK/orig.conf"
check "files removed"                        no_files

echo "Refuses to install over other Synology content"
mk_tree
echo '<!-- synology -->' >"$T/etc/decoders/old_synology.xml"
check "installer exits non-zero"             bash -c "! OSSEC_DIR='$T' BACKUP_ROOT='$WORK/backups' bash '$SCRIPT' ${INSTALL[*]} >'$WORK/out.txt' 2>&1"
check "--force overrides"                    run "${INSTALL[@]}" --force

echo "Input validation"
mk_tree
check "rejects a bad address"                bash -c "! OSSEC_DIR='$T' bash '$SCRIPT' --nas-ip 999.1.1.1 >'$WORK/out.txt' 2>&1"
check "requires --nas-ip"                    bash -c "! OSSEC_DIR='$T' bash '$SCRIPT' >'$WORK/out.txt' 2>&1"
check "rejects a bad protocol"               bash -c "! OSSEC_DIR='$T' bash '$SCRIPT' --nas-ip 192.0.2.10 --protocol tls >'$WORK/out.txt' 2>&1"

echo "SuperOps edition"
SO="$REPO/superops/synology-wazuh-install-superops.sh"
so() { env OSSEC_DIR="$T" BACKUP_ROOT="$WORK/backups" "$@" bash "$SO" >"$WORK/out.txt" 2>&1; }
mk_tree
check "generated file is up to date"         python3 "$REPO/tools/build-superops.py" --check
check "install via runtime variables"        so SynologyNasIp=192.0.2.10 SynologyRestart=No SynologyOpenFirewall=no
check "self-test passed"                     out_has 'Self-test passed'
check "one listener block written"           count_is 'BEGIN synology-wazuh-install' 1
# shellcheck disable=SC2016  # literal "$Name" is what SuperOps leaves when a variable is not filled in
check "unfilled variables fall back"         so SynologyNasIp=192.0.2.10 SynologyRestart=no SynologyOpenFirewall=no 'SynologyPort=$SynologyPort' 'SynologyAction=$SynologyAction'
check "default port used"                    count_is '<port>514</port>' 1
check "status action exits 0"                so SynologyAction=status
check "SynologyWatchUsers honoured"          so SynologyNasIp=192.0.2.10 SynologyRestart=no SynologyOpenFirewall=no SynologyWatchUsers=backup-admin
check "watch rule written (SuperOps)"        grep -q 'id="127509"' "$T/etc/rules/9999_synology_rules.xml"
check "SuperOps edition carries 127565"        grep -q 'id="127565"' "$T/etc/rules/9999_synology_rules.xml"
check "uninstall action exits 0"             so SynologyAction=Uninstall SynologyRestart=no SynologyOpenFirewall=no
check "ossec.conf identical to the original" conf_same "$WORK/orig.conf"
check "missing SynologyNasIp exits 1"        bash -c "! env OSSEC_DIR='$T' bash '$SO' >'$WORK/out.txt' 2>&1"
check "error names the runtime variable"     out_has 'SynologyNasIp runtime variable is required'

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
