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
check "no default IDs left behind"           bash -c "! grep -q '1275[0-5][0-9]' '$T/etc/rules/9999_synology_rules.xml'"
check "renumbered self-test passed"          out_has 'Self-test passed'

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
check "uninstall action exits 0"             so SynologyAction=Uninstall SynologyRestart=no SynologyOpenFirewall=no
check "ossec.conf identical to the original" conf_same "$WORK/orig.conf"
check "missing SynologyNasIp exits 1"        bash -c "! env OSSEC_DIR='$T' bash '$SO' >'$WORK/out.txt' 2>&1"
check "error names the runtime variable"     out_has 'SynologyNasIp runtime variable is required'

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
