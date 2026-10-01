#!/usr/bin/env bash
# =============================================================================
#  synology-wazuh-install.sh
#  Receive Synology DSM syslog (sign-ins, auto-block, file activity) on a
#  self-hosted Wazuh manager: adds a syslog listener restricted to the NAS,
#  installs tested decoders and rules, and proves them with wazuh-logtest
#  before the manager is restarted.
#
#  Run ON the Wazuh manager as root.
#
#  Author : Farmhouse Networking - https://www.farmhousenetworking.com
#  License: MIT
#  Repo   : https://github.com/FarmhouseNetworking/Wazuh-Synology
# =============================================================================
#
#  Configuration can be supplied three ways (later wins):
#    1. Defaults below
#    2. Environment variables (NAS_IP, SYSLOG_PORT, SYSLOG_PROTO, RULE_BASE, ...)
#    3. Command-line flags (--nas-ip, --port, --protocol, --rule-base, ...)
#
#  Run with --help for usage.
# =============================================================================

set -uo pipefail

SCRIPT_VERSION="1.0.0"

# ----------------------------- CONFIGURATION ---------------------------------
NAS_IP="${NAS_IP:-}"                      # NAS address(es), comma-separated, IPv4 or IPv4/CIDR
SYSLOG_PORT="${SYSLOG_PORT:-514}"         # Port the manager listens on for the NAS
SYSLOG_PROTO="${SYSLOG_PROTO:-tcp}"       # tcp | udp  (must match DSM's "Transfer protocol")
RULE_BASE="${RULE_BASE:-127500}"          # First rule ID; the ruleset uses RULE_BASE..RULE_BASE+12
ADD_LISTENER="${ADD_LISTENER:-yes}"       # yes | no  (no = you added the NAS to an existing <remote> block)
OPEN_FIREWALL="${OPEN_FIREWALL:-yes}"     # yes | no  (ufw / firewalld, NAS source only)
RESTART="${RESTART:-yes}"                 # yes | no  (restart wazuh-manager when tests pass)
FORCE="${FORCE:-no}"                      # yes = install even if other Synology rules/decoders exist
ACTION="${ACTION:-install}"               # install | status | uninstall
# -----------------------------------------------------------------------------

OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
DEC_FILE="$OSSEC_DIR/etc/decoders/9999_synology_decoders.xml"
RULES_FILE="$OSSEC_DIR/etc/rules/9999_synology_rules.xml"
ALERTS_JSON="$OSSEC_DIR/logs/alerts/alerts.json"
BACKUP_ROOT="${BACKUP_ROOT:-/root}"
MARK_BEGIN="<!-- BEGIN synology-wazuh-install listener -->"
MARK_END="<!-- END synology-wazuh-install listener -->"
DEFAULT_BASE=127500
RULE_OFFSETS="00 01 02 03 04 05 10 11 12"

BACKUP_DIR=""
HAD_DEC=0
HAD_RULES=0
PY=""

# ------------------------------- OUTPUT --------------------------------------
info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
synology-wazuh-install.sh v$SCRIPT_VERSION

Usage:
  sudo ./synology-wazuh-install.sh [install] --nas-ip <ip>[,<ip>...] [options]
  sudo ./synology-wazuh-install.sh status
  sudo ./synology-wazuh-install.sh uninstall

Actions:
  install      Add the listener, decoders and rules; test; restart (default)
  status       Show what is installed and the most recent Synology alerts
  uninstall    Remove the listener, decoders, rules and firewall rule

Options:
  --nas-ip LIST        NAS address(es), comma-separated (env NAS_IP)  [required]
  --port N             Listener port (env SYSLOG_PORT, default 514)
  --protocol P         tcp or udp (env SYSLOG_PROTO, default tcp)
  --rule-base N        First rule ID (env RULE_BASE, default 127500)
  --no-listener        Do not add a <remote> block (use when the NAS is already
                       allowed in an existing syslog listener)
  --no-firewall        Do not touch ufw / firewalld
  --no-restart         Install and test, but do not restart wazuh-manager
  --force              Install even if other Synology rules/decoders exist
  -h, --help           Show this help
  -V, --version        Show the version

Nothing is changed unless every check passes. If validation or the logtest
self-test fails, ossec.conf and the rule/decoder files are restored.
EOF
}

# ------------------------------- ARGUMENTS -----------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    install|status|uninstall) ACTION="$1" ;;
    --nas-ip)      NAS_IP="${2:-}"; shift ;;
    --port)        SYSLOG_PORT="${2:-}"; shift ;;
    --protocol)    SYSLOG_PROTO="${2:-}"; shift ;;
    --rule-base)   RULE_BASE="${2:-}"; shift ;;
    --no-listener) ADD_LISTENER="no" ;;
    --no-firewall) OPEN_FIREWALL="no" ;;
    --no-restart)  RESTART="no" ;;
    --force)       FORCE="yes" ;;
    -h|--help)     usage; exit 0 ;;
    -V|--version)  echo "$SCRIPT_VERSION"; exit 0 ;;
    *)             usage >&2; die "Unknown argument: $1" ;;
  esac
  shift
done

# ------------------------------- HELPERS -------------------------------------
rule_id() { echo $(( RULE_BASE + 10#$1 )); }

nas_list() { printf '%s\n' "$NAS_IP" | tr ',' '\n' | sed 's/[[:space:]]//g' | sed '/^$/d'; }

valid_ip() {
  local ip="${1%%/*}" mask="" o
  [[ "$1" == */* ]] && mask="${1##*/}"
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
  if [ -n "$mask" ]; then
    [[ "$mask" =~ ^[0-9]{1,2}$ ]] && [ "$mask" -le 32 ] || return 1
  fi
  return 0
}

find_python() {
  if [ -x "$OSSEC_DIR/framework/python/bin/python3" ]; then
    PY="$OSSEC_DIR/framework/python/bin/python3"
  elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
  else
    die "python3 not found (looked in $OSSEC_DIR/framework/python/bin and PATH)."
  fi
}

preflight_common() {
  [ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
  [ -f "$OSSEC_CONF" ] || die "$OSSEC_CONF not found. Run this on the Wazuh manager."
  local b
  for b in wazuh-analysisd wazuh-remoted wazuh-logtest; do
    [ -x "$OSSEC_DIR/bin/$b" ] || die "$OSSEC_DIR/bin/$b not found. This must be a Wazuh manager, not an agent."
  done
  find_python
}

# Normalised analysisd -t output (timestamps stripped) for before/after diffing
analysisd_test() {
  local out="$1" rc
  "$OSSEC_DIR/bin/wazuh-analysisd" -t >"$out.raw" 2>&1; rc=$?
  sed -E 's/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9:]{8} //' "$out.raw" | sort -u >"$out"
  return $rc
}

# Edits the marker-delimited listener block in ossec.conf.
#   conf_edit check  -> prints "conflict" if another syslog <remote> uses the same port
#   conf_edit write  -> replaces/inserts our block
#   conf_edit remove -> removes our block
#   conf_edit show   -> prints our block
conf_edit() {
  "$PY" - "$1" "$OSSEC_CONF" "$MARK_BEGIN" "$MARK_END" "$SYSLOG_PORT" "$SYSLOG_PROTO" "$NAS_IP" <<'PYEOF'
import re, sys
mode, path, begin, end, port, proto, ips = sys.argv[1:8]
s = open(path, encoding="utf-8", errors="surrogateescape").read()
ours = re.compile(r"[ \t]*" + re.escape(begin) + r".*?" + re.escape(end) + r"[ \t]*\n?", re.S)

if mode == "show":
    m = ours.search(s)
    print(m.group(0).rstrip() if m else "")
    sys.exit(0)

rest = ours.sub("", s)

if mode == "check":
    for blk in re.findall(r"<remote>.*?</remote>", re.sub(r"<!--.*?-->", "", rest, flags=re.S), re.S):
        if not re.search(r"<connection>\s*syslog\s*</connection>", blk):
            continue
        p = re.search(r"<port>\s*(\d+)\s*</port>", blk)
        q = re.search(r"<protocol>\s*([a-z,\s]+?)\s*</protocol>", blk)
        bport = p.group(1) if p else "514"
        bprotos = [x.strip() for x in q.group(1).split(",")] if q else [proto]
        if bport == port and proto in bprotos:
            print("conflict")
            sys.exit(0)
    print("clear")
    sys.exit(0)

if mode == "remove":
    open(path, "w", encoding="utf-8", errors="surrogateescape").write(rest)
    sys.exit(0)

if mode == "write":
    allowed = "".join("    <allowed-ips>%s</allowed-ips>\n" % i.strip()
                      for i in ips.split(",") if i.strip())
    block = ("  %s\n  <remote>\n    <connection>syslog</connection>\n"
             "    <port>%s</port>\n    <protocol>%s</protocol>\n%s  </remote>\n  %s\n"
             % (begin, port, proto, allowed, end))
    i = rest.rfind("</ossec_config>")
    if i < 0:
        sys.exit("no </ossec_config> closing tag found")
    open(path, "w", encoding="utf-8", errors="surrogateescape").write(rest[:i] + block + rest[i:])
    sys.exit(0)

sys.exit("unknown mode")
PYEOF
}

write_decoders() {
  cat >"$DEC_FILE" <<'XMLEOF'
<!--
  Synology DSM 7.x syslog decoders (BSD / RFC 3164 format)
  https://github.com/FarmhouseNetworking/Wazuh-Synology

  Connection lines are pre-decoded by Wazuh with program_name Connection.
  Wazuh only tries decoders that declare program_name against such events,
  so synology-conn must declare it.

  FileStation Event lines contain a space before the colon, so Wazuh sets
  no program_name and only tries decoders without one. synology-file must
  not declare program_name.
-->
<decoder name="synology-conn">
  <program_name>^Connection$</program_name>
  <prematch type="pcre2">User \[[^\]]+\] from \[[^\]]+\]|Host \[[^\]]+\] was blocked</prematch>
</decoder>
<decoder name="synology-conn-fields">
  <parent>synology-conn</parent>
  <regex type="pcre2">User \[([^\]]+)\] from \[([^\]]+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>
<decoder name="synology-conn-fields">
  <parent>synology-conn</parent>
  <regex type="pcre2">Host \[([^\]]+)\] was blocked</regex>
  <order>srcip</order>
</decoder>
<decoder name="synology-conn-fields">
  <parent>synology-conn</parent>
  <regex type="pcre2">(?:via|to) \[([^\]]+)\]</regex>
  <order>service</order>
</decoder>

<decoder name="synology-file">
  <prematch type="pcre2">Path: .+, File/Folder: </prematch>
</decoder>
<decoder name="synology-file-fields">
  <parent>synology-file</parent>
  <regex type="pcre2">(\w+), Path: (.+?), File/Folder: (\w+), Size: (.+?), User: (.+?), IP: (\S+)</regex>
  <order>syno_action, file_path, file_type, file_size, dstuser, srcip</order>
</decoder>
XMLEOF
}

write_rules() {
  cat >"$RULES_FILE" <<'XMLEOF'
<!--
  Synology DSM 7.x rules
  https://github.com/FarmhouseNetworking/Wazuh-Synology

  IDs 127500-127512 by default (the installer renumbers with RULE_BASE).
  action and dstuser are static Wazuh fields and cannot be matched with a
  field element, which is why the decoder emits syno_action and the admin
  rule matches on the log text.
-->
<group name="synology,">
  <rule id="127500" level="3">
    <decoded_as>synology-conn</decoded_as>
    <description>Synology: connection event</description>
  </rule>
  <rule id="127501" level="3">
    <if_sid>127500</if_sid>
    <match type="pcre2">(?:logged in|signed in to \[[^\]]+\]) successfully</match>
    <description>Synology: $(dstuser) signed in from $(srcip) via $(service)</description>
    <group>authentication_success,</group>
  </rule>
  <rule id="127502" level="5">
    <if_sid>127500</if_sid>
    <match type="pcre2">failed to (?:log|sign) in</match>
    <description>Synology: failed sign-in for $(dstuser) from $(srcip)</description>
    <group>authentication_failed,</group>
  </rule>
  <rule id="127503" level="10" frequency="6" timeframe="120">
    <if_matched_sid>127502</if_matched_sid>
    <same_srcip />
    <description>Synology: brute force - multiple failed sign-ins from $(srcip)</description>
    <group>authentication_failures,</group>
  </rule>
  <rule id="127504" level="10">
    <if_sid>127500</if_sid>
    <match>was blocked</match>
    <description>Synology: auto-block triggered for $(srcip)</description>
  </rule>
  <rule id="127505" level="8">
    <if_sid>127501</if_sid>
    <match type="pcre2">User \[(?i:admin|administrator|root)\]</match>
    <description>Synology: built-in admin account sign-in from $(srcip)</description>
  </rule>

  <rule id="127510" level="3">
    <decoded_as>synology-file</decoded_as>
    <description>Synology file $(syno_action): $(file_path) by $(dstuser) from $(srcip)</description>
  </rule>
  <rule id="127511" level="3">
    <if_sid>127510</if_sid>
    <field name="syno_action">^delete$</field>
    <description>Synology file deleted: $(file_path) by $(dstuser)</description>
  </rule>
  <rule id="127512" level="12" frequency="50" timeframe="60">
    <if_matched_sid>127511</if_matched_sid>
    <same_user />
    <description>Synology: mass deletion by $(dstuser) - possible ransomware or data destruction</description>
  </rule>
</group>
XMLEOF

  if [ "$RULE_BASE" -ne "$DEFAULT_BASE" ]; then
    local off
    for off in $RULE_OFFSETS; do
      sed -i -E "s/\\b1275${off}\\b/$(rule_id "$off")/g" "$RULES_FILE"
    done
  fi
}

# Sample lines in the exact format DSM 7 sends, and the rule each must hit.
# Format: <rule offset>|<log line>
self_test_samples() {
  cat <<'EOF'
02|Oct  1 16:22:41 NAS01 Connection: User [jdoe] from [203.0.113.25] failed to sign in to [DSM] via [password] due to authorization failure.
00|Oct  1 16:36:49 NAS01 Connection: User [jdoe] from [203.0.113.25] has successfully passed the first authentication of 2FA via [password]
01|Oct  1 16:36:55 NAS01 Connection: User [jdoe] from [203.0.113.25] signed in to [DSM] successfully via [password].
10|Oct  1 16:37:11 NAS01 FileStation Event: upload, Path: /Shared/Quarterly report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
10|Oct  1 16:37:18 NAS01 FileStation Event: rename, Path: /Shared/Quarterly report.docx -> /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
11|Oct  1 16:37:22 NAS01 FileStation Event: delete, Path: /Shared/Q3 report.docx, File/Folder: File, Size: 18.77 KB, User: jdoe, IP: 203.0.113.25
EOF
}

self_test() {
  local off line want out got fails=0
  while IFS='|' read -r off line; do
    [ -n "$off" ] || continue
    want="$(rule_id "$off")"
    out="$(printf '%s\n' "$line" | "$OSSEC_DIR/bin/wazuh-logtest" 2>&1)"
    got="$(printf '%s\n' "$out" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | tail -n 1)"
    if [ "$got" = "$want" ]; then
      ok "logtest: rule $want  <- ${line:16:70}..."
    else
      warn "logtest: expected rule $want, got '${got:-no rule}' <- ${line:16:70}..."
      fails=$((fails + 1))
    fi
  done < <(self_test_samples)
  return "$fails"
}

rollback() {
  warn "Rolling back. The manager has NOT been restarted."
  [ -f "$BACKUP_DIR/ossec.conf" ] && cp -p "$BACKUP_DIR/ossec.conf" "$OSSEC_CONF"
  if [ "$HAD_DEC" -eq 1 ]; then cp -p "$BACKUP_DIR/$(basename "$DEC_FILE")" "$DEC_FILE"; else rm -f "$DEC_FILE"; fi
  if [ "$HAD_RULES" -eq 1 ]; then cp -p "$BACKUP_DIR/$(basename "$RULES_FILE")" "$RULES_FILE"; else rm -f "$RULES_FILE"; fi
  warn "Restored from $BACKUP_DIR"
}

make_backup() {
  BACKUP_DIR="$BACKUP_ROOT/synology-wazuh-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR" || die "Cannot create $BACKUP_DIR"
  cp -p "$OSSEC_CONF" "$BACKUP_DIR/ossec.conf" || die "Cannot back up ossec.conf"
  cmp -s "$OSSEC_CONF" "$BACKUP_DIR/ossec.conf" || die "Backup of ossec.conf does not match the original"
  if [ -f "$DEC_FILE" ]; then cp -p "$DEC_FILE" "$BACKUP_DIR/"; HAD_DEC=1; fi
  if [ -f "$RULES_FILE" ]; then cp -p "$RULES_FILE" "$BACKUP_DIR/"; HAD_RULES=1; fi
  ok "Backup: $BACKUP_DIR"
}

set_owner() {
  if id wazuh >/dev/null 2>&1; then chown wazuh:wazuh "$@"; fi
  chmod 660 "$@"
}

firewall_open() {
  local ip
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    while read -r ip; do
      ufw allow from "$ip" to any port "$SYSLOG_PORT" proto "$SYSLOG_PROTO" comment 'synology-wazuh' >/dev/null \
        && ok "ufw: allowed $ip -> $SYSLOG_PORT/$SYSLOG_PROTO"
    done < <(nas_list)
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    while read -r ip; do
      firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=$SYSLOG_PORT protocol=$SYSLOG_PROTO accept" >/dev/null \
        && ok "firewalld: allowed $ip -> $SYSLOG_PORT/$SYSLOG_PROTO"
    done < <(nas_list)
    firewall-cmd --reload >/dev/null
  else
    info "No active ufw or firewalld found. If you filter with iptables/nftables, allow the NAS to $SYSLOG_PORT/$SYSLOG_PROTO yourself."
  fi
}

firewall_close() {
  local ip="$1" port="$2" proto="$3"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw delete allow from "$ip" to any port "$port" proto "$proto" >/dev/null 2>&1 && ok "ufw: removed rule for $ip"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$ip port port=$port protocol=$proto accept" >/dev/null 2>&1 \
      && ok "firewalld: removed rule for $ip"
    firewall-cmd --reload >/dev/null 2>&1
  fi
}

restart_manager() {
  info "Restarting wazuh-manager..."
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager'; then
    systemctl restart wazuh-manager || return 1
    sleep 8
    systemctl is-active --quiet wazuh-manager || return 1
  else
    "$OSSEC_DIR/bin/wazuh-control" restart >/dev/null || return 1
    sleep 8
  fi
  ok "wazuh-manager is running"
}

listener_up() {
  command -v ss >/dev/null 2>&1 || return 2
  local flag="-lnt"
  [ "$SYSLOG_PROTO" = "udp" ] && flag="-lnu"
  ss "$flag" 2>/dev/null | grep -Eq "[:.]${SYSLOG_PORT}[[:space:]]"
}

print_dsm_steps() {
  local mgr
  mgr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat <<EOF

------------------------------------------------------------------------------
 Next: configure the NAS (DSM 7)
------------------------------------------------------------------------------
 1. Log Center > Log Sending > Location
      Send logs to a syslog server : ticked
      Server                       : ${mgr:-<IP of this manager>}
      Port                         : $SYSLOG_PORT
      Transfer protocol            : ${SYSLOG_PROTO^^}   (must match the listener; check it is not UDP)
      Log format                   : BSD (RFC 3164)
      Enable secure connection     : unticked
 2. Log Center > Log Sending > Log Filters
      Categories : tick the ones you want (Connection, SMB, File Station log, ...)
      Priorities : include Info and Notice, or successful sign-ins and file
                   events are never sent
 3. Control Panel > File Services > SMB > Enable Transfer Log
 4. Click "Send test log", then run:  sudo $0 status
------------------------------------------------------------------------------
EOF
}

# ------------------------------- ACTIONS -------------------------------------
do_install() {
  preflight_common

  [ -n "$NAS_IP" ] || { usage >&2; die "--nas-ip is required."; }
  local ip
  while read -r ip; do
    valid_ip "$ip" || die "Not a valid IPv4 address or CIDR: $ip"
  done < <(nas_list)
  NAS_IP="$(nas_list | paste -sd, -)"
  [[ "$SYSLOG_PORT" =~ ^[0-9]+$ ]] && [ "$SYSLOG_PORT" -ge 1 ] && [ "$SYSLOG_PORT" -le 65535 ] || die "Invalid port: $SYSLOG_PORT"
  [ "$SYSLOG_PROTO" = "tcp" ] || [ "$SYSLOG_PROTO" = "udp" ] || die "Protocol must be tcp or udp."
  [[ "$RULE_BASE" =~ ^[0-9]+$ ]] && [ "$RULE_BASE" -ge 100000 ] && [ "$RULE_BASE" -le 999987 ] \
    || die "--rule-base must be between 100000 and 999987."

  info "NAS: $NAS_IP   listener: $SYSLOG_PORT/$SYSLOG_PROTO   rule IDs: $RULE_BASE-$((RULE_BASE + 12))"

  # --- Checks that must pass before anything is written ---------------------
  local other
  other="$(grep -rilE 'synology' "$OSSEC_DIR/etc/rules" "$OSSEC_DIR/etc/decoders" 2>/dev/null \
            | grep -vxF -e "$DEC_FILE" -e "$RULES_FILE" || true)"
  if [ -n "$other" ] && [ "$FORCE" != "yes" ]; then
    warn "Other Synology rules/decoders already exist:"
    printf '%s\n' "$other" | sed 's/^/      /' >&2
    die "Nothing changed. Review those files, or re-run with --force to install alongside them."
  fi

  local off id hit
  for off in $RULE_OFFSETS; do
    id="$(rule_id "$off")"
    hit="$(grep -rlE "<rule[^>]*[[:space:]]id=\"$id\"" "$OSSEC_DIR/etc/rules" "$OSSEC_DIR/ruleset/rules" 2>/dev/null \
            | grep -vxF "$RULES_FILE" | head -n 1 || true)"
    [ -z "$hit" ] || die "Rule ID $id is already used in $hit. Nothing changed. Pick another range with --rule-base."
  done

  if [ "$ADD_LISTENER" = "yes" ] && [ "$(conf_edit check)" = "conflict" ]; then
    warn "ossec.conf already has a syslog <remote> block on $SYSLOG_PORT/$SYSLOG_PROTO."
    warn "Two blocks cannot bind the same port. Add the NAS to the existing block instead:"
    while read -r ip; do printf '      <allowed-ips>%s</allowed-ips>\n' "$ip" >&2; done < <(nas_list)
    die "Nothing changed. Edit that block and re-run with --no-listener, or choose another --port / --protocol."
  fi
  ok "Pre-checks passed (no rule ID collisions, no listener conflict)"

  # --- Backup and baseline ---------------------------------------------------
  make_backup
  analysisd_test "$BACKUP_DIR/analysisd-before.txt" || warn "wazuh-analysisd -t already reports a problem before any change (see $BACKUP_DIR/analysisd-before.txt.raw)"

  # --- Write -----------------------------------------------------------------
  if [ "$ADD_LISTENER" = "yes" ]; then
    conf_edit write || { rollback; die "Could not write the listener block."; }
    ok "Wrote listener block for $NAS_IP"
  else
    info "Leaving ossec.conf alone (--no-listener)."
  fi
  write_decoders
  write_rules
  set_owner "$DEC_FILE" "$RULES_FILE"
  ok "Wrote $(basename "$DEC_FILE") and $(basename "$RULES_FILE")"

  # --- Validate ---------------------------------------------------------------
  if ! "$OSSEC_DIR/bin/wazuh-remoted" -t >"$BACKUP_DIR/remoted-after.txt" 2>&1; then
    cat "$BACKUP_DIR/remoted-after.txt" >&2
    rollback; die "wazuh-remoted -t failed."
  fi
  local rc=0 new
  analysisd_test "$BACKUP_DIR/analysisd-after.txt" || rc=$?
  new="$(comm -13 "$BACKUP_DIR/analysisd-before.txt" "$BACKUP_DIR/analysisd-after.txt" | grep -E 'WARNING|ERROR|CRITICAL' || true)"
  if [ "$rc" -ne 0 ] || [ -n "$new" ]; then
    [ -n "$new" ] && printf '%s\n' "$new" >&2
    rollback; die "wazuh-analysisd -t failed or reported new warnings."
  fi
  ok "Configuration test clean (no new warnings)"

  # --- Prove the decoders and rules against real DSM log lines ----------------
  if ! self_test; then
    rollback; die "wazuh-logtest self-test failed."
  fi
  ok "Self-test passed: all sample DSM lines hit the expected rules"

  # --- Firewall, restart, verify ----------------------------------------------
  if [ "$OPEN_FIREWALL" = "yes" ] && [ "$ADD_LISTENER" = "yes" ]; then firewall_open; fi

  if [ "$RESTART" = "yes" ]; then
    restart_manager || die "wazuh-manager did not restart cleanly. Check 'systemctl status wazuh-manager'. Backup: $BACKUP_DIR"
    if listener_up; then
      ok "Listening on $SYSLOG_PORT/$SYSLOG_PROTO"
    else
      warn "Could not confirm a listener on $SYSLOG_PORT/$SYSLOG_PROTO. Check: ss -lntup | grep ':$SYSLOG_PORT '"
    fi
  else
    info "Skipped restart (--no-restart). Restart wazuh-manager to activate the listener and rules."
  fi

  ok "Installed. Backup kept at $BACKUP_DIR"
  print_dsm_steps
}

do_status() {
  preflight_common
  local blk
  blk="$(conf_edit show)"
  echo "== Listener block in ossec.conf =="
  if [ -n "$blk" ]; then printf '%s\n' "$blk"; else echo "(not installed)"; fi
  echo
  echo "== Files =="
  ls -l "$DEC_FILE" "$RULES_FILE" 2>&1
  echo
  echo "== Listening sockets =="
  if [ -n "$blk" ] && command -v ss >/dev/null 2>&1; then
    local p
    p="$(printf '%s\n' "$blk" | sed -n 's/.*<port>\([0-9]*\)<\/port>.*/\1/p' | head -n 1)"
    ss -lntup 2>/dev/null | grep -E "[:.]${p}[[:space:]]" || echo "(nothing listening on port $p)"
  else
    echo "(n/a)"
  fi
  echo
  echo "== Last 10 Synology alerts =="
  if [ -r "$ALERTS_JSON" ]; then
    grep '"synology"' "$ALERTS_JSON" | tail -n 10 \
      | grep -o '"rule":{"level":[0-9]*,"description":"[^"]*","id":"[0-9]*"' \
      | sed -E 's/"rule":\{"level":([0-9]*),"description":"([^"]*)","id":"([0-9]*)"/  \3 (level \1)  \2/' \
      || true
    echo "  total today: $(grep -c '"synology"' "$ALERTS_JSON" || true)"
  else
    echo "($ALERTS_JSON not readable)"
  fi
}

do_uninstall() {
  preflight_common
  local blk
  blk="$(conf_edit show)"
  if [ -z "$blk" ] && [ ! -f "$DEC_FILE" ] && [ ! -f "$RULES_FILE" ]; then
    info "Nothing to remove."; exit 0
  fi
  make_backup

  if [ -n "$blk" ]; then
    local port proto ip
    port="$(printf '%s\n' "$blk" | sed -n 's/.*<port>\([0-9]*\)<\/port>.*/\1/p' | head -n 1)"
    proto="$(printf '%s\n' "$blk" | sed -n 's/.*<protocol>\([a-z]*\)<\/protocol>.*/\1/p' | head -n 1)"
    conf_edit remove || { rollback; die "Could not remove the listener block."; }
    ok "Removed listener block"
    if [ "$OPEN_FIREWALL" = "yes" ]; then
      while read -r ip; do
        [ -n "$ip" ] && firewall_close "$ip" "$port" "$proto"
      done < <(printf '%s\n' "$blk" | sed -n 's/.*<allowed-ips>\(.*\)<\/allowed-ips>.*/\1/p')
    fi
  fi
  rm -f "$DEC_FILE" "$RULES_FILE"
  ok "Removed decoder and rule files"

  if ! "$OSSEC_DIR/bin/wazuh-remoted" -t >/dev/null 2>&1 || ! "$OSSEC_DIR/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
    rollback; die "Configuration test failed after removal."
  fi
  if [ "$RESTART" = "yes" ]; then
    restart_manager || die "wazuh-manager did not restart cleanly. Backup: $BACKUP_DIR"
  else
    info "Skipped restart (--no-restart)."
  fi
  ok "Uninstalled. Backup kept at $BACKUP_DIR. Remember to turn off Log Sending on the NAS."
}

case "$ACTION" in
  install)   do_install ;;
  status)    do_status ;;
  uninstall) do_uninstall ;;
  *)         usage >&2; die "Unknown action: $ACTION" ;;
esac
