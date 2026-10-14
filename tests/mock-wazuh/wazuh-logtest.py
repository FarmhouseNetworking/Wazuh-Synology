#!/usr/bin/env python3
"""Stand-in for wazuh-logtest used by tests/run-tests.sh. Imitates Wazuh pre-decoding,
decoder selection and rule matching closely enough to exercise the Synology XML:
events WITH a program_name only try decoders that declare <program_name>, sibling
decoders all run, and children are tried highest level first."""
import os, re, sys
import xml.etree.ElementTree as ET
base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if os.environ.get("MOCK_LOGTEST_BREAK"): print("id: '1002'"); sys.exit(0)
def load(p): return ET.fromstring("<r>" + re.sub(r"<!--.*?-->", "", open(p).read(), flags=re.S) + "</r>")
dec = load(os.path.join(base, "etc/decoders/9999_synology_decoders.xml"))
rul = load(os.path.join(base, "etc/rules/9999_synology_rules.xml"))
VALID = re.compile(r"[A-Za-z0-9\-_./@]")  # isValidChar-ish
def predecode(line):
    m = re.match(r"^\w{3} [ \d]\d \d\d:\d\d:\d\d (\S+) (.*)$", line)
    host, rest = m.group(1), m.group(2)
    i = 0
    while i < len(rest) and VALID.match(rest[i]): i += 1
    if i < len(rest) and rest[i] == ":":
        return rest[:i], rest[i+2:] if rest[i+1:i+2] == " " else rest[i+1:]
    # p_name[pid]: (cleanevent.c, second format)
    m = re.match(r"\[(\d+)\]:( ?)", rest[i:])
    if m:
        return rest[:i], rest[i + m.end():]
    return None, rest
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line: continue
    pname, log = predecode(line)
    print("**Phase 1: program_name: %r" % pname)
    roots = [d for d in dec.findall("decoder") if d.find("parent") is None]
    name, fields = None, {}
    for d in roots:
        pn = d.find("program_name")
        if pname is not None:
            if pn is None or not re.search(pn.text, pname): continue
        else:
            if pn is not None: continue
        pm = d.find("prematch")
        if pm is not None and not re.search(pm.text, log): continue
        name = d.get("name"); break
    if name:
        for c in dec.findall("decoder"):
            par = c.find("parent")
            if par is None or par.text != name: continue
            m = re.search(c.find("regex").text, log)
            if not m: continue
            for k, v in zip([x.strip() for x in c.find("order").text.split(",")], m.groups()):
                fields[k] = v
    print("**Phase 2: name: %r %r" % (name, fields))
    rules = rul.findall(".//rule")
    def matches(r):
        if r.find("if_matched_sid") is not None: return False
        da = r.find("decoded_as")
        if da is not None and da.text != name: return False
        for mt in r.findall("match"):
            if mt.get("type") == "pcre2":
                if not re.search(mt.text, log): return False
            elif mt.text not in log: return False
        for f in r.findall("field"):
            if not re.search(f.text, fields.get(f.get("name"), "")): return False
        return True
    # analysisd keeps each parent's children sorted by level, highest first,
    # in load order within a level (rules_list.c _OS_AddRule)
    ordered = sorted(rules, key=lambda x: -int(x.get("level")))
    def descend(r):
        for c in ordered:
            s = c.find("if_sid")
            if s is not None and s.text == r.get("id") and matches(c):
                return descend(c)
        return r
    hit = next((r for r in ordered if r.find("decoded_as") is not None and matches(r)), None)
    if hit is None: print("**Phase 3: no rule"); continue
    hit = descend(hit)
    print("**Phase 3: Completed filtering (rules).\n        id: '%s'\n        level: '%s'" % (hit.get("id"), hit.get("level")))
