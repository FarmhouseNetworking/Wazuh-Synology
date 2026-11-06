#!/usr/bin/env python3
"""Models the weekly report's missed-backup check, for tests/run-tests.sh.

The Radio Design Group weekly report (rdg_weekly_security_review.sh) marks a backup source STALE when
the newest alert of a rule (127562 for Hyper Backup, 127557 for Active Backup) is more than 26 hours old,
and MISSING when there is none. This applies the same test to a replayed alert stream, so the tests can show
that the detection is the absence of a success, and does not depend on what failures are seen.

  stale-check.py --now 2026-11-03T09:00:00 [--rule 127562] [--hours 26]  < stream

stream: one alert per line, "ISO-timestamp|rule-id|level". Alerts after --now are ignored.
Exit 0 = fresh, 1 = STALE or MISSING, 2 = bad input.
"""
import argparse, datetime as dt, sys

ap = argparse.ArgumentParser()
ap.add_argument("--now", required=True)
ap.add_argument("--rule", default="127562")
ap.add_argument("--hours", type=float, default=26)
a = ap.parse_args()
try:
    now = dt.datetime.fromisoformat(a.now)
    last = None
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        ts, rid, _lvl = raw.split("|")
        t = dt.datetime.fromisoformat(ts)
        if rid == a.rule and t <= now and (last is None or t > last):
            last = t
except ValueError as e:
    print("bad input: %s" % e); sys.exit(2)
if last is None:
    print("MISSING: no rule %s alert at all" % a.rule); sys.exit(1)
age = now - last
if age > dt.timedelta(hours=a.hours):          # strictly greater, as in the report
    print("STALE: last rule %s alert %s is %.1fh old (limit %gh)" % (a.rule, last.isoformat(), age.total_seconds() / 3600, a.hours)); sys.exit(1)
print("FRESH: last rule %s alert %s is %.1fh old (limit %gh)" % (a.rule, last.isoformat(), age.total_seconds() / 3600, a.hours))
