#!/usr/bin/env python3
"""Flag potential threats from device behaviour -- fast log in/out and sudden
unknown entrances -- offline, from the AI CSV.

A "potential threat" here is a device worth a look, not proof of an attack:

  * FAST LOG IN/OUT (flapping): it connects and disconnects quickly and
    repeatedly. Could be a probe, a spoofed/retrying device, or an unstable
    intruder. (A device's count of sessions shorter than StreamWatch's
    missing-after window -- device_report's `fast_flaps`.)
  * UNKNOWN ENTRANCE: a device held at the gate -- on NEITHER the allow nor the
    deny list -- so it entered the network unexpectedly and is awaiting a
    decision (internet_access state HELD).

A recent first-sighting is added as context ("arrived <time>"), but a KNOWN,
allowed device simply arriving is not itself a threat -- only unknown or
flapping behaviour is flagged.

  threats.py                  scan the recorded history
  threats.py --min-flaps 3    only flag 3+ quick in/out sessions
  threats.py --hours 6        mark entrances within the last 6 h as "recent"
  threats.py --json
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import device_report as dr       # noqa: E402

DEFAULT_DIR = os.path.expanduser("~/mesh_records")
MIN_FLAPS = 2
RECENT_HOURS = 24


def find_threats(rows, min_flaps=MIN_FLAPS, recent_hours=RECENT_HOURS, now=None):
    """Devices showing flapping or an unknown entrance, most severe first."""
    agg = dr.aggregate(rows)
    devices = dr.select(agg, dr.collect_station_ips(rows))
    if now is None:
        seen = [d["last_seen"] for d in devices if d["last_seen"]]
        now = max(seen) if seen else time.time()
    out = []
    for d in devices:
        reasons, severity = [], 0
        if d["access_state"] == "HELD":
            reasons.append(("unknown entrance",
                            "held at the gate -- on neither the allow nor the deny list"))
            severity += 3
        if d["fast_flaps"] >= min_flaps:
            reasons.append(("fast log in/out",
                            "%d quick connect/disconnect session(s)" % d["fast_flaps"]))
            severity += 2 + d["fast_flaps"]
        if not reasons:
            continue
        recent = d["first_seen"] and (now - d["first_seen"]) <= recent_hours * 3600
        if recent:
            reasons.append(("recent arrival", "first seen %s" % dr.iso(d["first_seen"])))
            severity += 1
        out.append({
            "mac": d["mac"], "ip": d["ip"], "name": d["name"],
            "access_state": d["access_state"], "fast_flaps": d["fast_flaps"],
            "recent": bool(recent), "severity": severity, "reasons": reasons,
        })
    out.sort(key=lambda t: t["severity"], reverse=True)
    return out


def main(argv):
    folder, min_flaps, hours, as_json = DEFAULT_DIR, MIN_FLAPS, RECENT_HOURS, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip()); return 0
        elif a == "--dir":
            i += 1; folder = argv[i] if i < len(argv) else folder
        elif a == "--min-flaps":
            i += 1; min_flaps = int(argv[i]) if i < len(argv) else min_flaps
        elif a == "--hours":
            i += 1; hours = float(argv[i]) if i < len(argv) else hours
        elif a == "--json":
            as_json = True
        i += 1
    if not os.path.isdir(folder):
        print("no records folder: %s" % folder); return 1
    threats = find_threats(dr.load(folder), min_flaps=min_flaps, recent_hours=hours)

    if as_json:
        print(json.dumps(threats, indent=2)); return 0
    if not threats:
        print("No potential threats: no unknown entrances, no fast log in/out.")
        return 0
    print("Potential threats (fast log in/out, unknown entrances):")
    print("=" * 66)
    for t in threats:
        who = t["name"] or t["ip"] or t["mac"]
        print("%-16s %-15s  !! POTENTIAL THREAT" % (who, t["ip"] or t["mac"]))
        for label, detail in t["reasons"]:
            print("      - %s: %s" % (label, detail))
    print("=" * 66)
    print("%d device(s) worth a look." % len(threats))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
