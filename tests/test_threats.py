#!/usr/bin/env python3
"""Tests for threats.py -- fast log in/out and unknown entrances. No network.

    python3 tests/test_threats.py
"""
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("th", os.path.join(HERE, "..", "threats.py"))
th = importlib.util.module_from_spec(spec)
spec.loader.exec_module(th)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


NOW = 1_791_200_000


def row(rt, t, **kw):
    r = {k: "" for k in ("epoch", "date", "record_type", "category", "device_mac",
                         "device_ip", "device_name", "bytes_in", "bytes_out", "state")}
    r["epoch"] = str(t)
    r["record_type"] = rt
    r.update({k: str(v) for k, v in kw.items()})
    return r


def arrive_leave(mac, ip, name, start, dur):
    return [row("tracker_event", start, category="ARRIVED", device_mac=mac, device_ip=ip, device_name=name),
            row("tracker_event", start + dur, category="LEFT", device_mac=mac, device_ip=ip)]


# A normal, allowed, long-online device.
NORMAL = (arrive_leave("aa:bb:cc:dd:ee:01", "192.168.8.50", "laptop", NOW - 50000, 40000)
          + [row("internet_access", NOW - 49000, device_mac="aa:bb:cc:dd:ee:01", device_ip="192.168.8.50", state="GRANTED"),
             row("device_traffic", NOW - 40000, device_mac="aa:bb:cc:dd:ee:01", device_ip="192.168.8.50", bytes_in=1_000_000)])

# A flapping device: many short sessions.
FLAP = []
for k in range(5):
    FLAP += arrive_leave("de:ad:be:ef:00:01", "192.168.8.80", "flapper", NOW - 3000 + k * 300, 20)
FLAP += [row("device_traffic", NOW - 2900, device_mac="de:ad:be:ef:00:01", device_ip="192.168.8.80", bytes_in=50_000),
         row("internet_access", NOW - 2900, device_mac="de:ad:be:ef:00:01", device_ip="192.168.8.80", state="GRANTED")]

# An unknown device held at the gate, newly arrived.
UNKNOWN = (arrive_leave("12:34:56:78:9a:bc", "192.168.8.99", "", NOW - 1800, 1200)
           + [row("internet_access", NOW - 1700, device_mac="12:34:56:78:9a:bc", device_ip="192.168.8.99", state="HELD"),
              row("device_traffic", NOW - 1700, device_mac="12:34:56:78:9a:bc", device_ip="192.168.8.99", bytes_in=5000)])


print("a normal allowed device is NOT a threat:")
t = th.find_threats(NORMAL, now=NOW)
check("nothing flagged for the laptop alone", t == [])

print("\nfast log in/out is flagged:")
t = th.find_threats(NORMAL + FLAP, min_flaps=2, now=NOW)
macs = [x["mac"] for x in t]
check("only the flapper is flagged", macs == ["de:ad:be:ef:00:01"])
labels = [lbl for lbl, _ in t[0]["reasons"]]
check("flagged for fast log in/out", "fast log in/out" in labels)
check("flap count reported", t[0]["fast_flaps"] >= 4)

print("\nunknown entrance (held at the gate) is flagged:")
t = th.find_threats(NORMAL + UNKNOWN, now=NOW)
u = next(x for x in t if x["mac"] == "12:34:56:78:9a:bc")
labels = [lbl for lbl, _ in u["reasons"]]
check("flagged as unknown entrance", "unknown entrance" in labels)
check("recent arrival noted (within 24 h)", "recent arrival" in labels and u["recent"])

print("\nseverity ordering: unknown+flapping ranks above a lone flapper:")
BAD = []
for k in range(6):
    BAD += arrive_leave("b2:ad:00:00:00:01", "192.168.8.77", "", NOW - 3000 + k * 200, 15)
BAD += [row("internet_access", NOW - 2900, device_mac="b2:ad:00:00:00:01", device_ip="192.168.8.77", state="HELD"),
        row("device_traffic", NOW - 2900, device_mac="b2:ad:00:00:00:01", device_ip="192.168.8.77", bytes_in=5000)]
t = th.find_threats(FLAP + BAD, now=NOW)
check("the held + flapping device is most severe (ranked first)",
      t[0]["mac"] == "b2:ad:00:00:00:01" and t[0]["severity"] > t[1]["severity"])

print("\n--min-flaps threshold and --hours window:")
check("raising min-flaps past the count drops the flapper",
      th.find_threats(NORMAL + FLAP, min_flaps=99, now=NOW) == [])
old = th.find_threats(NORMAL + UNKNOWN, recent_hours=0.01, now=NOW)
u2 = next(x for x in old if x["mac"] == "12:34:56:78:9a:bc")
check("outside the recent window, still a threat but not 'recent'",
      not u2["recent"] and "unknown entrance" in [l for l, _ in u2["reasons"]])

print("\ninfra is excluded (reuses device_report's client filter):")
loop = [row("dns_query", NOW - 100, category="A", device_mac="", device_ip="127.0.0.1", domain="x.com"),
        row("internet_access", NOW - 100, device_ip="127.0.0.1", state="HELD")]
check("loopback 'device' is not flagged", th.find_threats(loop, now=NOW) == [])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
