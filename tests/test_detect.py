#!/usr/bin/env python3
"""Item 9 -- malfunction detection: internet outages (with history) and
devices that should be present going missing. No router needed.

    python3 tests/test_detect.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", file))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sw = load("sw", "streamwatch_v12.py")
mr = load("mr", "mesh_recorder.py")
PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


print("outage detection (3 misses = DOWN, dated from the first miss):")
m = sw.OutageMonitor(fail_n=3)
check("up -> nothing", m.step(100, True) is None)
check("1st miss -> nothing yet", m.step(110, False) is None)
check("2nd miss -> nothing yet", m.step(120, False) is None)
ev = m.step(130, False)
check("3rd miss -> internet_down", ev and ev["kind"] == "internet_down")
check("dated from first failed probe", ev["t"] == 110 and ev["confirmed_at"] == 130)
check("further misses -> no repeat alert", m.step(140, False) is None)
ev = m.step(560, True)
check("back -> internet_up", ev and ev["kind"] == "internet_up")
check("outage length = 450 s", ev["duration_s"] == 450 and ev["down_since"] == 110)
check("steady up -> nothing", m.step(570, True) is None)

print("\none or two blips are not an outage:")
m = sw.OutageMonitor(fail_n=3)
check("miss, miss, ok -> no event",
      [m.step(1, False), m.step(2, False), m.step(3, True)] == [None, None, None])
check("counter reset after recovery", m.step(4, False) is None and m.step(5, False) is None)

print("\ndevice not connected:")
p = sw.PresenceMonitor(missing_after=300)
A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
check("both present -> nothing", p.step(0, {A, B}, {A, B}) == [])
check("A gone 200 s -> still within grace", p.step(200, {A, B}, {B}) == [])
ev = p.step(300, {A, B}, {B})
check("A gone 300 s -> device_missing", len(ev) == 1 and ev[0]["kind"] == "device_missing"
      and ev[0]["mac"] == A and ev[0]["last_seen"] == 0)
check("no repeat while still missing", p.step(400, {A, B}, {B}) == [])
ev = p.step(900, {A, B}, {A, B})
check("A back -> device_back with how long", ev[0]["kind"] == "device_back"
      and ev[0]["duration_s"] == 900)
check("newly watched device gets a grace period", p.step(901, {A, B, "cc"}, {A, B}) == [])
p.step(1300, {A, B, "cc"}, {A, B})
check("removing a missing device from the list forgets it",
      p.step(1301, {A, B}, {A, B}) == [] and "cc" not in p.missing)

print("\nhealth log:")
sw.HEALTH_LOG = os.path.join(tempfile.mkdtemp(), "health.log")
sw.health_log("internet_down", t=110, detail="no answer")
sw.health_log("internet_up", t=560, duration_s=450, detail="down from a to b")
lines = [json.loads(x) for x in open(sw.HEALTH_LOG)]
check("two JSON events with their own times",
      [(x["kind"], x["t"]) for x in lines] == [("internet_down", 110), ("internet_up", 560)])
check("human duration", sw.human_dur(450) == "7 min 30 s" and sw.human_dur(3725) == "1 h 2 min")
sw.wifi_rssi_map = lambda ttl=5: {"aa:bb:cc:dd:ee:09": {}}
sw.run = lambda cmd, timeout=5: (
    "192.168.8.5 dev br-lan lladdr aa:bb:cc:dd:ee:05 REACHABLE\n"
    "192.168.8.6 dev br-lan lladdr aa:bb:cc:dd:ee:06 STALE\n")
check("radio + REACHABLE counted, STALE not",
      sw.present_macs() == {"aa:bb:cc:dd:ee:09", "aa:bb:cc:dd:ee:05"})

print("\nAI CSV malfunction rows:")
dump = "## SYS\nUPTIME 1\n## HEALTH\n" + "\n".join(json.dumps(x) for x in [
    {"t": 1791382000, "kind": "internet_down", "detail": "no answer"},
    {"t": 1791382450, "kind": "internet_up", "duration_s": 450, "detail": "down from x to y"},
    {"t": 1791382600, "kind": "device_missing", "mac": "d6:95:79:3b:1c:4a",
     "ip": "192.168.8.135", "name": "iPhone", "detail": "not seen since z"},
]) + "\n## END\n"
d = mr.parse_router(dump)
r = mr.Recorder(types.SimpleNamespace(out=tempfile.mkdtemp(), lan_prefix="192.168.8."))
rows = r.health_rows(d)
check("one malfunction row per event", [x["record_type"] for x in rows] == ["malfunction"] * 3)
check("states DOWN / UP / MISSING", [x["state"] for x in rows] == ["DOWN", "UP", "MISSING"])
check("outage row carries the duration", rows[1]["duration_s"] == 450)
check("rows dated by the event, with date/time", rows[0]["epoch"] == 1791382000
      and rows[0]["date"] and rows[0]["time"])
check("device columns on device rows", rows[2]["device_mac"] == "d6:95:79:3b:1c:4a"
      and rows[2]["device_name"] == "iPhone")
check("polled again -> no duplicates", r.health_rows(d) == [])
check("dictionary documents malfunction",
      "malfunction" in dict((x[0], x[1]) for x in mr.RECORD_TYPES))

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
