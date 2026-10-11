#!/usr/bin/env python3
"""Tests for device_report.py -- the per-device feature layer.

    python3 tests/test_device_report.py
"""
import csv
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dr", os.path.join(HERE, "..", "device_report.py"))
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


PHONE = "d6:95:79:3b:1c:4a"
PI = "88:a2:9e:67:e1:72"


def row(rt, epoch, **kw):
    r = {k: "" for k in ("timestamp", "date", "time", "epoch", "record_type",
                         "category", "device_mac", "device_ip", "device_name",
                         "device_vendor", "station_label", "state", "domain",
                         "bytes_in", "bytes_out", "rate_in_kbps", "service",
                         "dst_ip", "dst_port")}
    r["epoch"] = str(epoch)
    r["record_type"] = rt
    r.update({k: str(v) for k, v in kw.items()})
    return r


print("sessions from ARRIVED/LEFT -> online time, longest, flaps:")
ev = [(100, "in"), (400, "out"), (1000, "in"), (1005, "out"), (2000, "in")]
sess = dr.sessionize(ev, end_fallback=2500)
check("three sessions incl. the still-open one", len(sess) == 3)
check("durations 300, 5, 500", [b - a for a, b in sess] == [300, 5, 500])

check("device online before recording (leading 'out') counts from first sight",
      dr.sessionize([(50, "out")], end_fallback=50) == [(50, 50)])

print("\naggregate across record types (keyed on MAC):")
rows = [
    row("tracker_event", 1000, category="ARRIVED", device_mac=PHONE, device_ip="192.168.8.135", device_name="iPhone"),
    row("device_traffic", 1100, device_mac=PHONE, device_ip="192.168.8.135", bytes_in=500000, bytes_out=20000, rate_in_kbps=8000),
    row("dns_query", 1150, category="A", device_mac=PHONE, device_ip="192.168.8.135", domain="youtube.com"),
    row("dns_query", 1160, category="A", device_mac=PHONE, device_ip="192.168.8.135", domain="youtube.com"),
    row("dns_query", 1170, category="A", device_mac=PHONE, device_ip="192.168.8.135", domain="apple.com"),
    row("flow_end", 1200, device_mac=PHONE, device_ip="192.168.8.135", bytes_in=20*1024*1024, bytes_out=1000, service="https", dst_ip="1.2.3.4"),
    row("internet_access", 1250, device_mac=PHONE, device_ip="192.168.8.135", state="GRANTED"),
    row("device_position", 1300, device_mac=PHONE, device_ip="192.168.8.135", station_label="L1"),
    row("tracker_event", 1600, category="LEFT", device_mac=PHONE, device_ip="192.168.8.135"),
    # a different device
    row("tracker_event", 1000, category="ARRIVED", device_mac=PI, device_ip="192.168.8.162", device_name="pi"),
    row("malfunction", 1200, category="device_missing", device_mac=PI, device_ip="192.168.8.162"),
    row("malfunction", 1260, category="device_back", device_mac=PI, device_ip="192.168.8.162"),
]
agg = dr.aggregate(rows)
p = agg[PHONE]
check("identity carried", p["name"] == "iPhone" and p["ip"] == "192.168.8.135")
check("online time = 600 s (1000->1600)", p["online_s"] == 600 and p["sessions"] == 1)
check("data summed, peak rate kept", p["bytes_in"] == 500000 and p["bytes_out"] == 20000
      and p["peak_rate_kbps"] == 8000)
check("browsing counted", p["dns_queries"] == 3 and p["distinct_domains"] == 2)
check("top domain is youtube", p["top_domains"][0] == ("youtube.com", 2))
check("biggest flow + large-flow count", p["biggest_flow_bytes"] == 20*1024*1024 + 1000
      and p["large_flows"] == 1 and p["biggest_flow_service"] == "https")
check("access state latest", p["access_state"] == "GRANTED")
check("node recorded", p["nodes"] == ["L1"])

pi = agg[PI]
check("pi: missing then back = 1 not-connected alert", pi["times_not_connected"] == 1)
check("pi: online before going missing counted, the missing gap excluded",
      pi["online_s"] == 200 and pi["sessions"] == 2)

print("\nfast in/out (flapping) flagged by threshold:")
flappy = [row("tracker_event", 100, category="ARRIVED", device_mac=PHONE),
          row("tracker_event", 130, category="LEFT", device_mac=PHONE),
          row("tracker_event", 200, category="ARRIVED", device_mac=PHONE),
          row("tracker_event", 900, category="LEFT", device_mac=PHONE)]
a2 = dr.aggregate(flappy, flap_seconds=120)
check("the 30 s session is a flap, the 700 s one is not", a2[PHONE]["fast_flaps"] == 1)

print("\nsorted longest-online-first; feature CSV round-trips:")
devs = sorted(agg.values(), key=lambda d: d["online_s"], reverse=True)
check("iPhone (600 s) sorts above pi (260 s)", devs[0]["mac"] == PHONE)
tmp = os.path.join(tempfile.mkdtemp(), "feats.csv")
dr.write_csv(agg, tmp)
back = list(csv.DictReader(open(tmp)))
check("csv has a row per device with the key columns",
      len(back) == 2 and set(dr.CSV_COLS) <= set(back[0])
      and back[0]["mac"] == PHONE and back[0]["online_s"] == "600")
check("nodes flattened to a string in csv", back[0]["nodes"] == "L1")

print("\nhelpers:")
check("human bytes", dr.human(1536) == "1.5 KB")
check("human duration", dr.human_dur(3660) == "1 h 1 min")

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
