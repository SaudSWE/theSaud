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
check("repeated 'out' while offline adds no overlapping session",
      dr.sessionize([(0, "in"), (100, "out"), (200, "out"), (300, "out")],
                    end_fallback=300) == [(0, 100)])

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


print("\ntime window (since): counts only recent rows, clips sessions:")
w = dr.aggregate(rows, since=1250)
wp, wpi = w[PHONE], w[PI]
check("session clipped to window (1250->1600 = 350 s)", wp["online_s"] == 350 and wp["sessions"] == 1)
check("rows before the window not counted", wp["bytes_total"] == 0 and wp["dns_queries"] == 0
      and wp["large_flows"] == 0)
check("rows inside the window counted", wp["access_state"] == "GRANTED" and wp["nodes"] == ["L1"])
check("missing before the window not counted", wpi["times_not_connected"] == 0)
on = dr.aggregate([row("tracker_event", 0, category="ARRIVED", device_mac=PI),
                   row("device_traffic", 5000, device_mac=PI, bytes_in=1)], since=4000)
check("online since before the window counts from window start", on[PI]["online_s"] == 1000)
check("no window = all time (unchanged)", dr.aggregate(rows, since=None)[PHONE]["online_s"] == 600)
check("device first seen before the window is not new", wp["new_device"] == 0)
nw = dr.aggregate([row("tracker_event", 5000, category="ARRIVED", device_mac=PHONE)], since=4000)
check("device first seen inside the window is new", nw[PHONE]["new_device"] == 1)
check("no window -> nothing is 'new'", dr.aggregate(rows)[PHONE]["new_device"] == 0)
br = dr.aggregate([row("tracker_event", t, category=c, device_mac=PI) for t, c in
                   [(0, "ARRIVED"), (10, "LEFT"), (20, "ARRIVED"), (25, "LEFT"),
                    (5000, "ARRIVED"), (5030, "LEFT"), (9000, "ARRIVED")]])
check("burst = fast in/outs within 10 min (2), not the day's total (3)",
      br[PI]["fast_flaps"] == 3 and br[PI]["flap_burst"] == 2)
wl = dr.aggregate([row("router_log", 100, device_mac=PI, link_state="AP-STA-CONNECTED"),
                   row("router_log", 116, device_mac=PI, link_state="AP-STA-DISCONNECTED")])
check("router Wi-Fi connect/disconnect counts as a session", wl[PI]["sessions"] == 1
      and wl[PI]["online_s"] == 16 and wl[PI]["fast_flaps"] == 1)
check("a device that just connected (still online) is not a fast in/out",
      dr.aggregate([row("tracker_event", 50, category="ARRIVED", device_mac=PI)])[PI]["fast_flaps"] == 0)
check("since_hours(0) = all time", dr.since_hours(0) is None and dr.window_label(0) == "all time")

print("\nfast in/out (flapping) flagged by threshold:")
flappy = [row("tracker_event", 100, category="ARRIVED", device_mac=PHONE),
          row("tracker_event", 130, category="LEFT", device_mac=PHONE),
          row("tracker_event", 200, category="ARRIVED", device_mac=PHONE),
          row("tracker_event", 900, category="LEFT", device_mac=PHONE)]
a2 = dr.aggregate(flappy, flap_seconds=120)
check("the 30 s session is a flap, the 700 s one is not", a2[PHONE]["fast_flaps"] == 1)

print("\nsorted longest-online-first; feature CSV round-trips:")
devs = dr.select(agg)
check("iPhone (600 s) sorts above pi (260 s)", devs[0]["mac"] == PHONE)
tmp = os.path.join(tempfile.mkdtemp(), "feats.csv")
dr.write_csv(devs, tmp)
back = list(csv.DictReader(open(tmp)))
check("csv has a row per device with the key columns",
      len(back) == 2 and set(dr.CSV_COLS) <= set(back[0])
      and back[0]["mac"] == PHONE and back[0]["online_s"] == "600")
check("nodes flattened to a string in csv", back[0]["nodes"] == "L1")

print("\ninfrastructure and non-addresses are filtered out:")
check("loopback dropped", not dr.is_client({"ip": "127.0.0.1", "mac": "127.0.0.1"}))
check("network address .0 dropped", not dr.is_client({"ip": "192.168.8.0", "mac": "192.168.8.0"}))
check("broadcast .255 dropped", not dr.is_client({"ip": "192.168.8.255", "mac": "192.168.8.255"}))
check("null MAC dropped", not dr.is_client({"ip": "192.168.8.9", "mac": "00:00:00:00:00:00"}))
check("multicast MAC dropped", not dr.is_client({"ip": "192.168.8.9", "mac": "01:00:5e:00:00:fb"}))
check("a node's own self-traffic dropped",
      not dr.is_client({"ip": "192.168.8.1", "mac": "192.168.8.1"}, stations={"192.168.8.1"}))
check("a real client is kept", dr.is_client({"ip": "192.168.8.135", "mac": PHONE}))
check("a randomised (locally-administered) phone MAC is kept",
      dr.is_client({"ip": "192.168.8.131", "mac": "6a:44:f8:04:25:aa"}))
check("the Pi keeps its entry even though its IP is a station IP (it has a real MAC)",
      dr.is_client({"ip": "192.168.8.162", "mac": PI}, stations={"192.168.8.162"}))

print("\nzero-signal identities dropped unless --all-devices:")
quiet = {"online_s": 0, "bytes_total": 0, "dns_queries": 0, "sessions": 0, "access_state": ""}
busy = {"online_s": 0, "bytes_total": 5, "dns_queries": 0, "sessions": 0, "access_state": ""}
check("no signal -> dropped", not dr.has_signal(quiet))
check("any bytes -> kept", dr.has_signal(busy))
noise = {"88:a2:9e:67:e1:70": dict(agg[PI], mac="88:a2:9e:67:e1:70", ip="", online_s=0,
                                   bytes_total=0, dns_queries=0, sessions=0, access_state=""),
         PHONE: agg[PHONE]}
check("select() hides the quiet identity, --all-devices shows it",
      [d["mac"] for d in dr.select(noise)] == [PHONE]
      and len(dr.select(noise, show_all=True)) == 2)

print("\ncomma-joined MAC keyed on the first; absurd rate ignored:")
check("two-MAC field keys on the first MAC",
      dr.key_of({"device_mac": "88:a2:9e:67:e1:70,88:a2:9e:67:e1:72"}) == "88:a2:9e:67:e1:70")
glitch = dr.aggregate([
    row("device_traffic", 100, device_mac=PHONE, rate_in_kbps=40000),
    row("device_traffic", 110, device_mac=PHONE, rate_in_kbps=3473852)])   # 3.4 Gbps glitch
check("peak rate ignores the impossible 3.4 Gbps sample",
      glitch[PHONE]["peak_rate_kbps"] == 40000)

print("\nsurvives a stray header row mixed into the data (clock-jump artifact):")
header_like = {"epoch": "epoch", "record_type": "record_type", "device_mac": "device_mac"}
date_shift = {"epoch": "date", "record_type": "time"}   # old-schema header read shifted
mixed = [header_like, date_shift,
         row("device_traffic", 500, device_mac=PHONE, device_ip="192.168.8.135", bytes_in=1000)]
check("epoch_of flags non-numeric rows", dr.epoch_of(header_like) is None
      and dr.epoch_of(date_shift) is None and dr.epoch_of(mixed[2]) == 500)
a3 = dr.aggregate(mixed)
check("aggregate skips them, keeps the real row", list(a3) == [PHONE]
      and a3[PHONE]["bytes_in"] == 1000)

D = tempfile.mkdtemp()
with open(os.path.join(D, "records_2026-10-07.csv"), "w", newline="") as f:
    cols = list(row("x", 1).keys())
    w = csv.writer(f)
    w.writerow(cols)                                   # header
    w.writerow([row("device_traffic", 100, device_mac=PHONE, bytes_in=5)[c] for c in cols])
    w.writerow(cols)                                   # a SECOND header, mid-file
    w.writerow([row("device_traffic", 200, device_mac=PHONE, bytes_in=5)[c] for c in cols])
loaded = dr.load(D)
check("load drops the mid-file header, keeps both data rows",
      [r["epoch"] for r in loaded] == ["100", "200"])

print("\nhelpers:")
check("human bytes", dr.human(1536) == "1.5 KB")
check("human duration", dr.human_dur(3660) == "1 h 1 min")

print("\nend to end: phone drops Wi-Fi twice in a minute -> model says THREAT:")
spec = importlib.util.spec_from_file_location("am", os.path.join(HERE, "..", "eagle_eye.py"))
am = importlib.util.module_from_spec(spec)
spec.loader.exec_module(am)


def ap(epoch, state):
    return row("router_log", epoch, link_state="AP-STA-" + state, device_mac=PHONE, device_name="iPhone")


# online an hour, then off/on twice within ~20 s, then stays on
flaps = [ap(0, "CONNECTED"), ap(3600, "DISCONNECTED"), ap(3605, "CONNECTED"),
         ap(3610, "DISCONNECTED"), ap(3615, "CONNECTED"), ap(3620, "DISCONNECTED"),
         ap(3625, "CONNECTED"), ap(7200, "DISCONNECTED")]
ranked, _ = am.rank(list(dr.aggregate(flaps).values()))
check("raw AP-STA flaps -> THREAT on the phone",
      ranked[0]["mac"] == PHONE and any("sudden log-ins" in t for t in ranked[0]["threats"]))
calm_phone = [ap(0, "CONNECTED"), ap(3600, "DISCONNECTED"), ap(4000, "CONNECTED"), ap(7200, "DISCONNECTED")]
check("one normal reconnect -> no threat",
      not am.rank(list(dr.aggregate(calm_phone).values()))[0][0]["threats"])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
