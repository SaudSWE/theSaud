#!/usr/bin/env python3
"""Tests for history.py -- the readable activity-history viewer.

    python3 tests/test_history.py
"""
import csv
import gzip
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "history", os.path.join(HERE, "..", "history.py"))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


def row(rt, epoch, **kw):
    r = {"timestamp": "", "date": "", "time": "", "epoch": str(epoch),
         "record_type": rt, "category": "", "state": "", "device_name": "",
         "device_ip": "", "device_mac": "", "station": "", "station_label": "",
         "domain": "", "detail": "", "email_subject": "", "proto": "",
         "dst_port": "", "service": ""}
    r.update(kw)
    return r


print("which rows count as activity:")
check("internet_access kept", h.keep_event(row("internet_access", 1)))
check("malfunction kept", h.keep_event(row("malfunction", 1)))
check("email kept", h.keep_event(row("email", 1)))
check("dhcp_lease kept", h.keep_event(row("dhcp_lease", 1)))
check("device_position dropped", not h.keep_event(row("device_position", 1)))
check("flow_end dropped", not h.keep_event(row("flow_end", 1)))
check("router_log dropped", not h.keep_event(row("router_log", 1)))

print("\ntracker: real moves kept, distance jitter dropped:")
check("ARRIVED kept", h.keep_event(row("tracker_event", 1, category="ARRIVED")))
check("LEFT kept", h.keep_event(row("tracker_event", 1, category="LEFT")))
check("IDLE dropped", not h.keep_event(row("tracker_event", 1, category="IDLE", state="IDLE")))
check("APPROACHING dropped",
      not h.keep_event(row("tracker_event", 1, category="APPROACHING L1", state="APPROACHING L1")))
check("LEAVING dropped",
      not h.keep_event(row("tracker_event", 1, category="LEAVING L1", state="LEAVING L1")))
check("a forbidden-zone event is kept whatever its state",
      h.keep_event(row("tracker_event", 1, category="FORBIDDEN", state="BLOCKED")))

print("\nbrowsing only when asked:")
check("dns_query dropped by default", not h.keep_event(row("dns_query", 1)))
check("dns_query kept with --browsing", h.keep_event(row("dns_query", 1, domain="x.com"), browsing=True))
check("--all keeps even device_position", h.keep_event(row("device_position", 1), show_all=True))

print("\ndate/time falls back to the ISO timestamp (old-schema rows):")
check("uses date/time when present", h.when(row("x", 1, date="2026-10-08", time="13:00:00")) == ("2026-10-08", "13:00:00"))
check("falls back to timestamp when blank",
      h.when(row("x", 1, timestamp="2026-10-07T15:28:01+03:00")) == ("2026-10-07", "15:28:01"))

print("\nhourly port inventory collapses to each port's first sighting:")
rows = [row("open_port", 10, station_label="L1", proto="tcp", dst_port="22", service="ssh", state="LISTEN"),
        row("open_port", 20, station_label="L1", proto="tcp", dst_port="22", service="ssh", state="LISTEN"),
        row("open_port", 30, station_label="L1", proto="tcp", dst_port="22", service="ssh", state="LISTEN"),
        row("open_port", 40, station_label="L1", proto="tcp", dst_port="53", service="dns", state="LISTEN")]
ev = h.events(rows)
check("30 repeats -> one row per distinct port", len(ev) == 2
      and [e["dst_port"] for e in ev] == ["22", "53"])
check("--all keeps every repeat", len(h.events(rows, show_all=True)) == 4)
check("port detail shows proto/port/service", h.detail_of(ev[0]) == "tcp/22 ssh")

print("\nsorted oldest-first and filterable by device:")
mixed = [row("email", 300, email_subject="late"),
         row("internet_access", 100, device_name="iPhone", device_ip="192.168.8.135", state="GRANTED"),
         row("malfunction", 200, device_name="pi", device_ip="192.168.8.162", state="MISSING")]
ev = h.events(mixed)
check("time ordered", [e["epoch"] for e in ev] == ["100", "200", "300"])
check("filter by ip", [e["record_type"] for e in h.events(mixed, match=["192.168.8.135"])] == ["internet_access"])
check("filter by name", [e["record_type"] for e in h.events(mixed, match=["pi"])] == ["malfunction"])

print("\nreads .csv and .csv.gz from a folder:")
d = tempfile.mkdtemp()
with open(os.path.join(d, "records_2026-10-07.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(row("x", 1).keys()))
    w.writeheader()
    w.writerow(row("internet_access", 100, device_name="iPhone", state="GRANTED"))
with gzip.open(os.path.join(d, "records_2026-10-06.csv.gz"), "wt", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(row("x", 1).keys()))
    w.writeheader()
    w.writerow(row("malfunction", 50, state="DOWN"))
loaded = h.load(d)
check("both files read, gz included, sorted", [r["epoch"] for r in loaded] == ["50", "100"])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
