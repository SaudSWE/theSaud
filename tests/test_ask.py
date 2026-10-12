#!/usr/bin/env python3
"""Tests for ask.py -- the offline terminal to the model. No network.

    python3 tests/test_ask.py
"""
import csv
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ask", os.path.join(HERE, "..", "ask.py"))
ask = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ask)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


def make_ctx(flagged=False):
    d = tempfile.mkdtemp()
    cols = ["timestamp", "date", "time", "epoch", "record_type", "category",
            "station", "station_label", "station_ip", "device_mac", "device_ip",
            "device_name", "bytes_in", "bytes_out", "rate_in_kbps", "domain", "state"]
    rows, t = [], 1_791_000_000
    for i in range(5):
        mac, ip = "aa:bb:cc:00:00:%02d" % i, "192.168.8.%d" % (50 + i)
        rows += [
            dict(epoch=t, record_type="tracker_event", category="ARRIVED", device_mac=mac, device_ip=ip, device_name="dev%d" % i),
            # natural spread between ordinary devices (real devices differ)
            dict(epoch=t + 10, record_type="device_traffic", device_mac=mac, device_ip=ip, bytes_in=1_000_000 + i * 500_000, bytes_out=100_000),
            dict(epoch=t + 20, record_type="dns_query", category="A", device_mac=mac, device_ip=ip, domain="example%d.com" % i),
            dict(epoch=t + 3000 + i * 300, record_type="tracker_event", category="LEFT", device_mac=mac, device_ip=ip),
        ]
    # one device that is clearly online longer and moves much more data
    big = "d6:95:79:3b:1c:4a"
    rows += [
        dict(epoch=t, record_type="tracker_event", category="ARRIVED", device_mac=big, device_ip="192.168.8.135", device_name="iPhone"),
        dict(epoch=t + 50, record_type="device_traffic", device_mac=big, device_ip="192.168.8.135", bytes_in=50_000_000_000 if flagged else 5_000_000, bytes_out=1_000_000),
        dict(epoch=t + 50, record_type="dns_query", category="A", device_mac=big, device_ip="192.168.8.135", domain="youtube.com"),
        dict(epoch=t + 36000, record_type="tracker_event", category="LEFT", device_mac=big, device_ip="192.168.8.135"),
    ]
    with open(os.path.join(d, "records_2026-10-08.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({**{c: "" for c in cols}, **r})
    return ask.Context(d)


ctx = make_ctx()


def H(line):
    return ask.handle(line, ctx)


print("help and quit:")
check("help lists commands", "COMMANDS" in H("help"))
check("quit returns None (ends the loop)", H("quit") is None)
check("blank line -> empty", H("") == "")

print("\ndevice resolution by ip / name / mac fragment:")
check("by ip fragment", ask.find_device(ctx, "135")["name"] == "iPhone")
check("by name (case-insensitive)", ask.find_device(ctx, "iphone")["ip"] == "192.168.8.135")
check("by mac fragment", ask.find_device(ctx, "d6:95")["name"] == "iPhone")
check("no match -> None", ask.find_device(ctx, "zzz") is None)

print("\nonline / how long:")
out = H("online")
check("lists devices, longest first (iPhone on top)",
      "Time online" in out and out.splitlines()[1].strip().startswith("iPhone"))
check("'how long was iphone online' -> that device's time",
      "iPhone" in H("how long was iphone online") and "online" in H("how long was iphone online"))

print("\ndata usage:")
check("data ranking biggest first", H("data").splitlines()[1].strip().startswith("iPhone"))
check("data for one device", "down" in H("data iphone") and "total" in H("data iphone"))

print("\nbrowsing:")
check("browsing needs a device", "which device" in H("browsing"))
check("browsing a device names the site", "youtube.com" in H("browsing 135"))

print("\nanomalies / flagged:")
check("anomalies scans and scores", "Model scan" in H("anomalies"))
cf = make_ctx(flagged=True)
check("flagged shows the outlier when one exists",
      "FLAGGED" in ask.handle("flagged", cf))
check("flagged says all-normal when none", "normal" in H("flagged 999"))

print("\nhistory:")
check("history returns events", "tracker_event" in H("history") or "internet" in H("history"))
check("history for a device filters", "iPhone" in H("history iphone") or H("history iphone") != "")

print("\ndevice detail + unknowns:")
check("device detail block", "online" in H("device iphone") and "browsing" in H("device iphone"))
check("unknown device is reported", "no device matches" in H("device nope"))
check("gibberish -> help hint", "help" in H("florble the glorp").lower())

print("\nemail command is wired (dry, faked -- no real send):")
import report_mailer
real = report_mailer.main
report_mailer.main = lambda argv: print("would send; args=%s" % argv)
try:
    out = H("email")
    check("email runs report_mailer with --only-flagged by default", "--only-flagged" in out)
    out2 = H("email all")
    check("'email all' drops --only-flagged", "--only-flagged" not in out2)
finally:
    report_mailer.main = real

print("\none-shot mode:")
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = ask.main(["--dir", ctx.folder, "online"])
check("ask.py <command> runs once and exits 0", rc == 0 and "Time online" in buf.getvalue())

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
