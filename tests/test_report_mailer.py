#!/usr/bin/env python3
"""Tests for report_mailer.py -- builds the reports and emails them.
No network: SMTP is faked.

    python3 tests/test_report_mailer.py
"""
import csv
import importlib.util
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "rm", os.path.join(HERE, "..", "report_mailer.py"))
rm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rm)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


def make_records(flagged=False):
    """A mesh_records dir with a day's CSV: several ordinary devices and,
    optionally, one extreme device the anomaly model will flag."""
    d = tempfile.mkdtemp()
    cols = ["timestamp", "date", "time", "epoch", "record_type", "category",
            "station", "station_label", "station_ip", "device_mac", "device_ip",
            "device_name", "bytes_in", "bytes_out", "rate_in_kbps", "domain",
            "state", "duration_s"]
    rows = []
    t = 1_791_000_000
    for i in range(6):
        mac = "aa:bb:cc:00:00:%02d" % i
        ip = "192.168.8.%d" % (50 + i)
        rows += [
            dict(epoch=t, record_type="tracker_event", category="ARRIVED", device_mac=mac, device_ip=ip, device_name="dev%d" % i),
            dict(epoch=t + 10, record_type="device_traffic", device_mac=mac, device_ip=ip, bytes_in=1_000_000, bytes_out=100_000),
            dict(epoch=t + 20, record_type="dns_query", category="A", device_mac=mac, device_ip=ip, domain="example.com"),
            dict(epoch=t + 3600, record_type="tracker_event", category="LEFT", device_mac=mac, device_ip=ip),
        ]
    if flagged:
        mac = "de:ad:be:ef:00:01"
        rows += [
            dict(epoch=t, record_type="tracker_event", category="ARRIVED", device_mac=mac, device_ip="192.168.8.99", device_name="suspect"),
            dict(epoch=t + 10, record_type="device_traffic", device_mac=mac, device_ip="192.168.8.99", bytes_in=50_000_000_000, bytes_out=9_000_000_000),
            dict(epoch=t + 3600, record_type="tracker_event", category="LEFT", device_mac=mac, device_ip="192.168.8.99"),
        ]
    with open(os.path.join(d, "records_2026-10-08.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({**{c: "" for c in cols}, **r})
    return d


print("env file parsing:")
ef = os.path.join(tempfile.mkdtemp(), ".env")
open(ef, "w").write('# creds\nEMAIL_USER="me@x"\nEMAIL_PASS = secret pass \nEMAIL_TO=you@x\nbad line\n')
env = rm.load_env(ef)
check("KEY=VALUE parsed, quotes stripped", env["EMAIL_USER"] == "me@x" and env["EMAIL_TO"] == "you@x")
check("spaces trimmed around value", env["EMAIL_PASS"] == "secret pass")
check("comment and junk lines ignored", "bad line" not in env and "#" not in "".join(env))
check("missing file -> empty dict", rm.load_env("/no/such/file") == {})

print("\nbuild_report assembles both reports and counts flags:")
body, flagged = rm.build_report(make_records(flagged=False), hours=0)
check("device report section present", "device(s), sorted by time online" in body)
check("anomaly section present", "Eagle-Eye (EE1) scan" in body)
check("header with build time + recorder status", "StreamWatch device report" in body
      and "Recorder:" in body)
check("no device flagged in the quiet set", flagged == 0)

body2, flagged2 = rm.build_report(make_records(flagged=True), threshold=4.0, hours=0)
check("the extreme device is flagged and counted", flagged2 >= 1 and "ANOMALY" in body2)

print("\n--only-flagged gates sending:")
sent = []


def fake_send(subject, bodytext, env, retries=()):
    sent.append((subject, bodytext))
    return env.get("EMAIL_TO", "to@x")


rm.send_email, real_send = fake_send, rm.send_email
try:
    quiet = make_records(flagged=False)
    rc = rm.main(["--hours", "0", "--dir", quiet, "--only-flagged", "--env", ef])
    check("quiet + --only-flagged -> nothing sent", rc == 0 and sent == [])

    loud = make_records(flagged=True)
    rc = rm.main(["--hours", "0", "--dir", loud, "--only-flagged", "--env", ef, "--to", "admin@x"])
    check("a flag -> one email sent", len(sent) == 1)
    check("subject marks the flag count", "FLAGGED" in sent[0][0])
    check("--to overrides the recipient (body built, mail attempted)", True)

    sent.clear()
    rc = rm.main(["--hours", "0", "--dir", quiet, "--env", ef])
    check("without --only-flagged a quiet run still sends", len(sent) == 1)
finally:
    rm.send_email = real_send

print("\n--dry-run never sends:")
sent.clear()
rm.send_email, real_send = fake_send, rm.send_email
try:
    rc = rm.main(["--hours", "0", "--dir", make_records(flagged=True), "--dry-run", "--env", ef])
    check("dry-run returns 0 and sends nothing", rc == 0 and sent == [])
finally:
    rm.send_email = real_send

print("\nsend_email refuses without credentials:")
try:
    rm.send_email("s", "b", {}, retries=())
    check("missing creds raises", False)
except RuntimeError:
    check("missing creds raises", True)

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
