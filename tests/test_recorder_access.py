#!/usr/bin/env python3
"""Tests for the internet_access record in mesh_recorder.py (the AI CSV) and
its data-dictionary entry. No router needed: the gateway's SSH output is faked.

    python3 tests/test_recorder_access.py
"""
import csv
import importlib.util
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "mr", os.path.join(HERE, "..", "mesh_recorder.py"))
mr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mr)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


PHONE, LAPTOP, GUEST = "d6:95:79:3b:1c:4a", "aa:bb:cc:dd:ee:50", "aa:bb:cc:dd:ee:77"


def dump(allow, deny, leases):
    """What the gateway prints over SSH, cut down to the parts that matter."""
    out = ["## SYS", "UPTIME 1", "## LEASES"]
    out += ["1791417350 %s %s %s *" % (m, ip, n) for m, ip, n in leases]
    for name, body in (("allow", allow), ("deny", deny)):
        out.append("## ACL %s" % name)
        out += ["__MISSING__"] if body is None else body
    out.append("## END")
    return "\n".join(out) + "\n"


print("parsing the list files:")
d = mr.parse_router(dump(
    ["# allow list", "%s  # 192.168.8.135 added 2026-10-07T16:09:49" % PHONE, "junk"],
    [], [(PHONE, "192.168.8.135", "phone")]))
check("allow parsed by MAC with its comment",
      d["acl"]["allow"] == {PHONE: "192.168.8.135 added 2026-10-07T16:09:49"})
check("empty deny list is {} not None", d["acl"]["deny"] == {})
d2 = mr.parse_router(dump(None, None, []))
check("missing files parse as None", d2["acl"] == {"allow": None, "deny": None})

TMP = tempfile.mkdtemp()
args = types.SimpleNamespace(out=TMP, lan_prefix="192.168.8.")
r = mr.Recorder(args)


def step(t, allow, deny, leases):
    main = mr.parse_router(dump(allow, deny, leases))
    for l in main["leases"]:
        r.learn(l["mac"], l["ip"], l["name"])
    return {row["device_mac"]: row for row in r.access_rows(t, main)}


L = [(PHONE, "192.168.8.135", "phone"), (GUEST, "192.168.8.140", "guest")]

print("\nfirst look: a baseline row per device:")
rows = step(1000, ["%s  # 192.168.8.135 added 2026-10-07T16:09:49" % PHONE], [], L)
check("phone GRANTED", rows[PHONE]["state"] == "GRANTED")
check("guest (lease, no list) HELD", rows[GUEST]["state"] == "HELD")
check("category initial", rows[PHONE]["category"] == "initial")
check("timestamp + epoch filled (date and time of the access)",
      rows[PHONE]["epoch"] == 1000 and rows[PHONE]["timestamp"].startswith("1970-01-01"))
check("detail carries the time the list recorded",
      "2026-10-07T16:09:49" in rows[PHONE]["detail"])
check("device_ip/name joined from the lease",
      rows[PHONE]["device_ip"] == "192.168.8.135" and rows[PHONE]["device_name"] == "phone")
check("record_type internet_access, station main123",
      rows[PHONE]["record_type"] == "internet_access" and rows[PHONE]["station"] == "main123")

print("\nno change -> no new rows:")
check("nothing written", step(1010, ["%s  # x" % PHONE], [], L) == {})

print("\nguest approved, phone blocked (deny beats allow):")
rows = step(1020, ["%s  # x" % PHONE, "%s  # 192.168.8.140 added later" % GUEST],
            ["%s  # 192.168.8.135 set 2026-10-08T09:00:00" % PHONE], L)
check("guest HELD->GRANTED", rows[GUEST]["category"] == "HELD->GRANTED")
check("phone on both lists -> BLOCKED", rows[PHONE]["state"] == "BLOCKED"
      and rows[PHONE]["category"] == "GRANTED->BLOCKED")

print("\nguest removed from the lists and gone from leases:")
rows = step(1030, ["%s  # x" % PHONE], ["%s  # y" % PHONE], [L[0]])
check("guest GRANTED->HELD (access gone)", rows[GUEST]["category"] == "GRANTED->HELD")

print("\nno list files on the gateway -> no access rows:")
r2 = mr.Recorder(args)
check("nothing written when not gating",
      r2.access_rows(1, mr.parse_router(dump(None, None, L))) == [])

print("\ndata dictionary:")
mr.write_dictionary(TMP)
dd = list(csv.reader(open(os.path.join(TMP, "data_dictionary.csv"))))
check("data_dictionary.csv lists record_type internet_access",
      any(x[:2] == ["record_type", "internet_access"] for x in dd))
md = open(os.path.join(TMP, "DATA_DICTIONARY.md")).read()
check("DATA_DICTIONARY.md has the internet_access row", "| internet_access |" in md)
check("state column documents GRANTED/BLOCKED/HELD", "GRANTED/BLOCKED/HELD" in md)
check("analysis hint added", "Who had internet and when" in md)

print("\nrows fit the unified CSV schema:")
check("every row has exactly the schema's columns",
      all(set(row) == set(mr.FIELDS) for row in
          r.access_rows(2000, mr.parse_router(dump([], ["%s" % GUEST], L))) or [{f: "" for f in mr.FIELDS}]))

print("\ndate / time / access_time columns:")
rr = mr.rec("internet_access", 1791382158, access_time="2026-10-07T16:09:49")
check("date column = YYYY-MM-DD of timestamp", rr["date"] == rr["timestamp"][:10]
      and len(rr["date"]) == 10)
check("time column = HH:MM:SS of timestamp", rr["time"] == rr["timestamp"][11:19]
      and rr["time"].count(":") == 2)
r3 = mr.Recorder(args)
rows = {x["device_mac"]: x for x in r3.access_rows(5, mr.parse_router(dump(
    ["%s  # 192.168.8.135 added 2026-10-07T16:09:49" % PHONE], [], L)))}
check("access_time filled from the list", rows[PHONE]["access_time"] == "2026-10-07T16:09:49")
check("access_time empty for HELD", rows[GUEST]["access_time"] == "")

print("\nemails from the gateway log:")
import json as _j
lines = [_j.dumps({"t": 1791382000.5, "dir": "sent", "from": "sw@x", "to": "admin@x",
                   "subject": "[streamwatch] new device", "detail": "streamwatch - new device",
                   "id": ""}),
         _j.dumps({"t": 1791382100, "dir": "received", "from": "admin@x", "to": "sw@x",
                   "subject": "cmd", "detail": "close ['192.168.8.135']", "id": "<a@b>"}),
         _j.dumps({"t": 1791382200, "dir": "refused", "from": "evil@y", "to": "sw@x",
                   "subject": "hi", "detail": "sender not on the allowed list: open", "id": "<c@d>"}),
         "not json"]
txt = "## SYS\nUPTIME 1\n## EMAILS\n" + "\n".join(lines) + "\n## END\n"
dm = mr.parse_router(txt)
check("3 valid email lines parsed, junk skipped", len(dm["emails"]) == 3)
r4 = mr.Recorder(args)
er = r4.email_rows(dm)
check("one email row per email", len(er) == 3 and all(x["record_type"] == "email" for x in er))
check("row time is the email's own time", er[0]["epoch"] == 1791382000)
check("date/time on email rows", er[0]["date"] and er[0]["time"])
check("categories sent/received/refused",
      [x["category"] for x in er] == ["sent", "received", "refused"])
check("from/to/subject columns", er[1]["email_from"] == "admin@x"
      and er[1]["email_to"] == "sw@x" and er[1]["email_subject"] == "cmd")
check("commands in detail", "192.168.8.135" in er[1]["detail"])
check("same tail polled again -> no duplicates", r4.email_rows(dm) == [])

print("\nmid-day schema change does not misalign the CSV:")
W = tempfile.mkdtemp()
day = __import__("time").strftime("%Y-%m-%d")
old_path = os.path.join(W, "records_%s.csv" % day)
with open(old_path, "w") as f:
    f.write("timestamp,epoch,record_type\n2026,1,x\n")
w = mr.Writer(W)
w.write([mr.rec("recorder", 1, category="start")])
w.close()
hdr = next(csv.reader(open(old_path)))
check("today's file restarted with the full new header", hdr == mr.FIELDS)
check("old rows kept aside", os.path.exists(os.path.join(W, "records_%s.old1.csv" % day))
      or os.path.exists(os.path.join(W, "records_%s.old1.csv.gz" % day)))

print("\nbrowsing history (dns_query):")
import time as _tm
stamp = _tm.strftime("%a %b %d %H:%M:%S %Y", _tm.localtime(1791382300))
r5 = mr.Recorder(types.SimpleNamespace(out=TMP, lan_prefix="192.168.8.", no_dns=False,
                                       log_backfill=10 ** 10))
r5.learn(PHONE, "192.168.8.135", "iPhone")
log = ["%s daemon.info dnsmasq[1234]: query[A] www.YouTube.com from 192.168.8.135" % stamp,
       "%s daemon.info dnsmasq[1234]: forwarded www.youtube.com to 1.1.1.1" % stamp,
       "%s daemon.info dnsmasq[1234]: reply www.youtube.com is 142.250.1.1" % stamp,
       "%s daemon.info dnsmasq[1234]: query[HTTPS] api.example.org from 192.168.8.140" % stamp]
dr = r5.log_rows("main123", {"log": log})
q = [x for x in dr if x["record_type"] == "dns_query"]
check("one row per lookup (reply/forwarded noise dropped)", len(q) == 2)
check("domain column, lower-cased", q[0]["domain"] == "www.youtube.com")
check("device joined: ip, mac, name", q[0]["device_ip"] == "192.168.8.135"
      and q[0]["device_mac"] == PHONE and q[0]["device_name"] == "iPhone")
check("query type in category", [x["category"] for x in q] == ["A", "HTTPS"])
check("date/time of the lookup", q[0]["epoch"] == 1791382300 and q[0]["date"] and q[0]["time"])
check("other devices recorded too", q[1]["device_ip"] == "192.168.8.140")
check("same log polled again -> no duplicates", r5.log_rows("main123", {"log": log}) == [])

print("\ngateway switches query logging on:")
g = mr.parse_router("## SYS\nUPTIME 1\n## ACCT\nACCT 1\nDNSLOG enabled\n"
                    "LOGSIZE 64 raised to 1024\n## END\n")
check("status lines parsed", g["dnslog"] == "enabled" and g["logsize"] == "64 raised to 1024")
check("remote script switches logqueries on",
      "logqueries=1" in mr.REMOTE and "log_size=1024" in mr.REMOTE)
check("--no-dns leaves it alone", '"%(dns)s" = 1' in mr.REMOTE)
check("dictionary documents domain + browsing",
      any(c[0] == "domain" for c in mr.COLUMNS)
      and "Browsing history" in dict((r[0], r[1]) for r in mr.RECORD_TYPES)["dns_query"])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
