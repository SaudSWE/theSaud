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

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
