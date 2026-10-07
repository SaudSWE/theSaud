#!/usr/bin/env python3
"""Tests for group_lists.py -- allow/deny file management. No router needed:
the IP->MAC resolver is stubbed, so add/remove/reject/classify logic is
checked exactly.

    python3 tests/test_group_lists.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "gl", os.path.join(HERE, "..", "group_lists.py"))
gl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gl)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


# stub resolver: these IPs have MACs, others do not (device unknown)
MAP = {"192.168.8.50": "aa:bb:cc:dd:ee:50",
       "192.168.8.60": "aa:bb:cc:dd:ee:60"}
res = lambda ip: MAP.get(ip)

TMP = tempfile.mkdtemp()
ALLOW = os.path.join(TMP, "allow.txt")
DENY = os.path.join(TMP, "deny.txt")


def reset():
    for p in (ALLOW, DENY):
        try:
            os.remove(p)
        except OSError:
            pass


print("resolve:")
check("MAC passes through", gl.resolve("AA:BB:CC:DD:EE:50", res)[0] == "aa:bb:cc:dd:ee:50")
check("IP resolves to MAC", gl.resolve("192.168.8.50", res) == ("aa:bb:cc:dd:ee:50", "192.168.8.50"))
try:
    gl.resolve("192.168.8.99", res)
    check("unknown IP raises", False)
except ValueError:
    check("unknown IP raises", True)
try:
    gl.resolve("999.1.1.1", res)
    check("bad IP raises", False)
except ValueError:
    check("bad IP raises", True)
try:
    gl.resolve("not-a-thing", res)
    check("garbage raises", False)
except ValueError:
    check("garbage raises", True)

print("\nadd to allow file:")
reset()
a = gl.GroupList(ALLOW)
r = a.add("192.168.8.50", res)
check("add announced", r.startswith("*** 192.168.8.50 (aa:bb:cc:dd:ee:50) ADDED"))
check("stored by MAC", list(a.load()) == ["aa:bb:cc:dd:ee:50"])
check("IP kept as comment", "192.168.8.50" in a.load()["aa:bb:cc:dd:ee:50"])
check("file is mode 600", oct(os.stat(ALLOW).st_mode & 0o777) == "0o600")
r = a.add("192.168.8.50", res)
check("duplicate not re-added", "already in" in r and len(a.load()) == 1)
r = a.add("aa:bb:cc:dd:ee:60", res)
check("bare MAC accepted", "aa:bb:cc:dd:ee:60" in a.load())

print("\nreject what cannot be identified ('otherwise reject it'):")
r = a.add("192.168.8.99", res)
check("unknown IP rejected", "REJECTED" in r and "no MAC known" in r)
check("rejected entry not written", "192.168.8.99" not in open(ALLOW).read())
r = a.add("garbage", res)
check("garbage rejected", "REJECTED" in r)
check("still two good entries", len(a.load()) == 2)

print("\nremove from allow file:")
r = a.remove("192.168.8.50", res)
check("remove announced", "REMOVED" in r)
check("gone from file", "aa:bb:cc:dd:ee:50" not in a.load())
r = a.remove("192.168.8.50", res)
check("removing absent is reported, not an error", "was not in" in r)
# a device whose lease is gone: resolver returns None, but admin can name MAC
r = a.remove("aa:bb:cc:dd:ee:60", res)
check("remove by bare MAC works", "REMOVED" in r and len(a.load()) == 0)

print("\ncomments and blank lines survive a round-trip:")
reset()
with open(ALLOW, "w") as f:
    f.write("# header comment\n\naa:bb:cc:dd:ee:50  # 192.168.8.50 phone\n")
a = gl.GroupList(ALLOW)
check("parses MAC past comments", list(a.load()) == ["aa:bb:cc:dd:ee:50"])
a.add("192.168.8.60", res)
check("second add keeps first", set(a.load()) == {"aa:bb:cc:dd:ee:50", "aa:bb:cc:dd:ee:60"})

print("\nclassify (Model A, deny beats allow):")
reset()
gl.GroupList(ALLOW).add("192.168.8.50", res)
check("allow-listed -> allow", gl.classify("192.168.8.50", res, ALLOW, DENY) == "allow")
check("unlisted -> hold", gl.classify("192.168.8.60", res, ALLOW, DENY) == "hold")
gl.GroupList(DENY).add("192.168.8.60", res)
check("deny-listed -> deny", gl.classify("192.168.8.60", res, ALLOW, DENY) == "deny")
gl.GroupList(DENY).add("192.168.8.50", res)       # now on BOTH
check("on both -> deny wins (BR-2)", gl.classify("192.168.8.50", res, ALLOW, DENY) == "deny")

print("\natomic save leaves no .tmp behind:")
check("no tmp file", not os.path.exists(ALLOW + ".tmp"))

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
