#!/usr/bin/env python3
"""StreamWatch's email log (feeds the email rows in the AI CSV).

    python3 tests/test_email_log.py
"""
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "sw", os.path.join(HERE, "..", "streamwatch_v12.py"))
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


sw.EMAIL_LOG = os.path.join(tempfile.mkdtemp(), "emails.log")
sw.email_log("sent", "sw@x", "admin@x", "[streamwatch] alert", "line one")
sw.email_log("received", "admin@x", "sw@x", "cmd", "close ['1.2.3.4']", "<id>")
rows = [json.loads(l) for l in open(sw.EMAIL_LOG)]
check("two JSON lines", len(rows) == 2)
check("fields present", set(rows[0]) == {"t", "dir", "from", "to", "subject", "detail", "id"})
check("time recorded", abs(rows[0]["t"] - __import__("time").time()) < 5)
check("direction kept", [r["dir"] for r in rows] == ["sent", "received"])
sw.email_log("sent", "a", "b", "s" * 999, "d" * 999)
last = json.loads(open(sw.EMAIL_LOG).readlines()[-1])
check("subject/detail truncated", len(last["subject"]) == 200 and len(last["detail"]) == 300)
sw.EMAIL_LOG_KEEP = 5
for i in range(40):
    sw.email_log("sent", "a", "b", "subj %d" % i, "x" * 290)
n = len(open(sw.EMAIL_LOG).readlines())
check("log is bounded", n <= 5 + 6)
check("first-line helper", sw._first_line("\n\n  hello\nworld") == "hello")
print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
