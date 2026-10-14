#!/usr/bin/env python3
"""Tests for eagle_eye.py (Eagle-Eye) -- the offline robust anomaly detector.

    python3 tests/test_eagle_eye.py
"""
import csv
import importlib.util
import math
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "am", os.path.join(HERE, "..", "eagle_eye.py"))
am = importlib.util.module_from_spec(spec)
spec.loader.exec_module(am)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


def dev(**kw):
    r = {c: "0" for c, _ in am.FEATURES}
    r["mac"] = kw.pop("mac", "aa:bb:cc:dd:ee:00")
    r["ip"] = kw.pop("ip", "")
    r["name"] = kw.pop("name", "")
    r.update({k: str(v) for k, v in kw.items()})
    return r


print("robust statistics:")
check("median odd", am.median([3, 1, 2]) == 2)
check("median even", am.median([1, 2, 3, 4]) == 2.5)
check("value log-scales when asked", abs(am.value({"x": "99"}, "x", True) - math.log1p(99)) < 1e-9)
check("non-numeric -> None", am.value({"x": "n/a"}, "x", False) is None)

print("\nfit learns median + robust sigma per feature:")
rows = [dev(sessions=s) for s in (4, 5, 5, 6, 5, 5, 4, 6)]
m = am.fit(rows)
check("median learned", m["sessions"]["median"] == 5)
check("sigma positive", m["sessions"]["sigma"] > 0)

print("\na clear outlier is flagged, with the right reason:")
# eight ordinary devices, one that transfers and flaps far more than the rest
normal = [dev(mac="n%d" % i, name="normal%d" % i, online_s=3600, sessions=3,
              bytes_total=50_000_000, fast_flaps=0, dns_queries=200)
          for i in range(8)]
odd = dev(mac="odd", name="suspect", online_s=3600, sessions=3,
          bytes_total=50_000_000_000, fast_flaps=40, dns_queries=200)
ranked, model = am.rank(normal + [odd], threshold=4.0)
check("the outlier ranks first", ranked[0]["name"] == "suspect")
check("it is flagged", ranked[0]["anomaly"] is True)
check("none of the normal devices is flagged",
      all(not d["anomaly"] for d in ranked if d["name"] != "suspect"))
reasons = dict(ranked[0]["reasons"])
check("bytes_total named as a reason, high", "bytes_total" in reasons and reasons["bytes_total"] > 0)
check("fast_flaps named as a reason, high", "fast_flaps" in reasons and reasons["fast_flaps"] > 0)

print("\nhigh side only: a quiet (below-median) device is NOT an anomaly:")
busy = [dev(mac="b%d" % i, name="busy%d" % i, bytes_total=500_000_000,
            large_flows=20, dns_queries=400, online_s=20000)
        for i in range(8)]
quiet = dev(mac="quiet", name="quiet", bytes_total=100, large_flows=0,
            dns_queries=0, online_s=60)
rq, _ = am.rank(busy + [quiet], threshold=4.0)
qd = next(d for d in rq if d["name"] == "quiet")
check("the quiet device is not flagged", not qd["anomaly"])
check("its score is ~0, not a huge negative-driven number", qd["score"] <= 1.0)
check("no 'low' reasons are reported", all(z > 0 for _, z in qd["reasons"]))

print("\nlog-scaling: a merely heavy (not extreme) user is not auto-flagged:")
# heavy-tailed bytes: most small, a few large, one 3x the largest
heavy = [dev(mac="h%d" % i, bytes_total=b) for i, b in enumerate(
    [1e6, 2e6, 3e6, 5e6, 8e6, 1.2e7, 2e7, 4e7])]
heavy_user = dev(mac="heavy", name="heavy", bytes_total=1.2e8)   # 3x the top
r2, _ = am.rank(heavy + [heavy_user], threshold=4.0)
check("the heavy-but-not-extreme user is not flagged at 4 sigma",
      not next(d for d in r2 if d["name"] == "heavy")["anomaly"])

print("\nthreshold controls sensitivity:")
r3, _ = am.rank(normal + [odd], threshold=100.0)
check("nothing flagged by score when the bar is very high (40 fast in/out is still a THREAT)",
      not any(d["score"] >= 100.0 for d in r3) and [d["anomaly"] for d in r3] == [bool(d["threats"]) for d in r3])

print("\nMAD=0 fallback (near-constant feature with one spike):")
spike = [dev(mac="s%d" % i, blocked_times=0) for i in range(9)] + \
        [dev(mac="spike", name="spike", blocked_times=25)]
r4, _ = am.rank(spike, threshold=4.0)
check("the lone spike is still caught despite MAD=0",
      r4[0]["name"] == "spike" and r4[0]["anomaly"])

print("\nreads a features.csv written in device_report's format:")
cols = ["mac", "ip", "name", "vendor", "first_seen", "last_seen", "sessions",
        "online_s", "longest_session_s", "fast_flaps", "bytes_in", "bytes_out",
        "bytes_total", "peak_rate_kbps", "dns_queries", "distinct_domains",
        "biggest_flow_bytes", "biggest_flow_service", "large_flows",
        "access_state", "blocked_times", "nodes", "times_not_connected"]
tmp = os.path.join(tempfile.mkdtemp(), "features.csv")
with open(tmp, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for i in range(6):
        w.writerow({**{c: 0 for c in cols}, "mac": "d%d" % i, "name": "dev%d" % i,
                    "bytes_total": 10_000_000, "sessions": 2})
    w.writerow({**{c: 0 for c in cols}, "mac": "bad", "name": "bad",
                "bytes_total": 10_000_000_000, "sessions": 2, "fast_flaps": 30})
loaded = am.load_features(tmp)
check("csv loaded, all rows kept", len(loaded) == 7)
ranked2, _ = am.rank(loaded)
check("the odd device from the csv is ranked first and flagged",
      ranked2[0]["name"] == "bad" and ranked2[0]["anomaly"])

print("\ndeterministic:")
a = am.rank(normal + [odd])[0]
b = am.rank(normal + [odd])[0]
check("same input -> same ranking and scores",
      [(d["mac"], d["score"]) for d in a] == [(d["mac"], d["score"]) for d in b])

print("\nthreat rule: sudden log-ins flagged regardless of the baseline:")
calm = {"mac": "aa:00:00:00:00:%02x", "fast_flaps": "0", "new_device": "0", "online_s": "3600"}
herd = [dict(calm, mac=calm["mac"] % i) for i in range(5)]
hacker = dict(calm, mac="de:ad:00:00:00:01", fast_flaps="3", flap_burst="3")
r, _ = am.rank(herd + [hacker])
check("3 fast in/out in a burst -> THREAT, ranked first", r[0]["mac"] == hacker["mac"]
      and r[0]["anomaly"] and "sudden log-ins: 3 fast in/out within 10 min" in r[0]["threats"])
check("calm devices carry no threat", all(not d["threats"] for d in r[1:]))
newbie = dict(calm, mac="de:ad:00:00:00:02", fast_flaps="1", new_device="1")
check("new device + 1 fast in/out -> THREAT", am.threats(newbie) == ["new device logging in and out fast"])
check("known device with 1 fast in/out is not a threat", am.threats(dict(calm, fast_flaps="1", flap_burst="1")) == [])
check("isolated fast in/outs (hours apart) are not a threat",
      am.threats(dict(calm, fast_flaps="4", flap_burst="1")) == [])
check("new device that stays connected is not a threat", am.threats(dict(calm, new_device="1")) == [])
everyone = [dict(calm, mac=calm["mac"] % i, fast_flaps="4", flap_burst="2") for i in range(4)]
check("threat holds even when every device flaps (no baseline masking)",
      all(d["anomaly"] for d in am.rank(everyone)[0]))

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
