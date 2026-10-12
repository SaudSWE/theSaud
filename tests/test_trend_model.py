#!/usr/bin/env python3
"""Tests for trend_model.py -- each device vs its own history. No network.

    python3 tests/test_trend_model.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tm", os.path.join(HERE, "..", "trend_model.py"))
tm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tm)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


DAY0 = 1_791_072_000          # a midnight-ish epoch; +86400 per day
PHONE = "d6:95:79:3b:1c:4a"


def row(rt, day_i, **kw):
    r = {k: "" for k in ("epoch", "date", "record_type", "category", "device_mac",
                         "device_ip", "device_name", "bytes_in", "bytes_out",
                         "rate_in_kbps", "domain", "state")}
    epoch = DAY0 + day_i * 86400 + 3600
    r["epoch"] = str(epoch)
    r["date"] = __import__("time").strftime("%Y-%m-%d", __import__("time").localtime(epoch))
    r["record_type"] = rt
    r.update({k: str(v) for k, v in kw.items()})
    return r


def day_rows(day_i, mac, ip, name, bytes_in, dns_n):
    rows = [row("device_traffic", day_i, device_mac=mac, device_ip=ip, device_name=name,
                bytes_in=bytes_in, bytes_out=bytes_in // 10)]
    for j in range(dns_n):
        rows.append(row("dns_query", day_i, category="A", device_mac=mac, device_ip=ip,
                        device_name=name, domain="site%d.com" % j))
    return rows


print("build_daily buckets per device per day:")
rows = []
for d in range(4):
    rows += day_rows(d, PHONE, "192.168.8.135", "iPhone", 1_000_000, 50)
daily = tm.build_daily(rows)
check("one device seen", list(daily) == [PHONE])
check("four distinct days", len(daily[PHONE]["days"]) == 4)
anyday = next(iter(daily[PHONE]["days"].values()))
check("daily features computed", anyday["dns_queries"] == 50 and anyday["bytes_total"] == 1_100_000
      and anyday["distinct_domains"] == 50)
check("identity kept", daily[PHONE]["name"] == "iPhone" and daily[PHONE]["ip"] == "192.168.8.135")

print("\na device normal for 4 days, then a spike day -> flagged for itself:")
rows = []
for d in range(4):
    rows += day_rows(d, PHONE, "192.168.8.135", "iPhone", 1_000_000, 50)
rows += day_rows(4, PHONE, "192.168.8.135", "iPhone", 80_000_000_000, 900)   # huge day
res = tm.trend(rows, min_days=3, threshold=4.0)
me = next(r for r in res if r["mac"] == PHONE)
check("the spike day is flagged", me["anomaly"] is True)
check("scored against 4 prior days", me["history_days"] == 4)
reasons = {c: (today, usual) for c, _, today, usual in me["reasons"]}
check("data flagged: today >> usual", "bytes_total" in reasons
      and reasons["bytes_total"][0] > reasons["bytes_total"][1])
check("browsing flagged: today >> usual", "dns_queries" in reasons
      and reasons["dns_queries"][0] == 900 and reasons["dns_queries"][1] == 50)

print("\na steady device is NOT flagged against itself:")
steady = []
for d in range(6):
    steady += day_rows(d, "aa:bb:cc:dd:ee:01", "192.168.8.60", "steady",
                       1_000_000 + d * 20_000, 40 + d)     # mild natural drift
rs = tm.trend(steady, min_days=3, threshold=4.0)
check("steady device present but not abnormal",
      rs and rs[0]["mac"] == "aa:bb:cc:dd:ee:01" and not rs[0]["anomaly"])

print("\ntoo little history is skipped, not guessed:")
short = []
for d in range(2):                 # only 2 days total
    short += day_rows(d, "aa:bb:cc:dd:ee:02", "192.168.8.61", "new", 1_000_000, 10)
check("device with < min_days+1 days is skipped", tm.trend(short, min_days=3) == [])
check("--min-days 1 lets a 2-day device in", len(tm.trend(short, min_days=1)) == 1)

print("\nonly the high side flags (a quiet day for this device is not abnormal):")
rows = []
for d in range(4):
    rows += day_rows(d, PHONE, "192.168.8.135", "iPhone", 5_000_000, 100)
rows += day_rows(4, PHONE, "192.168.8.135", "iPhone", 1000, 0)     # near-silent day
res = tm.trend(rows, min_days=3, threshold=4.0)
me = next(r for r in res if r["mac"] == PHONE)
check("a much-quieter-than-usual day is not flagged", not me["anomaly"])

print("\nformatting + determinism:")
check("byte feature formatted human", tm.fmt_val("bytes_total", 1536) == "1.5 KB")
check("count feature formatted plain", tm.fmt_val("dns_queries", 900) == "900")
a = tm.trend(rows, min_days=3)
b = tm.trend(rows, min_days=3)
check("same input -> same result",
      [(r["mac"], r["score"]) for r in a] == [(r["mac"], r["score"]) for r in b])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
