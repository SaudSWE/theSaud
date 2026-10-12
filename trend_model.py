#!/usr/bin/env python3
"""Per-device-over-time anomaly model -- each device vs its OWN history.

The cross-device model (anomaly_model.py) asks "which device differs from the
others" -- which, with few devices, flags the Pi just for being the always-on
server. This model asks a better question: "is THIS device behaving abnormally
FOR ITSELF today?" It builds one feature row per device per day, learns each
device's own normal day (robust median/MAD over its past days), and flags the
latest day when it deviates -- a phone that suddenly browses 5x its usual sites
or moves 10x its usual data. It works with few devices, because each device
supplies many days.

Pure stdlib, offline, reuses anomaly_model's robust math and high-side scoring.

  trend_model.py                    reads ~/mesh_records
  trend_model.py --min-days 2       flag with as few as 2 prior days (default 3)
  trend_model.py --threshold 3.5 --json

Only the HIGH side is flagged (excess is the concern). A device needs at least
--min-days days of history plus the latest day; devices with less are skipped.
"""
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import device_report as dr       # noqa: E402
import anomaly_model as am       # noqa: E402

DEFAULT_DIR = os.path.expanduser("~/mesh_records")
MIN_DAYS = 3
BYTE_COLS = {"bytes_in", "bytes_out", "bytes_total", "biggest_flow_bytes"}


def day_of(r):
    d = r.get("date")
    if d and len(d) >= 10:
        return d[:10]
    e = dr.epoch_of(r)
    return time.strftime("%Y-%m-%d", time.localtime(e)) if e is not None else None


def build_daily(rows):
    """{key: {"ip","name","days": {YYYY-MM-DD: {feature: value}}}} -- one
    feature row per device per day (additive/countable features only, so each
    day stands on its own)."""
    ident = {}

    def blank():
        return {"bytes_in": 0.0, "bytes_out": 0.0, "peak_rate_kbps": 0.0,
                "dns_queries": 0, "domains": set(), "large_flows": 0,
                "biggest_flow_bytes": 0.0, "blocked_times": 0}

    acc = defaultdict(lambda: defaultdict(blank))
    for r in rows:
        if dr.epoch_of(r) is None:
            continue
        k = dr.key_of(r)
        if not k:
            continue
        day = day_of(r)
        if not day:
            continue
        who = ident.setdefault(k, {"ip": "", "name": ""})
        if r.get("device_ip"):
            who["ip"] = r["device_ip"]
        if r.get("device_name"):
            who["name"] = r["device_name"]
        cell = acc[k][day]
        rt = r.get("record_type", "")
        if rt == "device_traffic":
            cell["bytes_in"] += dr.num(r, "bytes_in")
            cell["bytes_out"] += dr.num(r, "bytes_out")
            for v in (dr.num(r, "rate_in_kbps"), dr.num(r, "rate_out_kbps")):
                if 0 <= v <= dr.RATE_CEILING_KBPS:
                    cell["peak_rate_kbps"] = max(cell["peak_rate_kbps"], v)
        elif rt == "dns_query" and r.get("domain"):
            cell["dns_queries"] += 1
            cell["domains"].add(r["domain"])
        elif rt in ("flow_end", "flow_active"):
            b = dr.num(r, "bytes_in") + dr.num(r, "bytes_out")
            cell["biggest_flow_bytes"] = max(cell["biggest_flow_bytes"], b)
            if b >= dr.BIG_FLOW:
                cell["large_flows"] += 1
        elif rt == "internet_access" and r.get("state") == "BLOCKED":
            cell["blocked_times"] += 1

    out = {}
    for k, days in acc.items():
        dd = {}
        for day, c in days.items():
            dd[day] = {
                "bytes_in": c["bytes_in"], "bytes_out": c["bytes_out"],
                "bytes_total": c["bytes_in"] + c["bytes_out"],
                "peak_rate_kbps": c["peak_rate_kbps"],
                "dns_queries": c["dns_queries"], "distinct_domains": len(c["domains"]),
                "large_flows": c["large_flows"],
                "biggest_flow_bytes": c["biggest_flow_bytes"],
                "blocked_times": c["blocked_times"],
            }
        out[k] = {"ip": ident[k]["ip"], "name": ident[k]["name"], "days": dd}
    return out


def trend(rows, min_days=MIN_DAYS, threshold=am.THRESHOLD):
    """Score each device's LATEST day against its own prior days. Returns the
    devices with enough history, most-abnormal first."""
    daily = build_daily(rows)
    results = []
    for k, info in daily.items():
        days = sorted(info["days"])
        if len(days) < min_days + 1:          # need history PLUS the latest day
            continue
        hist = [info["days"][d] for d in days[:-1]]
        latest_day, latest = days[-1], info["days"][days[-1]]
        model = am.fit(hist)
        # Score the latest day against the device's own baseline. High side
        # only. If a feature's history has zero spread (sigma 0 -- e.g. it was
        # always 0) and today breaks it upward, that is a clear first-time
        # event, so flag it rather than returning 0 for lack of variance.
        zs = []
        for col, _ in am.FEATURES:
            m = model.get(col)
            if not m:
                continue
            x = am.value(latest, col, m["log"])
            if x is None:
                continue
            if m["sigma"] == 0:
                z = 6.0 if x > m["median"] else 0.0
            else:
                z = (x - m["median"]) / m["sigma"]
            zs.append((col, z))
        zs.sort(key=lambda kv: kv[1], reverse=True)
        headline = max((z for _, z in zs), default=0.0)
        reasons = [(col, z, latest.get(col, 0), am.median([h.get(col, 0) for h in hist]))
                   for col, z in zs if z >= am.CONTRIB]
        results.append({
            "mac": k, "ip": info["ip"], "name": info["name"], "day": latest_day,
            "history_days": len(days) - 1, "score": round(headline, 2),
            "anomaly": headline >= threshold, "reasons": reasons,
        })
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def fmt_val(col, v):
    if col in BYTE_COLS:
        return dr.human(v)
    if col == "peak_rate_kbps":
        return "%.0f kbps" % v
    return str(int(v))


def main(argv):
    folder, min_days, threshold, as_json = DEFAULT_DIR, MIN_DAYS, am.THRESHOLD, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip()); return 0
        elif a == "--dir":
            i += 1; folder = argv[i] if i < len(argv) else folder
        elif a == "--min-days":
            i += 1; min_days = int(argv[i]) if i < len(argv) else min_days
        elif a == "--threshold":
            i += 1; threshold = float(argv[i]) if i < len(argv) else threshold
        elif a == "--json":
            as_json = True
        i += 1
    if not os.path.isdir(folder):
        print("no records folder: %s" % folder); return 1
    results = trend(dr.load(folder), min_days=min_days, threshold=threshold)

    if as_json:
        print(json.dumps(results, indent=2)); return 0

    if not results:
        print("No device has %d+ days of history yet -- the per-device baseline "
              "needs more days. Try --min-days 2, or wait for more data." % min_days)
        return 0
    flagged = [r for r in results if r["anomaly"]]
    print("Each device vs ITS OWN history (threshold %.1f robust-sigma):" % threshold)
    print("=" * 68)
    for r in results:
        mark = "  !! ABNORMAL for this device" if r["anomaly"] else ""
        who = r["name"] or r["ip"] or r["mac"]
        print("%-16s %-15s  %s  score %5.2f%s  [%d days]" %
              (who, r["ip"] or r["mac"], r["day"], r["score"], mark, r["history_days"]))
        for col, z, today, usual in r["reasons"][:4]:
            print("      - %s today %s vs usual %s (%.1f sigma)" %
                  (col, fmt_val(col, today), fmt_val(col, usual), z))
    print("=" * 68)
    print("%d device(s) scored, %d abnormal today." % (len(results), len(flagged)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
