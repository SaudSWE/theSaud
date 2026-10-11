#!/usr/bin/env python3
"""Offline anomaly model over the per-device feature table.

Classical, robust, pure-stdlib anomaly detection -- no internet, no pip, no
GPU; it runs on the Pi and keeps every resident's data on the server (PRV).

It reads the feature table that `device_report.py --csv` writes (one row per
device), learns what "normal" looks like across the devices, and flags the
ones that stand out -- naming the features that made each one stand out, so a
flag is explainable ("this device is abnormal because its data use and its
fast log-in/out count are far above everyone else"), not a black box.

HOW IT WORKS
  For each numeric feature it learns the MEDIAN and the MAD (median absolute
  deviation) across devices. Median/MAD are robust: the very outliers we are
  hunting do not drag the baseline, the way a mean/standard-deviation would.
  Heavy-tailed features (bytes, rates, counts) are log-scaled first so one
  heavy user is not automatically "abnormal". Each device is then scored by
  its most extreme feature -- a robust z-score, i.e. how many robust standard
  deviations it sits from the median -- and anything past --threshold (default
  4) is flagged, highest first. Only the HIGH side counts: for security,
  excess is the concern (too much data, too many flows, too much flapping);
  a device that is merely quiet is not an anomaly here.

  This is a drop-in slot: swap fit()/score() for scikit-learn's IsolationForest
  later if you install it; the CLI and the feature contract stay the same.

NOTE ON SIZE
  With only a handful of devices the baseline is rough -- treat scores as
  indicative until more devices / more history accumulate. Re-running over
  time, or scoring a device against its OWN past, is the stronger next step.

    python3 anomaly_model.py                      # reads ~/features.csv
    python3 anomaly_model.py path/to/features.csv
    python3 anomaly_model.py --threshold 3.5 --json
"""
import csv
import json
import math
import os
import sys

DEFAULT_FEATURES = os.path.expanduser("~/features.csv")
THRESHOLD = 4.0                      # robust-sigma past which a device is flagged
CONTRIB = 2.0                        # a feature is a "reason" at |z| >= this

# (column, log-scale?) -- the numeric features the model scores on.
FEATURES = [
    ("online_s", False), ("sessions", False), ("longest_session_s", False),
    ("fast_flaps", False), ("bytes_in", True), ("bytes_out", True),
    ("bytes_total", True), ("peak_rate_kbps", True), ("dns_queries", True),
    ("distinct_domains", False), ("biggest_flow_bytes", True),
    ("large_flows", True), ("blocked_times", False), ("times_not_connected", False),
]
MAD_TO_SIGMA = 1.4826                # scales MAD to a normal-consistent sigma


def value(row, col, log):
    try:
        x = float(row.get(col) or 0)
    except (TypeError, ValueError):
        return None
    if log:
        x = math.log1p(max(x, 0))
    return x


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2.0


def fit(rows):
    """Learn (median, robust-sigma) per feature across the devices."""
    model = {}
    for col, log in FEATURES:
        xs = [v for v in (value(r, col, log) for r in rows) if v is not None]
        if not xs:
            continue
        med = median(xs)
        mad = median([abs(x - med) for x in xs])
        sigma = mad * MAD_TO_SIGMA
        if sigma == 0:
            # MAD collapses when most values are identical; fall back to a
            # mean-absolute-deviation so a lone non-zero value is still seen.
            mean = sum(xs) / len(xs)
            sigma = sum(abs(x - mean) for x in xs) / len(xs)
        model[col] = {"log": log, "median": med, "sigma": sigma}
    return model


def robust_z(model, col, row):
    m = model.get(col)
    if not m or m["sigma"] == 0:
        return 0.0
    x = value(row, col, m["log"])
    if x is None:
        return 0.0
    return (x - m["median"]) / m["sigma"]


def score(model, row):
    """(headline score, [(feature, z) ...] sorted most-positive first).

    Scored on the HIGH side only: for security, excess is the concern -- too
    much data, too many flows, too much flapping, too many blocks. A device
    that is merely quiet (every feature below the median) is NOT an anomaly.
    Catching a normally-busy device that goes silent is the job of the
    per-device-over-time model, not this cross-device one."""
    zs = [(col, robust_z(model, col, row)) for col, _ in FEATURES if col in model]
    zs.sort(key=lambda kv: kv[1], reverse=True)
    headline = max((z for _, z in zs), default=0.0)
    return max(headline, 0.0), zs


def rank(rows, model=None, threshold=THRESHOLD):
    """Devices scored and sorted most-anomalous first."""
    model = model or fit(rows)
    out = []
    for r in rows:
        headline, zs = score(model, r)
        reasons = [(c, z) for c, z in zs if z >= CONTRIB]   # high-side only
        out.append({
            "mac": r.get("mac", ""), "ip": r.get("ip", ""),
            "name": r.get("name", ""), "score": round(headline, 2),
            "anomaly": headline >= threshold, "reasons": reasons,
        })
    out.sort(key=lambda d: d["score"], reverse=True)
    return out, model


def load_features(path):
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(f) if (r.get("mac") or r.get("ip"))]


def direction(z):
    return "high" if z > 0 else "low"


def main(argv):
    path, threshold, as_json = DEFAULT_FEATURES, THRESHOLD, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip()); return 0
        elif a == "--threshold":
            i += 1; threshold = float(argv[i]) if i < len(argv) else threshold
        elif a == "--json":
            as_json = True
        else:
            path = a
        i += 1
    if not os.path.exists(path):
        print("no feature table at %s -- run: python3 device_report.py --csv %s"
              % (path, path))
        return 1
    rows = load_features(path)
    ranked, _ = rank(rows, threshold=threshold)

    if as_json:
        print(json.dumps(ranked, indent=2))
        return 0

    n = len(rows)
    flagged = [d for d in ranked if d["anomaly"]]
    print("Anomaly scan of %d device(s); threshold %.1f robust-sigma." % (n, threshold))
    if n < 5:
        print("(only %d devices -- baseline is rough; scores are indicative)" % n)
    print("=" * 64)
    for d in ranked:
        mark = "  !! ANOMALY" if d["anomaly"] else ""
        who = d["name"] or d["ip"] or d["mac"]
        print("%-18s %-16s  score %5.2f%s" % (who, d["ip"] or d["mac"], d["score"], mark))
        for col, z in d["reasons"][:4]:
            print("      - %s %s (%.1f sigma)" % (col, direction(z), z))
    print("=" * 64)
    print("%d flagged of %d device(s)." % (len(flagged), n))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
