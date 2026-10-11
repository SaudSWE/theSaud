#!/usr/bin/env python3
"""Per-device report from the mesh recorder's AI CSV -- the feature layer a
model on the server can train on or reason over.

One section per DEVICE (keyed on its MAC, which is the stable identity; the IP
it held is shown but is only a lease). For each device it answers, from the
recorded data:

  * how long it was online        -- sessions from ARRIVED/LEFT, total online
                                     time, longest single session, first/last
                                     seen (devices are sorted longest-online
                                     first, so the top device is the one that
                                     was connected the longest)
  * data usage                    -- bytes in / out / total, peak rate, and
                                     its current internet-access state
  * browsing                      -- how many lookups, how many distinct sites,
                                     the busiest domains
  * file transfer                 -- the biggest single flow and how many large
                                     flows (inferred from flow SIZE + service;
                                     contents are never inspected -- PRV-4)
  * log in / log out              -- session count, and 'fast' flaps (sessions
                                     shorter than --flap-seconds)
  * where it was                  -- which nodes (L1/L2/L3) it was seen on
  * reliability                   -- how often it was flagged not-connected

NOT yet computed here (need a time-join or host-level data -- see REQUIREMENTS):
  * internet-speed impact (which device's load coincided with latency spikes)
  * fine-grained location<->usage split (bytes per node)
  * 'a download that affected the system' (big inbound flow + a NEW open_port)

    python3 device_report.py                 # every device, longest online first
    python3 device_report.py 192.168.8.135   # one device (ip, mac or name)
    python3 device_report.py --csv feats.csv  # also write a per-device feature table
    python3 device_report.py --dir /path/to/mesh_records --flap-seconds 120
"""
import csv
import glob
import gzip
import os
import sys
from collections import Counter, defaultdict

DEFAULT_DIR = os.path.expanduser("~/mesh_records")
BIG_FLOW = 10 * 1024 * 1024          # 10 MB: "large" transfer
FLAP_SECONDS = 120                   # a session shorter than this is a fast in/out


def num(r, k):
    try:
        return float(r.get(k) or 0)
    except (TypeError, ValueError):
        return 0.0


def key_of(r):
    return (r.get("device_mac") or r.get("device_ip") or "").strip().lower()


def load(folder):
    rows = []
    for f in sorted(glob.glob(os.path.join(folder, "records_*.csv*"))):
        opener = gzip.open if f.endswith(".gz") else open
        try:
            with opener(f, mode="rt", errors="replace", newline="") as fh:
                rows.extend(csv.DictReader(fh))
        except OSError:
            pass
    rows.sort(key=lambda r: int(r.get("epoch") or 0))
    return rows


def sessionize(events, end_fallback):
    """events: (epoch, 'in'|'out') for one device, already time-sorted.
    Returns a list of (start, end) online intervals. A device already online
    when recording starts (first event is 'out') is counted from its first
    sighting; one still online at the end is closed at end_fallback."""
    sessions = []
    start = None
    first = events[0][0] if events else None
    for t, kind in events:
        if kind == "in":
            if start is None:
                start = t
        else:  # out
            if start is None:
                # was online before we first saw an 'in': count from the start
                sessions.append((first, t))
            else:
                sessions.append((start, t))
                start = None
    if start is not None:
        sessions.append((start, end_fallback))
    return [(a, b) for a, b in sessions if b >= a]


def aggregate(rows, flap_seconds=FLAP_SECONDS):
    ident = {}                       # key -> {ip,name,vendor}
    presence = defaultdict(list)     # key -> [(epoch,'in'/'out')]
    bytes_in = Counter()
    bytes_out = Counter()
    peak_rate = defaultdict(float)
    domains = defaultdict(Counter)
    big_flow = defaultdict(lambda: (0.0, "", ""))   # key -> (bytes, service, dst)
    big_flow_n = Counter()
    access_state = {}                # key -> latest GRANTED/BLOCKED/HELD
    block_n = Counter()
    nodes = defaultdict(set)
    missing_n = Counter()
    first_seen, last_seen = {}, {}

    for r in rows:
        k = key_of(r)
        if not k:
            continue
        rt = r.get("record_type", "")
        t = int(r.get("epoch") or 0)
        first_seen.setdefault(k, t)
        last_seen[k] = t
        d = ident.setdefault(k, {"ip": "", "name": "", "vendor": ""})
        if r.get("device_ip"):
            d["ip"] = r["device_ip"]
        if r.get("device_name"):
            d["name"] = r["device_name"]
        if r.get("device_vendor"):
            d["vendor"] = r["device_vendor"]

        if rt == "tracker_event":
            cat = (r.get("category") or "").upper()
            if cat == "ARRIVED":
                presence[k].append((t, "in"))
            elif cat == "LEFT":
                presence[k].append((t, "out"))
        elif rt == "malfunction":
            cat = (r.get("category") or "")
            if cat == "device_back":
                presence[k].append((t, "in"))
            elif cat == "device_missing":
                presence[k].append((t, "out"))
                missing_n[k] += 1
        elif rt == "device_traffic":
            bytes_in[k] += num(r, "bytes_in")
            bytes_out[k] += num(r, "bytes_out")
            peak_rate[k] = max(peak_rate[k], num(r, "rate_in_kbps"), num(r, "rate_out_kbps"))
        elif rt == "dns_query" and r.get("domain"):
            domains[k][r["domain"]] += 1
        elif rt in ("flow_end", "flow_active"):
            b = num(r, "bytes_in") + num(r, "bytes_out")
            if b > big_flow[k][0]:
                big_flow[k] = (b, r.get("service") or r.get("dst_port") or "", r.get("dst_ip") or "")
            if b >= BIG_FLOW:
                big_flow_n[k] += 1
        elif rt == "internet_access":
            st = r.get("state") or ""
            if st:
                access_state[k] = st
            if st == "BLOCKED":
                block_n[k] += 1
        elif rt == "device_position" and r.get("station_label"):
            nodes[k].add(r["station_label"])

    out = {}
    for k in ident:
        sess = sessionize(presence.get(k, []), last_seen.get(k, 0))
        durs = [b - a for a, b in sess]
        out[k] = {
            "mac": k, "ip": ident[k]["ip"], "name": ident[k]["name"],
            "vendor": ident[k]["vendor"],
            "first_seen": first_seen.get(k, 0), "last_seen": last_seen.get(k, 0),
            "sessions": len(sess),
            "online_s": int(sum(durs)),
            "longest_session_s": int(max(durs)) if durs else 0,
            "fast_flaps": sum(1 for x in durs if x < flap_seconds),
            "bytes_in": int(bytes_in[k]), "bytes_out": int(bytes_out[k]),
            "bytes_total": int(bytes_in[k] + bytes_out[k]),
            "peak_rate_kbps": round(peak_rate[k], 1),
            "dns_queries": sum(domains[k].values()),
            "distinct_domains": len(domains[k]),
            "top_domains": domains[k].most_common(5),
            "biggest_flow_bytes": int(big_flow[k][0]),
            "biggest_flow_service": big_flow[k][1],
            "large_flows": big_flow_n[k],
            "access_state": access_state.get(k, ""),
            "blocked_times": block_n[k],
            "nodes": sorted(nodes[k]),
            "times_not_connected": missing_n[k],
        }
    return out


def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f %s" % (n, u)
        n /= 1024
    return "%.1f PB" % n


def human_dur(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%d h %d min" % (h, m)
    if m:
        return "%d min %d s" % (m, s)
    return "%d s" % s


def iso(epoch):
    import datetime
    if not epoch:
        return "-"
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


def report(agg, match=()):
    devices = sorted(agg.values(), key=lambda d: d["online_s"], reverse=True)
    for d in devices:
        if match:
            hay = " ".join((d["mac"], d["ip"], d["name"])).lower()
            if not any(m.lower() in hay for m in match):
                continue
        print("=" * 72)
        print("%s   %s   %s" % (d["name"] or "(unnamed)", d["ip"] or "-", d["mac"]))
        print("  online      : %s over %d session(s); longest %s; %d fast in/out"
              % (human_dur(d["online_s"]), d["sessions"],
                 human_dur(d["longest_session_s"]), d["fast_flaps"]))
        print("  seen        : %s  ->  %s" % (iso(d["first_seen"]), iso(d["last_seen"])))
        print("  data        : %s down, %s up (%s total); peak %.0f kbps"
              % (human(d["bytes_in"]), human(d["bytes_out"]),
                 human(d["bytes_total"]), d["peak_rate_kbps"]))
        print("  internet    : %s%s"
              % (d["access_state"] or "-",
                 "; blocked %d time(s)" % d["blocked_times"] if d["blocked_times"] else ""))
        print("  browsing    : %d lookups, %d distinct sites"
              % (d["dns_queries"], d["distinct_domains"]))
        if d["top_domains"]:
            print("  top sites   : " + ", ".join("%s (%d)" % (dom, n) for dom, n in d["top_domains"]))
        if d["biggest_flow_bytes"]:
            print("  file xfer   : biggest flow %s (%s); %d large flow(s) over %s"
                  % (human(d["biggest_flow_bytes"]), d["biggest_flow_service"] or "?",
                     d["large_flows"], human(BIG_FLOW)))
        if d["nodes"]:
            print("  location    : node(s) %s" % ", ".join(d["nodes"]))
        if d["times_not_connected"]:
            print("  not-connected alerts: %d" % d["times_not_connected"])
    print("=" * 72)
    print("%d device(s), sorted by time online (longest first)" % len(devices))


CSV_COLS = ["mac", "ip", "name", "vendor", "first_seen", "last_seen", "sessions",
            "online_s", "longest_session_s", "fast_flaps", "bytes_in", "bytes_out",
            "bytes_total", "peak_rate_kbps", "dns_queries", "distinct_domains",
            "biggest_flow_bytes", "biggest_flow_service", "large_flows",
            "access_state", "blocked_times", "nodes", "times_not_connected"]


def write_csv(agg, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction="ignore")
        w.writeheader()
        for d in sorted(agg.values(), key=lambda d: d["online_s"], reverse=True):
            row = {c: d.get(c, "") for c in CSV_COLS}
            row["nodes"] = " ".join(d["nodes"])
            w.writerow(row)


def main(argv):
    folder, csv_path, flap, match = DEFAULT_DIR, None, FLAP_SECONDS, []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        elif a == "--dir":
            i += 1; folder = argv[i] if i < len(argv) else folder
        elif a == "--csv":
            i += 1; csv_path = argv[i] if i < len(argv) else None
        elif a == "--flap-seconds":
            i += 1; flap = int(argv[i]) if i < len(argv) else flap
        else:
            match.append(a)
        i += 1
    if not os.path.isdir(folder):
        print("no records folder: %s" % folder)
        return 1
    agg = aggregate(load(folder), flap_seconds=flap)
    report(agg, match=match)
    if csv_path:
        write_csv(agg, csv_path)
        print("feature table written to %s" % csv_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
