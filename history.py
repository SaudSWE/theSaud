#!/usr/bin/env python3
"""Readable activity history from the mesh recorder's AI CSV.

Reads every records_*.csv(.gz) under the records folder and prints the
MEANINGFUL events in time order -- who connected, who had internet, outages,
emails sent/received, zone arrivals and departures, new devices and new
listening services -- while skipping the high-frequency sampling that fills
the raw file: positions every 10 s, per-flow rows, DNS lookups, router logs,
the hourly port inventory's repeats, and the tracker's distance jitter while a
device sits still (IDLE / APPROACHING / LEAVING / SETTLING).

    python3 history.py                 # all meaningful events, oldest first
    python3 history.py 192.168.8.135   # only this device (by ip, mac or name)
    python3 history.py iPhone pi        # more than one filter (any match)
    python3 history.py --browsing       # also include dns_query browsing
    python3 history.py --all            # include the noisy sampling too
    python3 history.py --dir /path/to/mesh_records
"""
import csv
import glob
import gzip
import os
import sys

DEFAULT_DIR = os.path.expanduser("~/mesh_records")

# record types that are always an event worth showing
ALWAYS = {"malfunction", "internet_access", "email", "dhcp_lease"}
# tracker states that are only RSSI jitter, not a real move
TRACKER_KEEP = ("ARRIVED", "LEFT")


def keep_event(r, browsing=False, show_all=False):
    """True if this row is a meaningful activity event, not sampling noise."""
    if show_all:
        return True
    rt = r.get("record_type", "")
    if rt in ALWAYS:
        return True
    if rt == "tracker_event":
        text = " ".join((r.get("category") or "", r.get("state") or "",
                         r.get("detail") or "")).upper()
        if "FORBID" in text or "ZONE" in text:   # entering/leaving a zone
            return True
        return (r.get("category") or "").upper() in TRACKER_KEEP
    if rt == "dns_query":
        return browsing
    if rt == "open_port":
        return True            # de-duplicated in events(), below
    return False               # device_position, flow_*, wifi_station, router_* ...


def who(r):
    return (r.get("device_name") or r.get("device_ip")
            or r.get("device_mac") or "").strip()


def when(r):
    """date, time -- falling back to the ISO timestamp for old-schema rows
    written before the recorder had split-out date/time columns."""
    d, t = r.get("date", ""), r.get("time", "")
    if d and t:
        return d, t
    ts = r.get("timestamp", "") or ""
    return ts[:10], ts[11:19]


def detail_of(r):
    rt = r.get("record_type", "")
    if rt == "email":
        return r.get("email_subject") or r.get("detail") or ""
    if rt == "dns_query":
        return r.get("domain") or ""
    if rt == "open_port":
        return ("%s/%s %s" % (r.get("proto", ""), r.get("dst_port", ""),
                              r.get("service", ""))).strip()
    return r.get("detail") or ""


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


def events(rows, browsing=False, show_all=False, match=()):
    """The kept rows, with the hourly port inventory collapsed to each
    distinct listening port's first appearance, and an optional device filter."""
    seen_ports = set()
    out = []
    for r in sorted(rows, key=lambda r: int(r.get("epoch") or 0)):
        if not keep_event(r, browsing, show_all):
            continue
        if r.get("record_type") == "open_port" and not show_all:
            key = (r.get("station_label") or r.get("station"),
                   r.get("proto"), r.get("dst_port"))
            if key in seen_ports:
                continue
            seen_ports.add(key)
        if match:
            hay = " ".join((who(r), r.get("device_ip", ""), r.get("device_mac", ""),
                            r.get("station_label", ""), r.get("station", ""),
                            detail_of(r))).lower()
            if not any(m.lower() in hay for m in match):
                continue
        out.append(r)
    return out


def format_event(r):
    d, t = when(r)
    label = who(r) or r.get("station_label") or r.get("station") or ""
    return "%s %s  %-15s %-16s %-8s %-18s %s" % (
        d, t, r.get("record_type", ""), r.get("category", ""),
        r.get("state", ""), label, detail_of(r)[:60])


def main(argv):
    browsing = show_all = False
    folder = DEFAULT_DIR
    match = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        elif a == "--browsing":
            browsing = True
        elif a == "--all":
            show_all = True
        elif a == "--dir":
            i += 1
            folder = argv[i] if i < len(argv) else folder
        else:
            match.append(a)
        i += 1
    if not os.path.isdir(folder):
        print("no records folder: %s" % folder)
        return 1
    evs = events(load(folder), browsing=browsing, show_all=show_all, match=match)
    for r in evs:
        print(format_event(r))
    print("\n%d events%s" % (len(evs), (" for %s" % ", ".join(match)) if match else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
