#!/usr/bin/env python3
"""
mesh_recorder.py -- record EVERYTHING the Manarat Mesh system sees into CSV,
so it can be analysed later (and fed to an AI that looks for problems,
unusual behaviour and improvements).

What it records (one unified CSV schema, one row per observation)
  device_position   where each device is: station, lat/lon, distance, accuracy,
                    signal, moving/idle state            (from the tracker)
  tracker_event     ARRIVED / LEFT / HANDOVER / STEER / APPROACHING / LEAVING /
                    IDLE, with the numbers parsed out     (from the tracker)
  wifi_station      every Wi-Fi client of every router: band, channel, signal,
                    signal average, link speeds, bytes up/down + rates,
                    inactive time, connected time
  mesh_link         each router's view of each mesh peer: signal, link state,
                    speeds, backhaul bytes + rates
  device_traffic    data usage per device from main123's connection table:
                    bytes in/out this interval, kbit/s, running totals, flows
  flow_end          one row per finished connection: device, protocol,
                    source/destination IP and PORT, service, direction,
                    bytes each way, duration
  flow_active       long connections (streams, calls) reported every 10 min
  router_health     uptime, load, free memory, temperature, client count,
                    reachability; WAN bytes + rates on main123; same for the Pi
  internet_latency  StreamWatch's latency probe (ms)
  router_log        router syslog: Wi-Fi joins/leaves, DHCP, logins (failed
                    logins flagged), StreamWatch alerts/commands, kernel/system
  dns_query         browsing history: every site address each device looks up
                    (dnsmasq query logging is switched on by the recorder)
  dhcp_lease        IP address handed to a device (new / changed)
  sw_quota / sw_throttle / device_inventory
                    StreamWatch limits, blocks, throttles, and its registry of
                    every MAC ever seen (vendor, randomised MAC, first seen)
  open_port         listening ports on each router and on the Pi (hourly)
  station_config    stations: IP, MAC, coordinates, calibration, channels,
                    SSIDs (at start, daily, and when something changes)
  recorder          the recorder's own start / stop / problems

Files
  ~/mesh_records/records_YYYY-MM-DD.csv     today's file (a new one each day;
                                            older days are gzipped)
  ~/mesh_records/DATA_DICTIONARY.md         what every column / record means
  ~/mesh_records/data_dictionary.csv        same, as CSV
  ~/mesh_records/history/                   converted tracker history

Commands (run on the Pi)
  python3 mesh_recorder.py                  record continuously (Ctrl+C stops)
  python3 mesh_recorder.py import-history   convert the tracker's past logs
  python3 mesh_recorder.py export --from "2026-09-30 08:00" --to "2026-09-30 18:00"
        [--types device_position,flow_end] [-o slice.csv]
                                            one CSV for a time range (to hand to AI)
  python3 mesh_recorder.py dictionary       (re)write the data dictionary
  python3 mesh_recorder.py note "moved 456 to the other side of the dome"
                                            log a manual change (context for AI)

Read-only towards the routers except one thing: if connection byte counting
(nf_conntrack_acct) is off on main123 it is switched on, because data usage
cannot be measured without it. StreamWatch switches it on as well.

Pure standard library. Needs key-based SSH from the Pi to root@ each router.
"""

import argparse
import csv
import glob
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

# ------------------------------------------------------------------ setup

ROUTERS = {                      # name -> (ip, short label, long label)
    "main123": ("192.168.8.1", "L1", "Location 1"),
    "acf":     ("192.168.8.2", "L2", "Location 2"),
    "456":     ("192.168.8.3", "L3", "Location 3"),
}
MAIN = "main123"                 # gateway: internet, DHCP, firewall, StreamWatch
HOME = os.path.expanduser("~")
TRACKER_DIR = os.path.join(HOME, "mesh_tracker")
CALIB_FILE = os.path.join(HOME, "mesh_calibration.json")
OUT_DIR = os.path.join(HOME, "mesh_records")

COLUMNS = [
    ("timestamp", "Local date-time of the observation, ISO 8601 with UTC offset (Riyadh = +03:00).", ""),
    ("date", "Local date of the observation, YYYY-MM-DD (same moment as timestamp).", ""),
    ("time", "Local time of the observation, HH:MM:SS, 24-hour, Riyadh time.", ""),
    ("epoch", "Same moment as Unix seconds (for sorting / maths).", "s"),
    ("record_type", "What kind of row this is -- see the record types table.", ""),
    ("category", "Sub-type: event name, log category, service, status (depends on record_type).", ""),
    ("station", "Router / station involved: main123, acf, 456 (or pi for the Raspberry Pi).", ""),
    ("station_label", "Station's location label: L1 (main123), L2 (acf), L3 (456).", ""),
    ("station_ip", "Station's IP address.", ""),
    ("device_mac", "Device MAC address (Wi-Fi clients are identified by MAC).", ""),
    ("device_ip", "Device IP address on the LAN (192.168.8.x).", ""),
    ("device_name", "Device name from DHCP / tracker (e.g. iPhone, pi); may be empty.", ""),
    ("device_vendor", "Manufacturer from StreamWatch, or 'randomised MAC' when the device invents its MAC (iPhones/Android do per network).", ""),
    ("lat", "Latitude (WGS84 decimal degrees): device estimate or station position.", "deg"),
    ("lon", "Longitude (WGS84 decimal degrees).", "deg"),
    ("dist_m", "Estimated distance from the device to its station, from signal strength.", "m"),
    ("uncertainty_m", "Radius of the position uncertainty circle (smaller = surer).", "m"),
    ("rssi_dbm", "Signal strength (closer to 0 = stronger; -40 very close, -75 far).", "dBm"),
    ("rssi_avg_dbm", "Driver-averaged signal strength.", "dBm"),
    ("state", "Movement state (IDLE, APPROACHING Lx, LEAVING Lx, SETTLING); station online/unreachable; log level (info, warn, err) for router_log; BLOCKED/ok for sw_quota; GRANTED/BLOCKED/HELD for internet_access; LISTEN for open_port.", ""),
    ("band", "Wi-Fi band: 2.4G or 5G.", ""),
    ("channel", "Wi-Fi channel number.", ""),
    ("bytes_in", "Bytes received BY THE DEVICE (download) in this interval / flow. mesh_link: received from the peer. router_health on main123: WAN bytes from the internet.", "bytes"),
    ("bytes_out", "Bytes sent BY THE DEVICE (upload). mesh_link: sent to the peer. router_health on main123: WAN bytes to the internet.", "bytes"),
    ("rate_in_kbps", "Download rate over the interval.", "kbit/s"),
    ("rate_out_kbps", "Upload rate over the interval.", "kbit/s"),
    ("total_in", "Running total of bytes_in (since the recorder / association started).", "bytes"),
    ("total_out", "Running total of bytes_out.", "bytes"),
    ("tx_bitrate_mbps", "Wi-Fi link speed router->device (or router->peer).", "Mbit/s"),
    ("rx_bitrate_mbps", "Wi-Fi link speed device->router.", "Mbit/s"),
    ("inactive_ms", "Time since the router last heard the device/peer.", "ms"),
    ("connected_s", "How long the device/peer has been associated to this router.", "s"),
    ("proto", "Network protocol of a connection: tcp, udp, icmp.", ""),
    ("src_ip", "Connection source IP (who opened it).", ""),
    ("src_port", "Connection source port.", ""),
    ("dst_ip", "Connection destination IP.", ""),
    ("dst_port", "Connection destination port.", ""),
    ("service", "Well-known service for the port (https, dns, quic, ssh, ...).", ""),
    ("direction", "outbound (device opened it), inbound (opened from outside towards a device), local (LAN to LAN).", ""),
    ("duration_s", "Duration of a connection (first to last time seen); for router_health: uptime of the station.", "s"),
    ("peer", "Other end: mesh peer router, previous station in a handover, etc.", ""),
    ("link_state", "Mesh link state (ESTAB = working), TCP state, lease state.", ""),
    ("value", "Generic number whose meaning is in 'unit' (latency, load, uptime, limit, ...).", ""),
    ("unit", "Unit of 'value'.", ""),
    ("domain", "dns_query: the domain name (site address) the device looked up, e.g. www.youtube.com. Name only -- never the page path or content (PRV-4).", ""),
    ("access_time", "internet_access: when the device's access was set on the gateway (time written next to it in the allow/deny list), ISO 8601; empty for HELD.", ""),
    ("email_from", "email: sender address.", ""),
    ("email_to", "email: recipient address.", ""),
    ("email_subject", "email: subject line.", ""),
    ("detail", "Free text: original event / log message, JSON for complex state.", ""),
]
FIELDS = [c[0] for c in COLUMNS]

RECORD_TYPES = [
    ("station_config", "One row per station describing it: IP, MAC, coordinates, calibration A (dBm at 1 m) and n (path-loss exponent) in detail, channels and SSIDs.", "start, daily, on change"),
    ("device_position", "Tracker's estimate of where a device is: station it is connected to, lat/lon, distance, uncertainty, signal, movement state.", "every interval (10 s)"),
    ("tracker_event", "Tracker events: ARRIVED, LEFT, HANDOVER (peer = previous station), STEER (tracker pushed a sticky phone to a closer router), APPROACHING / LEAVING / IDLE with distance.", "as they happen"),
    ("wifi_station", "A Wi-Fi client as seen by the router it is connected to: signal, link speeds, bytes, rates, inactivity.", "every interval"),
    ("mesh_link", "Router-to-router mesh link as seen from one end: signal, state, speeds, backhaul traffic.", "every health interval (60 s)"),
    ("device_traffic", "Internet/LAN data used by a device in the interval (from main123's connection table), with rates, running totals and number of active connections (value).", "every interval with traffic"),
    ("flow_end", "A finished connection: device, proto, src/dst IP and port, service, direction, bytes each way, duration.", "when a connection closes"),
    ("flow_active", "A long-running connection still open (cumulative bytes so far).", "every 10 min per long connection"),
    ("router_health", "Station health: uptime, load (value), free memory, temperature, clients; 'unreachable' when SSH fails; WAN bytes/rates on main123.", "every health interval (60 s)"),
    ("internet_latency", "Latency to the internet measured by StreamWatch (value, ms).", "as logged (about every 5 s)"),
    ("router_log", "Router syslog line, categorised: wifi, dhcp, ssh, ssh_fail, streamwatch, kernel, network, system.", "as logged"),
    ("dns_query", "Browsing history: a device looked up a site address. One row per lookup, for every device that uses the router for DNS: device_ip/mac/name, domain, category = record type asked (A = IPv4, AAAA = IPv6, HTTPS = service info), date/time of the lookup. The recorder switches dnsmasq query logging on and enlarges the router log buffer itself, so no lookup is missed between samples. A device using encrypted DNS (DoH/DoT) to an outside server does not appear.", "as logged"),
    ("dhcp_lease", "A device got / changed an IP lease.", "on change"),
    ("sw_usage", "StreamWatch's own per-minute usage table: per device total_in / total_out / value = total bytes since StreamWatch started, signal or 'wired'; plus a summary row (value = live flows).", "every minute"),
    ("sw_quota", "StreamWatch data limit for a device: limit (value), used (total_in), period, blocked.", "on change"),
    ("sw_throttle", "StreamWatch speed limit for a device (down/up kbit in detail).", "on change"),
    ("email", "Every email StreamWatch sent (alerts, reports, replies) and every command email it received, refused or ignored as too old: category = sent, failed, received, refused or stale; email_from / email_to / email_subject; detail = first line sent, or the commands found. timestamp/date/time = when the email was handled on main123. Ordinary non-command mail is not recorded.", "as it happens"),
    ("internet_access", "When a device's internet access changed, from StreamWatch's allow/deny lists on main123: state GRANTED (on the allow list), BLOCKED (on the deny list; a block beats an allow), or HELD (on neither list -- has an address but no internet until approved). category = previous->new state, or 'initial' for the first row per device. timestamp = when the recorder saw the change; detail = the time and IP written next to the device in the list file.", "on change"),
    ("device_inventory", "StreamWatch's registry entry for a MAC: vendor, randomised, first/last seen, hostnames, IPs.", "on change"),
    ("open_port", "A listening port on a station (proto, local IP:port).", "hourly"),
    ("calibration_point", "A calibration measurement: phone at a tape-measured distance (dist_m) from a station, median signal (rssi_dbm); value = distance the fitted model gives back.", "when calibrating"),
    ("change_log", "A manual change to the system (placement, configuration, software) -- context when explaining anomalies before/after it.", "when it happens"),
    ("recorder", "The recorder itself: start, stop, errors, settings.", "as needed"),
]

SERVICES = {
    ("tcp", 20): "ftp-data", ("tcp", 21): "ftp", ("tcp", 22): "ssh",
    ("tcp", 23): "telnet", ("tcp", 25): "smtp", ("udp", 53): "dns",
    ("tcp", 53): "dns", ("udp", 67): "dhcp", ("udp", 68): "dhcp",
    ("tcp", 80): "http", ("udp", 123): "ntp", ("udp", 137): "netbios",
    ("udp", 138): "netbios", ("tcp", 139): "netbios", ("tcp", 143): "imap",
    ("tcp", 443): "https", ("udp", 443): "quic", ("tcp", 445): "smb",
    ("tcp", 465): "smtps", ("udp", 500): "ipsec", ("tcp", 587): "smtp-submit",
    ("tcp", 853): "dns-over-tls", ("tcp", 993): "imaps", ("tcp", 995): "pop3s",
    ("udp", 1194): "openvpn", ("udp", 1900): "ssdp", ("tcp", 3389): "rdp",
    ("udp", 3478): "stun/turn (calls)", ("udp", 3479): "stun/turn (calls)",
    ("udp", 4500): "ipsec-nat", ("tcp", 5222): "xmpp/whatsapp",
    ("tcp", 5223): "apple-push", ("tcp", 5228): "google-push",
    ("udp", 5353): "mdns", ("tcp", 7681): "ttyd (web terminal)",
    ("tcp", 8080): "http-alt", ("tcp", 8090): "mesh map", ("tcp", 8443): "https-alt",
    ("udp", 51820): "wireguard",
}


def service_of(proto, port):
    try:
        p = int(port)
    except (TypeError, ValueError):
        return ""
    return SERVICES.get((proto, p), "")


def is_randomised(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def iso(epoch):
    return datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")


def local_epoch(text, fmt="%Y-%m-%d %H:%M:%S"):
    """'2026-09-30 10:56:15' (local time) -> epoch; None if unparseable."""
    try:
        return time.mktime(datetime.strptime(text.strip()[:19].replace("T", " "),
                                              fmt).timetuple())
    except (ValueError, AttributeError):
        return None


def rec(record_type, epoch, **kw):
    r = {k: "" for k in FIELDS}
    r["record_type"] = record_type
    r["epoch"] = int(epoch)
    r["timestamp"] = iso(epoch)
    r["date"] = r["timestamp"][:10]
    r["time"] = r["timestamp"][11:19]
    for k, v in kw.items():
        if k not in r:
            raise KeyError(k)
        if isinstance(v, float):
            v = round(v, 7) if k in ("lat", "lon") else round(v, 2)
        r[k] = "" if v is None else v
    return r


def st_fields(name):
    """station, station_label, station_ip for a router name."""
    if name in ROUTERS:
        ip, short, _ = ROUTERS[name]
        return {"station": name, "station_label": short, "station_ip": ip}
    return {"station": name or ""}


def label_to_station(text):
    """'Location 2' / 'L2' -> 'acf'."""
    m = re.search(r"(?:Location\s*|L)([123])\b", text or "")
    if not m:
        return ""
    for name, (_, short, _) in ROUTERS.items():
        if short == "L" + m.group(1):
            return name
    return ""


def pi_ips():
    out = set()
    try:
        for tok in subprocess.run(["hostname", "-I"], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=5
                                  ).stdout.decode().split():
            out.add(tok)
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def pi_macs():
    out = set()
    for p in glob.glob("/sys/class/net/*/address"):
        try:
            with open(p) as f:
                out.add(f.read().strip().lower())
        except OSError:
            pass
    return out


def in_lan(ip, prefix):
    return ip.startswith(prefix)


# ------------------------------------------------------------------ output

class Writer:
    """Appends rows to ~/mesh_records/records_<date>.csv, one file per day;
    gzips finished days."""

    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self.day = None
        self.f = None
        self.w = None
        self.count = 0

    def _open(self, day):
        if self.f:
            self.f.close()
        path = os.path.join(self.folder, "records_%s.csv" % day)
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        if not new:
            with open(path, newline="", encoding="utf-8") as fh:
                header = next(csv.reader(fh), [])
            if header != FIELDS:
                # schema changed mid-day: keep the old rows under their own
                # header rather than appending rows that no longer line up
                n = 1
                while os.path.exists(path[:-4] + ".old%d.csv" % n):
                    n += 1
                os.rename(path, path[:-4] + ".old%d.csv" % n)
                new = True
        self.f = open(path, "a", newline="", encoding="utf-8")
        self.w = csv.DictWriter(self.f, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            self.w.writeheader()
        self.day = day
        threading.Thread(target=self.compress_old, daemon=True).start()

    def compress_old(self):
        today = "records_%s.csv" % self.day
        for p in glob.glob(os.path.join(self.folder, "records_*.csv")):
            if os.path.basename(p) == today:
                continue
            try:
                with open(p, "rb") as src, gzip.open(p + ".gz", "ab") as dst:
                    shutil.copyfileobj(src, dst)
                os.remove(p)
            except OSError:
                pass

    def write(self, rows):
        day = time.strftime("%Y-%m-%d")          # file = day of writing
        if day != self.day:
            self._open(day)
        for r in rows:
            self.w.writerow(r)
            self.count += 1
        if self.f:
            self.f.flush()

    def close(self):
        if self.f:
            self.f.close()


def write_dictionary(folder):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "data_dictionary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "name", "meaning", "unit_or_cadence"])
        for name, meaning, unit in COLUMNS:
            w.writerow(["column", name, meaning, unit])
        for name, meaning, cadence in RECORD_TYPES:
            w.writerow(["record_type", name, meaning, cadence])
    lines = [
        "# Manarat Mesh records -- data dictionary",
        "",
        "Every file `records_YYYY-MM-DD.csv(.gz)` has the same columns. Each row is",
        "one observation; `record_type` says what it is, and only the columns that",
        "make sense for that type are filled (others are empty).",
        "",
        "## Network",
        "",
        "* 802.11s Wi-Fi mesh of three GL.iNet GL-MT3000 routers (OpenWrt 24.10).",
        "* main123 = Location 1 (L1), 192.168.8.1 -- gateway: internet (WAN), DHCP,",
        "  firewall, StreamWatch (traffic metering, alerts, email commands).",
        "* acf = Location 2 (L2), 192.168.8.2 and 456 = Location 3 (L3),",
        "  192.168.8.3 -- mesh nodes (bridges).",
        "* Raspberry Pi 192.168.8.162 at L1 runs the tracker (mesh_tracker.py),",
        "  the live map (port 8090, public via ngrok behind Google login) and this",
        "  recorder. It is fixed at L1 -- its own 'movement' would be an error.",
        "* Positions come from Wi-Fi signal strength measured ONLY by the router a",
        "  device is connected to (d = 10^((A - RSSI)/(10 n)), per-station A and n",
        "  from calibration), plus a particle filter; expect metres of error.",
        "  Phones are 'sticky'; the tracker STEERs them (brief disconnect) to the",
        "  closest router when the signal drops below -70 dBm.",
        "* Data usage comes from main123's connection table; traffic between two",
        "  devices on the same node may not pass main123 and is not counted.",
        "* iPhones/Android use a randomised MAC per network; one physical phone",
        "  can appear under a new MAC after a reset of that setting.",
        "",
        "## Columns",
        "",
        "| column | meaning | unit |",
        "|---|---|---|",
    ]
    lines += ["| %s | %s | %s |" % c for c in COLUMNS]
    lines += ["", "## Record types", "", "| record_type | meaning | cadence |",
              "|---|---|---|"]
    lines += ["| %s | %s | %s |" % r for r in RECORD_TYPES]
    lines += [
        "",
        "## Useful questions for analysis",
        "",
        "* Devices that appear at unusual hours, new MACs (device_inventory,",
        "  tracker_event ARRIVED), failed SSH logins (router_log ssh_fail).",
        "* Inbound connections (flow_end direction=inbound), unusual ports/services,",
        "  sudden data spikes (device_traffic), quota hits (sw_quota).",
        "* Browsing (dns_query): which sites each device visited and when --",
        "  group by device_mac and domain, count, and look at the time of day.",
        "* Every email (email): alerts and reports sent, command emails received,",
        "  forged/unknown senders refused, stale commands ignored -- with date/time.",
        "* Who had internet and when (internet_access): when each device was",
        "  granted, held or blocked, and how long it waited before approval.",
        "* Weak or failing mesh links (mesh_link rssi_dbm, link_state), stations",
        "  unreachable or hot (router_health), internet latency spikes.",
        "* Tracking quality: frequent STEER/HANDOVER ping-pong, large",
        "  uncertainty_m, devices stuck on a far station (low rssi_dbm).",
        "",
    ]
    with open(os.path.join(folder, "DATA_DICTIONARY.md"), "w") as f:
        f.write("\n".join(lines))


# ------------------------------------------------------------------ routers

REMOTE = r"""
echo "## SYS"
echo "UPTIME $(cut -d' ' -f1 /proc/uptime)"
echo "LOAD $(cut -d' ' -f1-3 /proc/loadavg)"
echo "MEM $(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{print t, a}' /proc/meminfo)"
echo "TEMP $(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)"
echo "MAC $(cat /sys/class/net/eth0/address 2>/dev/null)"
for i in $(iw dev | awk '/Interface/{print $2}'); do
  info=$(iw dev $i info)
  t=$(echo "$info" | awk '/type/{print $2}')
  ch=$(echo "$info" | awk '/channel/{print $2}')
  fr=$(echo "$info" | awk '/channel/{gsub(/[()]/,"",$3); print $3}')
  a=$(echo "$info" | awk '/addr/{print $2}')
  echo "## IFACE $i ${t:--} ${ch:--} ${fr:--} ${a:--}"
  echo "SSID $(echo "$info" | sed -n 's/^[[:space:]]*ssid //p')"
  iw dev $i station dump
done
echo "## LOG"
logread 2>/dev/null | tail -n %(loglines)d
if [ "%(main)s" = 1 ]; then
  echo "## LEASES"
  cat /tmp/dhcp.leases 2>/dev/null
  echo "## ACCT"
  a=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null)
  if [ "$a" = 0 ]; then echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct; echo "ACCT 0 enabled"; else echo "ACCT ${a:--}"; fi
  # restarting logd cuts dnsmasq off from syslog (seen on GL-MT3000), so
  # dnsmasq is restarted after it -- otherwise lookups silently stop logging
  if [ "%(dns)s" = 1 ]; then
    q=$(uci -q get dhcp.@dnsmasq[0].logqueries)
    if [ "$q" != 1 ]; then uci set dhcp.@dnsmasq[0].logqueries=1; uci commit dhcp; /etc/init.d/dnsmasq restart >/dev/null 2>&1; echo "DNSLOG enabled"; else echo "DNSLOG on"; fi
    z=$(uci -q get system.@system[0].log_size)
    if [ "${z:-0}" -lt 1024 ]; then uci set system.@system[0].log_size=1024; uci commit system; /etc/init.d/log restart >/dev/null 2>&1; /etc/init.d/dnsmasq restart >/dev/null 2>&1; echo "LOGSIZE ${z:-64} raised to 1024"; else echo "LOGSIZE $z"; fi
  fi
  w=$(ip route | awk '/^default/{print $5; exit}')
  echo "WAN ${w:--} $(cat /sys/class/net/$w/statistics/rx_bytes 2>/dev/null) $(cat /sys/class/net/$w/statistics/tx_bytes 2>/dev/null)"
  echo "## CONNTRACK"
  cat /proc/net/nf_conntrack 2>/dev/null
  for f in quotas throttles devices; do
    echo "## SW $f"
    cat /root/.streamwatch_$f.json 2>/dev/null
    echo
  done
  echo "## EMAILS"
  tail -n 300 /root/.streamwatch_emails.log 2>/dev/null
  for f in allow deny; do
    echo "## ACL $f"
    if [ -f /etc/streamwatch/$f.txt ]; then cat /etc/streamwatch/$f.txt; else echo "__MISSING__"; fi
  done
fi
if [ "%(full)s" = 1 ]; then
  echo "## PORTS"
  netstat -ltnu 2>/dev/null
  echo "## UCI"
  uci show wireless 2>/dev/null | grep -E '\.(channel|band|htmode|txpower|mode|mesh_id|ssid|disabled)='
fi
echo "## END"
"""


def fetch(name, full, loglines, timeout=25, dns=True):
    ip = ROUTERS[name][0]
    script = REMOTE % {"main": 1 if name == MAIN else 0,
                       "full": 1 if full else 0, "loglines": loglines,
                       "dns": 1 if dns else 0}
    try:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                            "root@" + ip, "sh -s"], input=script.encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = p.stdout.decode(errors="replace")
    return out if "## END" in out else None


ACCESS_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
ACL_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
NUM = r"(-?\d+(?:\.\d+)?)"
STA_FIELDS = [
    ("inactive_ms", re.compile(r"^\s*inactive time:\s*(\d+)"), int),
    ("rx_bytes", re.compile(r"^\s*rx bytes:\s*(\d+)"), int),
    ("tx_bytes", re.compile(r"^\s*tx bytes:\s*(\d+)"), int),
    ("signal", re.compile(r"^\s*signal:\s*(-?\d+)"), int),
    ("signal_avg", re.compile(r"^\s*signal avg:\s*(-?\d+)"), int),
    ("tx_rate", re.compile(r"^\s*tx bitrate:\s*" + NUM), float),
    ("rx_rate", re.compile(r"^\s*rx bitrate:\s*" + NUM), float),
    ("connected_s", re.compile(r"^\s*connected time:\s*(\d+)"), int),
    ("plink", re.compile(r"^\s*mesh plink:\s*(\S+)"), str),
]


def band_of(freq):
    try:
        f = int(freq)
    except (TypeError, ValueError):
        return ""
    return "2.4G" if f < 3000 else ("5G" if f < 5950 else "6G")


def parse_router(text):
    d = {"sys": {}, "ifaces": [], "stations": [], "log": [], "leases": [],
         "conntrack": [], "sw": {}, "ports": [], "uci": [], "acct": "", "wan": None,
         "acl": {}, "emails": [], "dnslog": "", "logsize": ""}
    section, cur, iface, swname, swbuf = None, None, None, None, []
    aclname = None

    def flush_sw():
        if swname is not None:
            txt = "\n".join(swbuf).strip()
            try:
                d["sw"][swname] = json.loads(txt) if txt else {}
            except ValueError:
                d["sw"][swname] = None

    for line in text.splitlines():
        if line.startswith("## "):
            if section == "SW":
                flush_sw()
            parts = line.split()
            section = parts[1]
            cur = None
            if section == "IFACE":
                iface = {"if": parts[2], "type": parts[3], "ch": parts[4],
                         "freq": parts[5], "addr": parts[6].lower(), "ssid": ""}
                if iface["ch"] == "-":
                    iface["ch"] = ""
                d["ifaces"].append(iface)
            elif section == "SW":
                swname, swbuf = parts[2], []
            elif section == "ACL":
                aclname = parts[2]
                d["acl"][aclname] = {}
            continue
        if section == "SYS":
            k, _, v = line.partition(" ")
            d["sys"][k] = v.strip()
        elif section == "IFACE":
            if line.startswith("SSID "):
                iface["ssid"] = line[5:].strip()
            elif line.startswith("Station "):
                cur = {"mac": line.split()[1].lower(), "if": iface["if"],
                       "type": iface["type"], "ch": iface["ch"],
                       "band": band_of(iface["freq"])}
                d["stations"].append(cur)
            elif cur is not None:
                for key, rx, conv in STA_FIELDS:
                    m = rx.match(line)
                    if m:
                        try:
                            cur[key] = conv(m.group(1))
                        except ValueError:
                            pass
                        break
        elif section == "LOG":
            if line.strip():
                d["log"].append(line)
        elif section == "LEASES":
            p = line.split()
            if len(p) >= 4:
                d["leases"].append({"expiry": p[0], "mac": p[1].lower(),
                                    "ip": p[2], "name": "" if p[3] == "*" else p[3]})
        elif section == "ACCT":
            if line.startswith("ACCT"):
                d["acct"] = line[5:].strip()
            elif line.startswith("DNSLOG"):
                d["dnslog"] = line[7:].strip()
            elif line.startswith("LOGSIZE"):
                d["logsize"] = line[8:].strip()
            elif line.startswith("WAN"):
                p = line.split()
                if len(p) >= 4:
                    try:
                        d["wan"] = (p[1], int(p[2]), int(p[3]))
                    except ValueError:
                        pass
        elif section == "CONNTRACK":
            d["conntrack"].append(line)
        elif section == "SW":
            swbuf.append(line)
        elif section == "EMAILS":
            try:
                e = json.loads(line)
                if isinstance(e, dict) and "t" in e:
                    d["emails"].append(e)
            except ValueError:
                pass
        elif section == "ACL":
            if line.strip() == "__MISSING__":
                d["acl"][aclname] = None          # no list file on the gateway
                continue
            body, _, comment = line.partition("#")
            tok = body.strip().lower()
            if ACL_MAC.match(tok) and d["acl"][aclname] is not None:
                d["acl"][aclname][tok] = comment.strip()
        elif section == "PORTS":
            d["ports"].append(line)
        elif section == "UCI":
            d["uci"].append(line.strip())
    if section == "SW":
        flush_sw()
    return d


def parse_conntrack_line(line):
    """-> dict(proto, state, src, dst, sport, dport, ob, rb) or None"""
    toks = line.split()
    if len(toks) < 6 or toks[0] != "ipv4":
        return None
    proto = toks[2]
    state = toks[5] if proto == "tcp" and "=" not in toks[5] else ""
    src, dst, sport, dport, byts = [], [], [], [], []
    for t in toks:
        k, eq, v = t.partition("=")
        if not eq:
            continue
        if k == "src":
            src.append(v)
        elif k == "dst":
            dst.append(v)
        elif k == "sport":
            sport.append(v)
        elif k == "dport":
            dport.append(v)
        elif k == "bytes":
            try:
                byts.append(int(v))
            except ValueError:
                pass
    if len(src) < 2 or len(dst) < 2:
        return None
    return {"proto": proto, "state": state, "src": src[0], "dst": dst[0],
            "rsrc": src[1], "rdst": dst[1],
            "sport": sport[0] if sport else "", "dport": dport[0] if dport else "",
            "ob": byts[0] if len(byts) > 0 else 0,
            "rb": byts[1] if len(byts) > 1 else 0,
            "acct": len(byts) >= 2}


SW_ROW = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+([\d.]+ [KMG]?B)\s+"
                    r"([\d.]+ [KMG]?B)\s+([\d.]+ [KMG]?B)\s*(-?\d+ dBm|wired|-)?")


def size_bytes(text):
    """'75.0 GB' -> bytes (StreamWatch uses 1024 steps)."""
    try:
        num, unit = text.split()
        return int(float(num) * {"B": 1, "KB": 1024, "MB": 1024 ** 2,
                                 "GB": 1024 ** 3}[unit])
    except (ValueError, KeyError):
        return ""


LOG_RE = re.compile(r"^(\w{3} \w{3}\s+\d+ \d\d:\d\d:\d\d \d{4}) (\S+?)\.(\S+) "
                    r"([^:\[\s]+)(?:\[(\d+)\])?:\s?(.*)$")
MAC_RE = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def log_time(text):
    try:
        return time.mktime(datetime.strptime(" ".join(text.split()),
                                             "%a %b %d %H:%M:%S %Y").timetuple())
    except ValueError:
        return None


# ------------------------------------------------------------------ recorder

class Recorder:
    def __init__(self, args):
        self.args = args
        self.out = Writer(args.out)
        self.pi_ips = pi_ips()
        self.pi_macs = pi_macs()
        self.router_ips = {v[0] for v in ROUTERS.values()}
        self.lan = args.lan_prefix
        # tracker files
        self.ev_path = os.path.join(TRACKER_DIR, "tracker_events.csv")
        self.state_path = os.path.join(TRACKER_DIR, "tracker_state.json")
        self.ev_offset = os.path.getsize(self.ev_path) if os.path.exists(self.ev_path) else 0
        self.ev_last = ""
        # per-router memory
        self.log_last = {}            # router -> (epoch, set(hashes at that second))
        self.sta_prev = {}            # (router, mac) -> (t, rx, tx)
        self.wan_prev = None          # (t, rx, tx)
        self.flows = {}               # key -> flow dict
        self.first_ct = True
        self.last_ct = None
        self.dev_tot = {}             # ip -> [in, out]
        self.names = {}               # mac -> name ; ip -> mac
        self.ip2mac = {}
        self.vendor = {}              # mac -> vendor text
        self.leases = {}              # mac -> ip
        self.sw_hash = {}             # (kind, key) -> hash of last written state
        self.access = {}              # mac -> GRANTED / BLOCKED / HELD (internet_access)
        self.emails_seen = set()      # hashes of email-log lines already written
        self.reach = {}               # router -> bool
        self.next_health = 0.0
        self.next_full = 0.0
        self.next_config = 0.0
        self.calib_mtime = None
        self.last_state_updated = ""

    # -------------------------------------------------------------- helpers
    def dev(self, ip=None, mac=None):
        """device columns from what we know."""
        mac = (mac or self.ip2mac.get(ip or "", "")).lower()
        if not ip and mac:
            ip = self.leases.get(mac, "")
        vendor = self.vendor.get(mac, "")
        if not vendor and mac:
            vendor = "randomised MAC" if is_randomised(mac) else ""
        return {"device_mac": mac, "device_ip": ip or "",
                "device_name": self.names.get(mac, ""), "device_vendor": vendor}

    def learn(self, mac, ip="", name=""):
        mac = (mac or "").lower()
        if not mac:
            return
        if ip:
            self.ip2mac[ip] = mac
            self.leases.setdefault(mac, ip)
        if name:
            self.names[mac] = name

    # -------------------------------------------------------------- tracker
    def tracker_rows(self, now):
        rows = []
        try:
            with open(self.state_path) as f:
                st = json.load(f)
        except (OSError, ValueError):
            st = None
        if st:
            for d in st.get("devices", []):
                self.learn(d.get("mac"), d.get("ip"), d.get("name"))
            if st.get("updated") != self.last_state_updated:
                self.last_state_updated = st.get("updated")
                for d in st.get("devices", []):
                    rows.append(rec("device_position", now,
                                    **st_fields(d.get("router")),
                                    **self.dev(d.get("ip"), d.get("mac")),
                                    lat=d.get("lat"), lon=d.get("lon"),
                                    dist_m=d.get("dist_m"),
                                    uncertainty_m=d.get("uncertainty_m"),
                                    rssi_dbm=d.get("rssi"), state=d.get("state"),
                                    detail="last seen %s" % d.get("last_seen", "")))
        # new tracker events (the file is only appended to)
        try:
            size = os.path.getsize(self.ev_path)
        except OSError:
            return rows
        if size < self.ev_offset:          # file was rewritten -- reread, skip old
            self.ev_offset = 0
        if size == self.ev_offset:
            return rows
        with open(self.ev_path, "rb") as f:
            f.seek(self.ev_offset)
            data = f.read()
        # keep only complete lines
        cut = data.rfind(b"\n")
        if cut < 0:
            return rows
        self.ev_offset += cut + 1
        text = data[:cut + 1].replace(b"\x00", b"").decode(errors="replace")
        for r in csv.reader(io.StringIO(text)):
            if len(r) < 6 or r[0] == "time":
                continue
            if self.ev_last and r[0] < self.ev_last:
                continue
            self.ev_last = r[0]
            rows.append(event_row(r, self))
        return rows

    # -------------------------------------------------------------- routers
    def router_rows(self, now, results, do_health, do_full):
        rows = []
        own = {}
        for name, d in results.items():
            if d:
                for i in d["ifaces"]:
                    own[i["addr"]] = name
                mac = d["sys"].get("MAC", "").lower()
                if mac:
                    own[mac] = name
        # names / leases from main123 first, so all rows get names
        main = results.get(MAIN)
        if main:
            for l in main["leases"]:
                old = self.leases.get(l["mac"])
                self.learn(l["mac"], l["ip"], l["name"])
                if old != l["ip"]:
                    self.leases[l["mac"]] = l["ip"]
                    rows.append(rec("dhcp_lease", now, **st_fields(MAIN),
                                    **self.dev(l["ip"], l["mac"]),
                                    category="new" if old is None else "changed",
                                    detail="expires %s" % iso(int(l["expiry"]))
                                    if l["expiry"].isdigit() else ""))
            for kind, data in main["sw"].items():
                if kind == "devices" and isinstance(data, dict):
                    for mac, r in data.items():
                        v = r.get("vendor", "")
                        if r.get("randomised") or "randomised" in v:
                            v = "randomised MAC"
                        if v:
                            self.vendor[mac.lower()] = v

        for name in ROUTERS:
            d = results.get(name)
            was = self.reach.get(name)
            self.reach[name] = d is not None
            if d is None:
                if was is not False or do_health:
                    rows.append(rec("router_health", now, **st_fields(name),
                                    category="unreachable",
                                    detail="no answer over SSH"))
                continue
            if was is False:
                rows.append(rec("router_health", now, **st_fields(name),
                                category="back", detail="answering again"))
            rows += self.station_rows(now, name, d, own, do_health)
            rows += self.log_rows(name, d)
            if do_health:
                rows.append(self.health_row(now, name, d))
            if do_full:
                rows += port_rows(now, name, d["ports"])
        if main:
            rows += self.conntrack_rows(now, main)
            rows += self.sw_rows(now, main)
            rows += self.access_rows(now, main)
            for what, key in (("dns query logging", "dnslog"), ("router log buffer", "logsize")):
                v = main.get(key) or ""
                if "enabled" in v or "raised" in v:
                    rows.append(rec("recorder", now, **st_fields(MAIN), category=what,
                                    detail="%s %s on main123 so every lookup by every "
                                    "device is recorded" % (what, v)))
            rows += self.email_rows(main)
        return rows

    def health_row(self, now, name, d):
        s = d["sys"]
        load = (s.get("LOAD") or "").split()
        mem = (s.get("MEM") or "").split()
        temp = s.get("TEMP", "")
        clients = sum(1 for x in d["stations"] if x.get("type") == "AP")
        kw = {}
        detail = ["uptime %s s" % s.get("UPTIME", "?")]
        if len(mem) == 2:
            detail.append("mem free %s of %s kB" % (mem[1], mem[0]))
        if temp.isdigit():
            detail.append("temp %.1f C" % (int(temp) / 1000.0))
        detail.append("wifi clients %d" % clients)
        if name == MAIN and d.get("wan"):
            w, rx, tx = d["wan"]
            kw.update(total_in=rx, total_out=tx)
            if self.wan_prev:
                pt, prx, ptx = self.wan_prev
                dt = max(now - pt, 1)
                din, dout = max(rx - prx, 0), max(tx - ptx, 0)
                kw.update(bytes_in=din, bytes_out=dout,
                          rate_in_kbps=din * 8 / 1000.0 / dt,
                          rate_out_kbps=dout * 8 / 1000.0 / dt)
            self.wan_prev = (now, rx, tx)
            detail.append("wan %s" % w)
            if d.get("acct"):
                detail.append("byte counting %s" % d["acct"])
            if d.get("dnslog"):
                detail.append("dns query logging %s" % d["dnslog"])
            if d.get("logsize"):
                detail.append("log buffer %s KB" % d["logsize"])
        return rec("router_health", now, **st_fields(name), category="ok",
                   value=load[0] if load else "", unit="load1",
                   duration_s=int(float(s.get("UPTIME", "0") or 0)),
                   detail="; ".join(detail), **kw)

    def station_rows(self, now, name, d, own, do_health):
        rows = []
        for s in d["stations"]:
            mac = s["mac"]
            prev = self.sta_prev.get((name, mac))
            rx, tx = s.get("rx_bytes"), s.get("tx_bytes")
            kw = {}
            if rx is not None and tx is not None:
                if prev:
                    pt, prx, ptx = prev
                    dt = max(now - pt, 1)
                    din = tx - ptx if tx >= ptx else tx     # router tx = device in
                    dout = rx - prx if rx >= prx else rx
                    kw.update(bytes_in=din, bytes_out=dout,
                              rate_in_kbps=din * 8 / 1000.0 / dt,
                              rate_out_kbps=dout * 8 / 1000.0 / dt)
                self.sta_prev[(name, mac)] = (now, rx, tx)
                kw.update(total_in=tx, total_out=rx)
            common = dict(rssi_dbm=s.get("signal"), rssi_avg_dbm=s.get("signal_avg"),
                          band=s.get("band"), channel=s.get("ch"),
                          tx_bitrate_mbps=s.get("tx_rate"),
                          rx_bitrate_mbps=s.get("rx_rate"),
                          inactive_ms=s.get("inactive_ms"),
                          connected_s=s.get("connected_s"), **kw)
            if s.get("plink") or s.get("type") == "mesh":
                # for a mesh link: in = received from the peer, out = sent to it
                for a_, b_ in (("bytes_in", "bytes_out"), ("rate_in_kbps", "rate_out_kbps"),
                               ("total_in", "total_out")):
                    if a_ in common:
                        common[a_], common[b_] = common[b_], common[a_]
                if do_health:
                    rows.append(rec("mesh_link", now, **st_fields(name),
                                    peer=own.get(mac, mac), link_state=s.get("plink"),
                                    detail="peer radio %s on %s" % (mac, s["if"]),
                                    **common))
            elif s.get("type") == "AP":
                if s.get("inactive_ms") is not None and s["inactive_ms"] > 15000:
                    continue           # stale entry of a phone that roamed away
                rows.append(rec("wifi_station", now, **st_fields(name),
                                **self.dev(mac=mac), detail="iface %s" % s["if"],
                                **common))
        return rows

    def log_rows(self, name, d):
        rows = []
        last_t, seen = self.log_last.get(name, (0, set()))
        first_time = name not in self.log_last
        new_t, new_seen = last_t, set(seen)
        for line in d["log"]:
            m = LOG_RE.match(line)
            if not m:
                continue
            t = log_time(m.group(1))
            if t is None:
                continue
            h = hashlib.md5(line.encode()).hexdigest()[:12]
            if t < last_t or (t == last_t and h in seen):
                continue
            if t > new_t:
                new_t, new_seen = t, set()
            if t == new_t:
                new_seen.add(h)
            if first_time and t < time.time() - self.args.log_backfill:
                continue               # at start, only the last few minutes
            r = self.log_row(name, t, m.group(2), m.group(3), m.group(4), m.group(6))
            if r:
                rows.append(r)
        self.log_last[name] = (new_t, new_seen)
        return rows

    def log_row(self, name, t, facility, level, prog, msg):
        msg = msg.strip()
        st = st_fields(name)
        low = prog.lower()
        if low.startswith("dropbear"):
            if any(ip in msg for ip in self.pi_ips) and re.search(
                    r"Child connection|Pubkey auth succeeded|Exit \(root\)|"
                    r"Disconnect received", msg):
                return None            # the tracker/recorder's own logins
            cat = "ssh_fail" if re.search(r"Bad password|nonexistent user|"
                                          r"Max auth|Login attempt|auth fail",
                                          msg, re.I) else "ssh"
            ipm = IP_RE.search(msg)
            return rec("router_log", t, **st, category=cat, state=level,
                       src_ip=ipm.group(1) if ipm else "", detail=msg)
        if low.startswith("python"):          # StreamWatch prints via procd
            lm = re.search(r"\[speed\] latency (\d+(?:\.\d+)?) ms", msg)
            if lm:
                return rec("internet_latency", t, **st, value=float(lm.group(1)),
                           unit="ms", category="streamwatch probe")
            # the per-minute usage table: one structured row per device
            um = SW_ROW.match(msg)
            if um:
                ip, host = um.group(1), um.group(2)
                sig = um.group(6) or ""
                kw = self.dev(ip=ip)
                if host != "-" and not kw["device_name"]:
                    kw["device_name"] = host
                return rec("sw_usage", t, **st, **kw, category="streamwatch totals",
                           total_in=size_bytes(um.group(3)), total_out=size_bytes(um.group(4)),
                           value=size_bytes(um.group(5)), unit="bytes total",
                           rssi_dbm=sig.split()[0] if "dBm" in sig else "",
                           state="wired" if sig == "wired" else "",
                           detail="IN %s, OUT %s, TOTAL %s" % (um.group(3), um.group(4), um.group(5)))
            fm = re.match(r"(\d+) device\(s\), (\d+) live flows", msg)
            if fm:
                return rec("sw_usage", t, **st, category="streamwatch summary",
                           value=int(fm.group(2)), unit="live flows",
                           detail="%s devices metered" % fm.group(1))
            if not msg or msg.startswith("--") or msg.startswith("IP ") \
                    or re.match(r"\[commands: examined .* found 0 close, 0 open, 0 limit, "
                                r"0 unlimit, 0 throttl", msg):
                return None            # table header / spacer / empty command poll
            mm = re.match(r"MOVE\s+\S+ \S+\s+(\S+) is (\w+)\s+\[(.*)\]", msg)
            if mm:
                sig = re.search(r"now (-?\d+) dBm", mm.group(3))
                return rec("router_log", t, **st, category="streamwatch_move",
                           **self.dev(ip=mm.group(1)), state=mm.group(2).upper(),
                           rssi_dbm=int(sig.group(1)) if sig else "", detail=msg)
            ipm = IP_RE.search(msg)
            return rec("router_log", t, **st, category="streamwatch", state=level,
                       **(self.dev(ip=ipm.group(1)) if ipm else {}), detail=msg)
        if low == "dnsmasq":
            q = re.search(r"query\[(\w+)\] (\S+) from (\S+)", msg)
            if q:
                if self.args.no_dns:
                    return None
                return rec("dns_query", t, **st, category=q.group(1),
                           **self.dev(ip=q.group(3)), domain=q.group(2).lower(),
                           detail=q.group(2))
            if re.search(r"^(reply|forwarded|cached|config|/)", msg):
                return None            # the other half of each lookup: noise
            return rec("router_log", t, **st, category="dns", state=level, detail=msg)
        if low.startswith("dnsmasq-dhcp"):
            macm, ipm = MAC_RE.search(msg), IP_RE.search(msg)
            nm = re.search(r"[0-9a-f:]{17} (\S+)$", msg, re.I)
            if macm:
                self.learn(macm.group(1), ipm.group(1) if ipm else "",
                           nm.group(1) if nm else "")
            return rec("router_log", t, **st, category="dhcp", state=level,
                       **self.dev(ip=ipm.group(1) if ipm else None,
                                  mac=macm.group(1) if macm else None),
                       detail=msg)
        if low.startswith("hostapd") or low.startswith("wpa_supplicant"):
            macm = MAC_RE.search(msg)
            ev = re.search(r"(AP-STA-[A-Z-]+|associated|disassociated|"
                           r"deauthenticated|authenticated)", msg)
            return rec("router_log", t, **st, category="wifi", state=level,
                       **(self.dev(mac=macm.group(1)) if macm else {}),
                       link_state=ev.group(1) if ev else "", detail=msg)
        if low == "kernel":
            return rec("router_log", t, **st, category="kernel", state=level, detail=msg)
        if low in ("netifd", "odhcpd", "odhcp6c", "ntpd", "firewall", "fw4"):
            return rec("router_log", t, **st, category="network", state=level,
                       detail="%s: %s" % (prog, msg))
        return rec("router_log", t, **st, category="system", state=level,
                   detail="%s: %s" % (prog, msg))

    def conntrack_rows(self, now, main):
        rows = []
        cur = {}
        per_dev = {}
        acct_seen = False
        for line in main["conntrack"]:
            c = parse_conntrack_line(line)
            if not c:
                continue
            acct_seen = acct_seen or c["acct"]
            s_lan, d_lan = in_lan(c["src"], self.lan), in_lan(c["dst"], self.lan)
            if not (s_lan or d_lan):
                if in_lan(c["rsrc"], self.lan):        # port-forward (DNAT) to a device
                    d_lan = True
                    c = dict(c, dst=c["rsrc"])
                else:
                    continue
            # the Pi's own management logins to the routers: noise
            if c["dport"] == "22" and c["src"] in self.pi_ips and c["dst"] in self.router_ips:
                continue
            if s_lan and not d_lan:
                dev_ip, direction = c["src"], "outbound"
            elif d_lan and not s_lan:
                dev_ip, direction = c["dst"], "inbound"
            else:
                dev_ip, direction = c["src"], "local"
            key = (c["proto"], c["src"], c["sport"], c["dst"], c["dport"])
            cur[key] = True
            f = self.flows.get(key)
            if f is not None and (c["ob"] < f["ob"] or c["rb"] < f["rb"]):
                rows.append(self.flow_row("flow_end", now, f))   # key reused
                f = None
            if f is None:
                f = self.flows[key] = dict(c, first=now, last=now, dev=dev_ip,
                                           dir=direction, partial=self.first_ct,
                                           base_ob=c["ob"] if self.first_ct else 0,
                                           base_rb=c["rb"] if self.first_ct else 0,
                                           reported=now)
                d_o, d_r = 0 if self.first_ct else c["ob"], 0 if self.first_ct else c["rb"]
            else:
                d_o, d_r = c["ob"] - f["ob"], c["rb"] - f["rb"]
                f.update(ob=c["ob"], rb=c["rb"], state=c["state"], last=now)
            # device perspective: outbound/local -> orig is upload
            if direction == "inbound":
                din, dout = d_o, d_r
            else:
                din, dout = d_r, d_o
            pd = per_dev.setdefault(dev_ip, [0, 0, 0])
            pd[0] += din
            pd[1] += dout
            pd[2] += 1
            # long-running connection report
            if now - f["reported"] >= self.args.flow_update and now - f["first"] >= self.args.flow_update:
                f["reported"] = now
                rows.append(self.flow_row("flow_active", now, f))
        # finished connections
        for key in [k for k in self.flows if k not in cur]:
            f = self.flows.pop(key)
            if not f["partial"] or f["ob"] + f["rb"] > f["base_ob"] + f["base_rb"]:
                rows.append(self.flow_row("flow_end", now, f))
        self.first_ct = False
        # per-device usage for this interval
        dt = max(now - self.last_ct, 1.0) if self.last_ct else self.args.interval
        self.last_ct = now
        for ip, (din, dout, n) in sorted(per_dev.items()):
            tot = self.dev_tot.setdefault(ip, [0, 0])
            tot[0] += din
            tot[1] += dout
            if din or dout:
                rows.append(rec("device_traffic", now, **st_fields(MAIN), **self.dev(ip=ip),
                                bytes_in=din, bytes_out=dout,
                                rate_in_kbps=din * 8 / 1000.0 / dt,
                                rate_out_kbps=dout * 8 / 1000.0 / dt,
                                total_in=tot[0], total_out=tot[1],
                                value=n, unit="active connections"))
        if main["conntrack"] and not acct_seen and not getattr(self, "_warned_acct", False):
            self._warned_acct = True
            rows.append(rec("recorder", now, category="warning",
                            detail="main123 connection table has no byte counters "
                                   "(nf_conntrack_acct off?) -- data usage will read 0"))
        if "enabled" in (main.get("acct") or ""):
            rows.append(rec("recorder", now, category="info",
                            detail="switched on nf_conntrack_acct on main123 so data "
                                   "usage can be measured"))
        return rows

    def flow_row(self, kind, now, f):
        ob, rb = f["ob"] - f["base_ob"], f["rb"] - f["base_rb"]
        if f["dir"] == "inbound":
            bin_, bout = ob, rb
        else:
            bin_, bout = rb, ob
        port = f["dport"]
        return rec(kind, now, **st_fields(MAIN), **self.dev(ip=f["dev"]),
                   proto=f["proto"], src_ip=f["src"], src_port=f["sport"],
                   dst_ip=f["dst"], dst_port=port,
                   service=service_of(f["proto"], port), direction=f["dir"],
                   bytes_in=bin_, bytes_out=bout,
                   duration_s=int(f["last"] - f["first"]),
                   link_state=f.get("state", ""),
                   detail="started before the recorder (bytes partial)" if f["partial"] else "")

    def sw_rows(self, now, main):
        rows = []

        def changed(kind, key, obj):
            h = hashlib.md5(json.dumps(obj, sort_keys=True).encode()).hexdigest()
            if self.sw_hash.get((kind, key)) == h:
                return False
            self.sw_hash[(kind, key)] = h
            return True

        q = main["sw"].get("quotas")
        if isinstance(q, dict):
            for ip, v in q.items():
                if isinstance(v, dict) and changed("q", ip, v):
                    rows.append(rec("sw_quota", now, **st_fields(MAIN), **self.dev(ip=ip),
                                    value=v.get("limit"), unit="bytes limit",
                                    total_in=v.get("used"),
                                    category=v.get("period", "none"),
                                    state="BLOCKED" if v.get("blocked") else "ok",
                                    detail=json.dumps(v, sort_keys=True)))
        t = main["sw"].get("throttles")
        if isinstance(t, dict):
            for ip, v in t.items():
                if isinstance(v, dict) and changed("t", ip, v):
                    rows.append(rec("sw_throttle", now, **st_fields(MAIN), **self.dev(ip=ip),
                                    category="throttle",
                                    detail="down %s kbit, up %s kbit" % (
                                        v.get("down", "-"), v.get("up", "-"))))
        dv = main["sw"].get("devices")
        if isinstance(dv, dict):
            for mac, v in dv.items():
                if not isinstance(v, dict):
                    continue
                slim = {k: v.get(k) for k in ("vendor", "randomised", "first_seen",
                                              "hostnames", "ips")}
                if changed("d", mac, slim):
                    ips = v.get("ips") or []
                    rows.append(rec("device_inventory", now, **st_fields(MAIN),
                                    **self.dev(ip=ips[-1] if ips else None, mac=mac),
                                    category="randomised MAC" if v.get("randomised") else "fixed MAC",
                                    detail="first seen %s; hostnames %s; ips %s" % (
                                        iso(v["first_seen"]) if v.get("first_seen") else "?",
                                        ",".join(v.get("hostnames") or []) or "-",
                                        ",".join(ips) or "-")))
        # quotas / throttles that disappeared
        for kind, typ in (("q", "sw_quota"), ("t", "sw_throttle")):
            src = q if kind == "q" else t
            if not isinstance(src, dict):
                continue
            for (k2, ip) in [x for x in self.sw_hash if x[0] == kind]:
                if ip not in src:
                    del self.sw_hash[(k2, ip)]
                    rows.append(rec(typ, now, **st_fields(MAIN), **self.dev(ip=ip),
                                    category="removed", detail="no longer set"))
        return rows

    def access_rows(self, now, main):
        """internet_access rows: one per device whenever its access changes.

        GRANTED = on allow.txt, BLOCKED = on deny.txt (wins if on both, BR-2),
        HELD = has a DHCP lease but is on neither list (address, no internet).
        Nothing is written when the gateway has no list files -- then StreamWatch
        is not gating and 'held' would be false.
        """
        acl = main.get("acl") or {}
        allow, deny = acl.get("allow"), acl.get("deny")
        if allow is None and deny is None:
            return []
        allow, deny = allow or {}, deny or {}
        want = {}
        for mac in deny:
            want[mac] = ("BLOCKED", deny[mac])
        for mac in allow:
            want.setdefault(mac, ("GRANTED", allow[mac]))
        for l in main["leases"]:
            want.setdefault(l["mac"], ("HELD", ""))
        # a device that left both lists and has no lease: access is gone too
        for mac in self.access:
            if mac not in want:
                want[mac] = ("HELD", "removed from the lists")

        rows = []
        for mac, (state, note) in want.items():
            prev = self.access.get(mac)
            if prev == state:
                continue
            self.access[mac] = state
            m = ACCESS_TIME.search(note or "")
            rows.append(rec("internet_access", now, **st_fields(MAIN), **self.dev(mac=mac),
                            state=state,
                            access_time=m.group(1) if m else "",
                            category="initial" if prev is None else "%s->%s" % (prev, state),
                            detail=note))
        return rows

    def email_rows(self, main):
        """One row per email in StreamWatch's email log, at the email's own
        time. The gateway keeps a rolling tail, so lines already written are
        remembered by hash and skipped."""
        rows = []
        for e in main.get("emails") or []:
            key = hashlib.md5(json.dumps(e, sort_keys=True).encode()).hexdigest()
            if key in self.emails_seen:
                continue
            self.emails_seen.add(key)
            try:
                t = float(e["t"])
            except (TypeError, ValueError):
                continue
            rows.append(rec("email", t, **st_fields(MAIN),
                            category=e.get("dir", ""),
                            email_from=e.get("from", ""),
                            email_to=e.get("to", ""),
                            email_subject=e.get("subject", ""),
                            detail=e.get("detail", "")))
        return rows

    # -------------------------------------------------------------- pi + config
    def pi_rows(self, now, do_health, do_full):
        rows = []
        ip = sorted(self.pi_ips)[0] if self.pi_ips else ""
        if do_health:
            try:
                up = open("/proc/uptime").read().split()[0]
                load = open("/proc/loadavg").read().split()[0]
            except OSError:
                up, load = "", ""
            temp = ""
            try:
                temp = "%.1f C" % (int(open("/sys/class/thermal/thermal_zone0/temp").read()) / 1000.0)
            except (OSError, ValueError):
                pass
            du = shutil.disk_usage(self.args.out)
            rows.append(rec("router_health", now, station="pi", station_ip=ip,
                            category="ok", value=load, unit="load1",
                            duration_s=int(float(up or 0)),
                            detail="temp %s; disk free %.1f GB of %.1f GB; records written %d"
                                   % (temp or "?", du.free / 1e9, du.total / 1e9, self.out.count)))
        if do_full:
            try:
                out = subprocess.run(["ss", "-ltnuH"], stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, timeout=10).stdout.decode()
            except (OSError, subprocess.SubprocessError):
                out = ""
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 5:
                    local = p[4]
                    host, _, port = local.rpartition(":")
                    rows.append(rec("open_port", now, station="pi", station_ip=ip,
                                    proto=p[0], dst_ip=host.strip("[]"), dst_port=port,
                                    service=service_of(p[0], port), state=p[1]))
        return rows

    def config_rows(self, now, results):
        rows = []
        try:
            calib = json.load(open(CALIB_FILE))
        except (OSError, ValueError):
            calib = {}
        try:
            locs = json.load(open(self.state_path)).get("locations", {})
        except (OSError, ValueError):
            locs = {}
        for name in ROUTERS:
            d = results.get(name)
            site = calib.get("sites", {}).get(name) or locs.get(name) or {}
            c = calib.get("routers", {}).get(name, {})
            radios = []
            if d:
                for i in d["ifaces"]:
                    if i["type"] == "AP":
                        radios.append("%s %s ch%s '%s'" % (i["if"], band_of(i["freq"]),
                                                          i["ch"], i["ssid"]))
                    elif i["type"] == "mesh":
                        radios.append("%s mesh ch%s" % (i["if"], i["ch"]))
            info = {"calibration_A_dbm_at_1m": c.get("A"), "calibration_n": c.get("n"),
                    "calibration_r2": c.get("r2"), "calibrated": c.get("created"),
                    "radios": radios, "uci": d["uci"] if d else []}
            rows.append(rec("station_config", now, **st_fields(name),
                            device_mac=(d["sys"].get("MAC", "") if d else ""),
                            lat=site.get("lat"), lon=site.get("lon"),
                            category=ROUTERS[name][2],
                            state="online" if d else "unreachable",
                            detail=json.dumps(info)))
        rows.append(rec("station_config", now, station="pi",
                        station_ip=",".join(sorted(self.pi_ips)),
                        device_mac=",".join(sorted(m for m in self.pi_macs if m != "00:00:00:00:00:00")),
                        category="tracker / map / recorder host (fixed at L1)"))
        return rows

    # -------------------------------------------------------------- loop
    def run(self):
        a = self.args
        write_dictionary(a.out)
        self.out.write([rec("recorder", time.time(), category="start",
                            detail="interval %ss, health every %ss, output %s"
                                   % (a.interval, a.health, a.out))])
        try:
            while True:
                t0 = time.time()
                now = float(int(t0))
                do_health = now >= self.next_health
                do_full = now >= self.next_full
                if do_health:
                    self.next_health = now + a.health
                if do_full:
                    self.next_full = now + 3600
                results = {}

                def work(n):
                    raw = fetch(n, do_full, a.log_lines, dns=not a.no_dns)
                    results[n] = parse_router(raw) if raw else None

                threads = [threading.Thread(target=work, args=(n,)) for n in ROUTERS]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                rows = self.router_rows(now, results, do_health, do_full)
                rows = self.tracker_rows(now) + rows
                rows += self.pi_rows(now, do_health, do_full)
                try:
                    cm = os.path.getmtime(CALIB_FILE)
                except OSError:
                    cm = None
                if now >= self.next_config or cm != self.calib_mtime:
                    self.calib_mtime = cm
                    self.next_config = now + 86400
                    rows += self.config_rows(now, results)
                self.out.write(rows)
                if a.verbose:
                    kinds = {}
                    for r in rows:
                        kinds[r["record_type"]] = kinds.get(r["record_type"], 0) + 1
                    print("%s  %d rows  %s" % (time.strftime("%H:%M:%S"), len(rows),
                          " ".join("%s=%d" % kv for kv in sorted(kinds.items()))), flush=True)
                time.sleep(max(1.0, a.interval - (time.time() - t0)))
        except KeyboardInterrupt:
            pass
        finally:
            self.out.write([rec("recorder", time.time(), category="stop",
                                detail="%d rows written this run" % self.out.count)])
            self.out.close()


def port_rows(now, name, lines):
    rows = []
    for line in lines:
        p = line.split()
        if len(p) < 4 or p[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        host, _, port = p[3].rpartition(":")
        proto = p[0].rstrip("6")
        rows.append(rec("open_port", now, **st_fields(name), proto=proto,
                        dst_ip=host, dst_port=port, service=service_of(proto, port),
                        state=p[5] if len(p) > 5 else ""))
    return rows


# ------------------------------------------------------------------ history

def event_row(r, ctx=None):
    """tracker_events.csv row -> unified record (numbers parsed out of detail)."""
    t = local_epoch(r[0]) or time.time()
    mac, ip, name, ev, detail = r[1].lower(), r[2], r[3], r[4], r[5]
    kw = {"device_mac": mac, "device_ip": "" if ip == "?" else ip,
          "device_name": name,
          "device_vendor": "randomised MAC" if is_randomised(mac) else ""}
    if ctx:
        ctx.learn(mac, kw["device_ip"], name)
    m = re.search(r"Location (\d) -> Location (\d)", detail)
    if m:
        kw.update(st_fields(label_to_station("L" + m.group(2))),
                  peer=label_to_station("L" + m.group(1)))
    m = re.search(r"(-?\d+) dBm at Location (\d)", detail)
    if m:
        kw.update(st_fields(label_to_station("L" + m.group(2))), rssi_dbm=int(m.group(1)))
    m = re.search(r"([\d.]+) m from Location (\d)", detail)
    if m:
        kw.update(st_fields(label_to_station("L" + m.group(2))), dist_m=float(m.group(1)))
    m = re.search(r"^at Location (\d)", detail)
    if m:
        kw.update(st_fields(label_to_station("L" + m.group(1))))
    m = re.search(r"^at ([\d.]+) m \((.*)\)", detail)       # 2-router era
    if m:
        kw.update(value=float(m.group(1)), unit="m along L1-L2 path (2-router era)")
        s = label_to_station(m.group(2))
        if s:
            kw.update(st_fields(s))
    state = ev if re.match(r"(IDLE|APPROACHING|LEAVING|MOVING|SETTLING)", ev) else ""
    return rec("tracker_event", t, category=ev, state=state, detail=detail, **kw)


def import_history(args):
    out_dir = os.path.join(args.out, "history")
    os.makedirs(out_dir, exist_ok=True)
    path = args.o or os.path.join(out_dir, "tracker_history_%s.csv" % time.strftime("%Y-%m-%d"))
    n = {"tracker_event": 0, "device_position": 0}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        rows = history_rows(args.events, args.log, args.state)
        rows.sort(key=lambda r: r["epoch"])
        for r in rows:
            w.writerow(r)
            n[r["record_type"]] = n.get(r["record_type"], 0) + 1
    write_dictionary(args.out)
    print("wrote %s" % path)
    for k, v in sorted(n.items()):
        print("  %-18s %d rows" % (k, v))


def calibration_rows(path):
    rows = []
    try:
        cal = json.load(open(path))
    except (OSError, ValueError):
        return rows
    for name, c in cal.get("routers", {}).items():
        t = local_epoch(c.get("created", "") + ":00", "%Y-%m-%d %H:%M:%S") or time.time()
        A, n = c.get("A"), c.get("n")
        for p in c.get("points", []):
            d, r = p.get("distance_m"), p.get("rssi_dbm")
            back = 10 ** ((A - r) / (10.0 * n)) if (A is not None and n and r is not None) else None
            rows.append(rec("calibration_point", t, **st_fields(name), category=p.get("label", ""),
                            device_mac=c.get("phone", ""), dist_m=d, rssi_dbm=r,
                            value=back, unit="m (model)",
                            detail="fit A=%s dBm n=%s R2=%s; %d readings %s" % (
                                A, n, c.get("r2"), len(p.get("readings") or []),
                                p.get("readings") or "")))
    return rows


def history_rows(events_path, log_path, state_path, calib_path=CALIB_FILE):
    rows = calibration_rows(calib_path)
    if events_path and os.path.exists(events_path):
        with open(events_path, "rb") as f:
            text = f.read().replace(b"\x00", b"").decode(errors="replace")
        for r in csv.reader(io.StringIO(text)):
            if len(r) >= 6 and r[0] != "time" and local_epoch(r[0]):
                rows.append(event_row(r))
    if log_path and os.path.exists(log_path):
        with open(log_path, "rb") as f:
            text = f.read().replace(b"\x00", b"").decode(errors="replace")
        for r in csv.reader(io.StringIO(text)):
            if not r or r[0] == "time":
                continue
            t = local_epoch(r[0])
            if t is None:
                continue
            mac = r[1].lower() if len(r) > 1 else ""
            base = {"device_mac": mac, "device_ip": r[2] if len(r) > 2 else "",
                    "device_name": r[3] if len(r) > 3 else "",
                    "device_vendor": "randomised MAC" if is_randomised(mac) else ""}
            if len(r) == 11 and r[4] in ROUTERS:
                rows.append(rec("device_position", t, **st_fields(r[4]), **base,
                                rssi_dbm=r[6], dist_m=r[7], lat=r[8], lon=r[9],
                                state=r[10], detail="tracker log"))
            else:
                rows.append(rec("device_position", t, **base, category="legacy format",
                                detail=",".join(r[4:])))
    if state_path and os.path.exists(state_path):
        try:
            st = json.load(open(state_path))
        except ValueError:
            st = {}
        t = local_epoch(st.get("updated", "")) or time.time()
        for d in st.get("devices", []):
            mac = d.get("mac", "")
            rows.append(rec("device_position", t, **st_fields(d.get("router")),
                            device_mac=mac, device_ip=d.get("ip"), device_name=d.get("name"),
                            device_vendor="randomised MAC" if is_randomised(mac) else "",
                            lat=d.get("lat"), lon=d.get("lon"), dist_m=d.get("dist_m"),
                            uncertainty_m=d.get("uncertainty_m"), rssi_dbm=d.get("rssi"),
                            state=d.get("state"), detail="tracker state snapshot"))
        for name, l in st.get("locations", {}).items():
            rows.append(rec("station_config", t, **st_fields(name), lat=l.get("lat"),
                            lon=l.get("lon"), category=l.get("label"),
                            value=l.get("zone_radius_m"), unit="zone radius m"))
        for l in st.get("links", []):
            rows.append(rec("station_config", t, **st_fields(l["a"]), peer=l["b"],
                            category="station distance", value=l["distance_m"], unit="m"))
    return rows


# ------------------------------------------------------------------ export

def export(args):
    try:
        _export(args)
    except BrokenPipeError:          # e.g. piped into head
        pass


def _export(args):
    t_from = local_epoch(args.t_from, "%Y-%m-%d %H:%M") if args.t_from else 0
    t_to = local_epoch(args.t_to, "%Y-%m-%d %H:%M") if args.t_to else 1e12
    if args.t_from and t_from is None or args.t_to and t_to is None:
        sys.exit('use times like "2026-09-30 08:00"')
    types = set(t.strip() for t in args.types.split(",")) if args.types else None
    files = sorted(glob.glob(os.path.join(args.out, "records_*.csv*")) +
                   glob.glob(os.path.join(args.out, "history", "*.csv")))
    out = open(args.o, "w", newline="", encoding="utf-8") if args.o else sys.stdout
    w = csv.DictWriter(out, fieldnames=FIELDS)
    w.writeheader()
    n = 0
    for p in files:
        opener = gzip.open if p.endswith(".gz") else open
        with opener(p, "rt", newline="", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                try:
                    e = int(r.get("epoch") or 0)
                except ValueError:
                    continue
                if e < t_from or e > t_to:
                    continue
                if types and r.get("record_type") not in types:
                    continue
                w.writerow({k: r.get(k, "") for k in FIELDS})
                n += 1
    if args.o:
        out.close()
        print("wrote %d rows to %s" % (n, args.o))


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "import-history", "export", "dictionary", "note"])
    ap.add_argument("text", nargs="*", help="note: what you changed (free text)")
    ap.add_argument("--out", default=OUT_DIR, help="records folder (default ~/mesh_records)")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="seconds between samples (default 10)")
    ap.add_argument("--health", type=float, default=60.0,
                    help="seconds between health / mesh-link rows (default 60)")
    ap.add_argument("--flow-update", type=float, default=600.0,
                    help="report long connections every N s (default 600)")
    ap.add_argument("--log-lines", type=int, default=4000,
                    help="router log lines read per sample (default 4000; DNS "
                         "query logging writes several lines per lookup)")
    ap.add_argument("--log-backfill", type=float, default=600.0,
                    help="at start, include router log lines from the last N s")
    ap.add_argument("--lan-prefix", default="192.168.8.",
                    help="LAN address prefix (default 192.168.8.)")
    ap.add_argument("--no-dns", action="store_true",
                    help="don't record domain lookups")
    ap.add_argument("--verbose", action="store_true", help="print a line per sample")
    # import-history
    ap.add_argument("--events", default=os.path.join(TRACKER_DIR, "tracker_events.csv"))
    ap.add_argument("--log", default=os.path.join(TRACKER_DIR, "tracker_log.csv"))
    ap.add_argument("--state", default=os.path.join(TRACKER_DIR, "tracker_state.json"))
    # export
    ap.add_argument("--from", dest="t_from", help='export start, "YYYY-MM-DD HH:MM"')
    ap.add_argument("--to", dest="t_to", help='export end, "YYYY-MM-DD HH:MM"')
    ap.add_argument("--types", help="export only these record types (comma list)")
    ap.add_argument("-o", help="output file (export / import-history)")
    args = ap.parse_args()

    if args.command == "note":
        if not args.text:
            sys.exit('usage: python3 mesh_recorder.py note "moved 456 two metres north"')
        w = Writer(args.out)
        w.write([rec("change_log", time.time(), category="manual note",
                     detail=" ".join(args.text))])
        w.close()
        print("noted in %s" % os.path.join(args.out, "records_%s.csv" % time.strftime("%Y-%m-%d")))
    elif args.command == "dictionary":
        write_dictionary(args.out)
        print("wrote %s/DATA_DICTIONARY.md and data_dictionary.csv" % args.out)
    elif args.command == "import-history":
        import_history(args)
    elif args.command == "export":
        export(args)
    else:
        Recorder(args).run()


if __name__ == "__main__":
    main()
