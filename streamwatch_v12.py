#!/usr/bin/env python3
"""
streamwatch.py - watch per-device traffic through the gateway and alert on a
                 cumulative data threshold.

Runs ON the gateway (GL-MT3000 / OpenWrt). Pure standard library.

WHY CONNTRACK AND NOT PACKET CAPTURE
    A byte counter on a network card only ever describes that card. On the
    gateway, forwarded traffic is already accounted per-connection by the
    kernel's connection tracker, split by direction. Reading it costs nothing
    and cannot miss a packet the way a userspace capture loop can.

WHAT "LOCAL" MEANS HERE
    On a host, local == "me". On a gateway, neither end of a forwarded
    connection is the gateway, so local must mean "inside a LAN subnet".
    Subnets are read from the interfaces, with the WAN interface excluded.

COUNTERS ARE CUMULATIVE, ENTRIES ARE NOT
    A conntrack entry disappears when the connection closes and its bytes
    disappear with it. Summing live entries would make totals fall over time.
    This tracks each connection's last-seen counter and accumulates only the
    DELTA, so a closed connection keeps the bytes it already contributed.

Usage:
    python3 streamwatch.py                          alert at 1000K per device
    python3 streamwatch.py --threshold 5M
    python3 streamwatch.py --interval 5 --csv traffic.csv
    python3 streamwatch.py --direction in           threshold on inbound only
    python3 streamwatch.py --email-to me@example.com --smtp-host smtp.gmail.com \
                           --smtp-user me@example.com --smtp-pass APPPASSWORD
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

CREDS_FILE = "/root/.streamwatch_env"

# Mailbox login. INTENTIONALLY BLANK in version control.
#
# A committed secret stays in git history after the line is deleted, so the
# only real cleanup is rotating it -- which is why these are empty here. Supply
# the login at runtime by ONE of:
#   * export STREAMWATCH_EMAIL_USER / STREAMWATCH_EMAIL_PASS  (a one-off run)
#   * put them in CREDS_FILE (/root/.streamwatch_env), chmod 600, kept out of git
# load_credentials() below reads either and never needs this file edited.
#
# If you previously ran a build with a password hard-coded here, treat that
# password as compromised and rotate it (Gmail: revoke the App Password).
EMBEDDED_EMAIL_USER = ""
EMBEDDED_EMAIL_PASS = ""


def load_credentials():
    """Fill in the mailbox login. Precedence, highest first:

        1. exported environment variables  -- a one-off override
        2. CREDS_FILE                      -- if you later move it out of here
        3. the EMBEDDED_ constants above   -- the normal case

    Order matters: a temporary export must be able to beat the embedded value
    without editing the script, or testing a second mailbox means a code edit.
    """
    try:
        mode = os.stat(CREDS_FILE).st_mode
        if mode & 0o077:
            print("WARNING: %s is readable by other users. Fix with: chmod 600 %s"
                  % (CREDS_FILE, CREDS_FILE))
        with open(CREDS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip().lstrip("export ").strip()
                val = val.strip().strip('"').strip("'")
                if key.startswith("STREAMWATCH_") and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass          # no file is not an error -- the constants below cover it

    if not os.environ.get("STREAMWATCH_EMAIL_USER") and EMBEDDED_EMAIL_USER:
        os.environ["STREAMWATCH_EMAIL_USER"] = EMBEDDED_EMAIL_USER
    if not os.environ.get("STREAMWATCH_EMAIL_PASS") and EMBEDDED_EMAIL_PASS:
        os.environ["STREAMWATCH_EMAIL_PASS"] = EMBEDDED_EMAIL_PASS


CONNTRACK_PROC = "/proc/net/nf_conntrack"
ACCT_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_acct"
ROUTE_PROC = "/proc/net/route"


# --------------------------------------------------------------- ip helpers

def ip_to_int(ip):
    """Dotted quad -> int. No imports, so python3-light is enough."""
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(ip)
    n = 0
    for p in parts:
        v = int(p)
        if not 0 <= v <= 255:
            raise ValueError(ip)
        n = (n << 8) | v
    return n


def in_net(ip, net):
    base, mask = net
    try:
        return (ip_to_int(ip) & mask) == base
    except ValueError:
        return False


def cidr_to_net(ip, prefix):
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_to_int(ip) & mask, mask)


def net_to_str(net):
    base, mask = net
    dotted = ".".join(str((base >> s) & 0xFF) for s in (24, 16, 8, 0))
    return "%s/%d" % (dotted, bin(mask).count("1"))


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def wan_iface():
    """Interface holding the default route - its subnet is upstream, not LAN."""
    try:
        with open(ROUTE_PROC) as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) > 2 and c[1] == "00000000":
                    return c[0]
    except OSError:
        pass
    return None


def lan_networks(override=None):
    """[(base, mask), ...] for every LAN subnet on this box."""
    if override:
        nets = []
        for spec in override:
            ip, _, pfx = spec.partition("/")
            nets.append(cidr_to_net(ip, int(pfx or 24)))
        return nets

    skip = {"lo"}
    wan = wan_iface()
    if wan:
        skip.add(wan)

    nets = []
    for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        c = line.split()
        if len(c) < 4:
            continue
        iface = c[1]
        if iface in skip:
            continue
        for i, tok in enumerate(c):
            if tok == "inet" and i + 1 < len(c):
                addr, _, pfx = c[i + 1].partition("/")
                try:
                    nets.append(cidr_to_net(addr, int(pfx or 32)))
                except ValueError:
                    pass
    return nets


# --------------------------------------------------------------- conntrack

def ensure_accounting():
    """Byte counters are off by default on many builds. Turn them on."""
    try:
        with open(ACCT_SYSCTL) as f:
            if f.read().strip() == "1":
                return True, "already on"
    except OSError:
        return False, "no %s - conntrack accounting unavailable" % ACCT_SYSCTL
    try:
        with open(ACCT_SYSCTL, "w") as f:
            f.write("1\n")
        return True, "enabled now (counters start from zero for new flows)"
    except OSError as e:
        return False, "could not enable: %s" % e


def read_conntrack():
    """Yield (key, orig_src, orig_dst, orig_bytes, reply_bytes) per flow."""
    lines = []
    try:
        with open(CONNTRACK_PROC, errors="replace") as f:
            lines = f.readlines()
    except OSError:
        out = run(["conntrack", "-L"], timeout=10)   # conntrack-tools fallback
        lines = out.splitlines()

    for line in lines:
        toks = line.split()
        src, dst, sport, dport, byts = [], [], [], [], []
        proto = "?"
        for i, tok in enumerate(toks):
            if "=" not in tok:
                if i in (2, 0) and tok.isalpha() and tok not in ("ipv4", "ipv6"):
                    proto = tok
                continue
            k, _, v = tok.partition("=")
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

        if len(src) < 2 or len(dst) < 2 or len(byts) < 2:
            continue          # ipv6, or accounting off -> no bytes= tokens
        if "." not in src[0]:
            continue

        key = (proto, src[0], sport[0] if sport else "",
               dst[0], dport[0] if dport else "")
        yield key, src[0], dst[0], byts[0], byts[1]


# --------------------------------------------------------------- accounting

class Meter:
    """Cumulative per-device byte totals, built from conntrack deltas."""

    def __init__(self, nets):
        self.nets = nets
        self.flows = {}       # key -> (orig_bytes, reply_bytes) last seen
        self.dev = {}         # ip  -> {"in":n, "out":n, "level":n, "last_alert":t}

    def local_side(self, src, dst):
        """Return (device_ip, direction_of_orig) or None if neither end is LAN."""
        s = any(in_net(src, n) for n in self.nets)
        d = any(in_net(dst, n) for n in self.nets)
        if s and not d:
            return src, "out"      # LAN device initiated outbound
        if d and not s:
            return dst, "in"       # someone outside initiated toward a LAN device
        if s and d:
            return src, "out"      # LAN-to-LAN, attribute to the initiator
        return None

    def entry(self, ip):
        return self.dev.setdefault(
            ip, {"in": 0, "out": 0, "level": 0, "last_alert": 0.0})

    def poll(self):
        seen = set()
        for key, src, dst, ob, rb in read_conntrack():
            seen.add(key)
            prev_o, prev_r = self.flows.get(key, (0, 0))
            # A counter that went backwards means a new flow reused the key.
            d_o = ob - prev_o if ob >= prev_o else ob
            d_r = rb - prev_r if rb >= prev_r else rb
            self.flows[key] = (ob, rb)

            if d_o <= 0 and d_r <= 0:
                continue
            side = self.local_side(src, dst)
            if not side:
                continue
            ip, orig_dir = side
            e = self.entry(ip)
            if orig_dir == "out":
                e["out"] += d_o      # original direction leaves the device
                e["in"] += d_r       # reply direction arrives at it
            else:
                e["in"] += d_o
                e["out"] += d_r

        # Flows gone from the table keep their bytes; drop the tracking state.
        for key in set(self.flows) - seen:
            del self.flows[key]

    def measured(self, ip, direction):
        return self.measured_entry(self.dev[ip], direction)

    @staticmethod
    def measured_entry(e, direction):
        if direction == "in":
            return e["in"]
        if direction == "out":
            return e["out"]
        return e["in"] + e["out"]


# --------------------------------------------------------------- formatting

def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def parse_size(text):
    """'1000K' -> bytes. Bare numbers are bytes. K/M/G are 1024-based."""
    t = text.strip().upper().rstrip("B")
    mult = 1
    if t.endswith("K"):
        mult, t = 1024, t[:-1]
    elif t.endswith("M"):
        mult, t = 1024 ** 2, t[:-1]
    elif t.endswith("G"):
        mult, t = 1024 ** 3, t[:-1]
    return int(float(t) * mult)


def hostname_map():
    """MAC-less lookup: IP -> DHCP hostname, for readable alerts."""
    names = {}
    try:
        with open("/tmp/dhcp.leases", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[3] != "*":
                    names[p[2]] = p[3]
    except OSError:
        pass
    return names


# --------------------------------------------------------------- alerting

MIN_THRESHOLD = 10 * 1024                 # 10 KB
MAX_THRESHOLD = 10 * 1024 ** 3            # 10 GB
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SIZED = re.compile(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)\b", re.I)
BARE = re.compile(r"\d+(?:\.\d+)?")
UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def extract_threshold(text):
    """Find a data size in free text. Returns (status, bytes, raw) or None.

    IPv4 addresses are stripped FIRST -- in 'Device 192.168.8.182 has used
    540.9 KB', the first number is an octet, not a size. A number carrying a
    unit wins over a bare one. The result is clamped: a stray '2' would
    otherwise set a 2-byte limit that every device trips on every poll.
    """
    cleaned = IPV4.sub(" ", text)

    m = SIZED.search(cleaned)
    if m:
        value = float(m.group(1)) * UNITS[m.group(2).upper()]
    else:
        m = BARE.search(cleaned)
        if not m:
            return None
        value = float(m.group(0))          # bare number means bytes

    value = int(value)
    if value < MIN_THRESHOLD:
        return ("clamped", MIN_THRESHOLD, value)
    if value > MAX_THRESHOLD:
        return ("clamped", MAX_THRESHOLD, value)
    return ("ok", value, value)


CLOSE_CMD = re.compile(r"\bclose\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)", re.I)
OPEN_CMD = re.compile(r"\bopen\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)", re.I)

# limit(192.168.8.116, 500MB)  or  limit(192.168.8.116, 2GB, daily)
# The size accepts the same suffixes parse_size() already understands, so the
# email command and the --threshold flag speak one language.
LIMIT_CMD = re.compile(
    r"\blimit\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*[,;\s]\s*([0-9.]+\s*[KMGT]?B?)"
    r"(?:\s*[,;\s]\s*(daily|weekly|monthly|none))?\s*\)", re.I)
UNLIMIT_CMD = re.compile(
    r"\bunlimit\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)", re.I)

# throttle(192.168.8.116, 2mbit)            same cap both directions
# throttle(192.168.8.116, 5mbit, 1mbit)     download, then upload
THROTTLE_CMD = re.compile(
    r"\bthrottle\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*[,;\s]\s*"
    r"([0-9.]+\s*[kmg]?(?:bit|bps|b)?)"
    r"(?:\s*[,;\s]\s*([0-9.]+\s*[kmg]?(?:bit|bps|b)?))?\s*\)", re.I)
UNTHROTTLE_CMD = re.compile(
    r"\bunthrottle\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)", re.I)

# calibrate(192.168.8.116) or calibrate(192.168.8.116, 2) -- teach the
# distance model this device's signal at a known range.
CALIBRATE_CMD = re.compile(
    r"\bcalibrate\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s*[,;\s]\s*([0-9.]+))?\s*\)", re.I)

# devices() -- no argument; emails the registry back.
DEVICES_CMD = re.compile(r"\bdevices\s*\(\s*\)", re.I)

# browsing(192.168.8.116) for one device, or browsing() for every device.
BROWSING_CMD = re.compile(
    r"\bbrowsing\s*\(\s*((?:\d{1,3}(?:\.\d{1,3}){3})?)\s*\)", re.I)

# locate(192.168.8.116) for one device, or locate() for every located device.
LOCATE_CMD = re.compile(
    r"\blocate\s*\(\s*((?:\d{1,3}(?:\.\d{1,3}){3})?)\s*\)", re.I)

# zones() -- no argument; emails the forbidden-area config and who is inside.
ZONES_CMD = re.compile(r"\bzones\s*\(\s*\)", re.I)

# forbid(5) sets a 5 m radius; forbid(-55) sets a -55 dBm signal threshold
# (negative == dBm, positive == metres). unforbid() turns the area off and
# restores everyone it had cut.
FORBID_CMD = re.compile(r"\bforbid\s*\(\s*(-?\d+(?:\.\d+)?)\s*(m|dbm)?\s*\)", re.I)
UNFORBID_CMD = re.compile(r"\bunforbid\s*\(\s*\)", re.I)


def _parse_targets(pattern, text):
    out = []
    for ip in pattern.findall(text or ""):
        try:
            ip_to_int(ip)
            if ip not in out:
                out.append(ip)
        except ValueError:
            pass
    return out


def parse_limit_targets(text):
    """[(ip, bytes, period), ...] from limit(...). A malformed size is dropped
    rather than guessed at -- a quota built from a misread number would cut a
    device off at the wrong point, and the sender gets no feedback either way."""
    out = []
    for ip, size, period in LIMIT_CMD.findall(text or ""):
        try:
            ip_to_int(ip)
            nbytes = parse_size(size.strip())
        except (ValueError, TypeError):
            continue
        if nbytes <= 0:
            continue
        out.append((ip, nbytes, (period or "none").lower()))
    return out


def parse_throttle_targets(text):
    """[(ip, down_kbit, up_kbit), ...]. One rate means both directions get it.
    A rate that will not parse is dropped rather than guessed at."""
    out = []
    for ip, down, up in THROTTLE_CMD.findall(text or ""):
        try:
            ip_to_int(ip)
            d = parse_rate(down)
            u = parse_rate(up) if up.strip() else d
        except (ValueError, TypeError):
            continue
        out.append((ip, d, u))
    return out


def parse_open_targets(text):
    """All IPs named by open(x.x.x.x) -- the undo of close()."""
    return _parse_targets(OPEN_CMD, text)


def wifi_iface_sections():
    """uci indexes of wifi-iface sections, for the maclist fallback."""
    idx = set()
    for line in run(["uci", "show", "wireless"]).splitlines():
        m = re.match(r"wireless\.@wifi-iface\[(\d+)\]", line)
        if m:
            idx.add(int(m.group(1)))
    return sorted(idx)


def have(cmd):
    return bool(run(["which", cmd]).strip())


def wifi_ban_plan(mac, remove=False):
    """Commands to ban (or unban) a MAC from associating.

    hostapd_cli is not present on every GL.iNet build. When it is missing the
    same result is reached through uci, which is always available -- at the
    cost of a `wifi reload` that briefly drops every wireless client.
    """
    plan = []
    if have("hostapd_cli"):
        verb = "DEL_MAC" if remove else "ADD_MAC"
        for iface in wireless_ifaces():
            plan.append(["hostapd_cli", "-i", iface, "deny_acl", verb, mac])
            if not remove:
                plan.append(["hostapd_cli", "-i", iface, "deauthenticate", mac])
        return plan, "hostapd_cli"

    for n in wifi_iface_sections():
        key = "wireless.@wifi-iface[%d]" % n
        if remove:
            plan.append(["uci", "del_list", "%s.maclist=%s" % (key, mac)])
        else:
            plan.append(["uci", "set", "%s.macfilter=deny" % key])
            plan.append(["uci", "add_list", "%s.maclist=%s" % (key, mac)])
    if plan:
        plan.append(["uci", "commit", "wireless"])
        plan.append(["wifi", "reload"])
    if not remove and have("iw"):
        for iface in wireless_ifaces():
            plan.append(["iw", "dev", iface, "station", "del", mac])
    return plan, "uci maclist (hostapd_cli absent)"


def local_addresses():
    """Every IPv4 address bound to this router -- never blockable."""
    addrs = set()
    for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        c = line.split()
        for i, tok in enumerate(c):
            if tok == "inet" and i + 1 < len(c):
                addrs.add(c[i + 1].split("/")[0])
    return addrs


def ssh_peer():
    """The IP we are being administered from. Blocking it locks us out."""
    conn = os.environ.get("SSH_CONNECTION", "")
    return conn.split()[0] if conn else None


def parse_close_targets(text):
    """All IPs named by close(x.x.x.x) in a message body."""
    out = []
    for ip in CLOSE_CMD.findall(text or ""):
        try:
            ip_to_int(ip)                     # rejects 999.1.1.1 etc.
            if ip not in out:
                out.append(ip)
        except ValueError:
            pass
    return out


def mac_for_ip(ip):
    """Resolve a LAN IP to its MAC via ARP, falling back to the lease table."""
    try:
        with open("/proc/net/arp", errors="replace") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[0] == ip and c[3] != "00:00:00:00:00:00":
                    return c[3].lower()
    except OSError:
        pass
    try:
        with open("/tmp/dhcp.leases", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[2] == ip:
                    return p[1].lower()
    except OSError:
        pass
    return None


def wireless_ifaces():
    return [l.split()[0] for l in run(["iwinfo"]).splitlines()
            if l and not l[0].isspace()]


def _run_plan(plan):
    failures = []
    for step in plan:
        try:
            p = subprocess.run(step, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=20)
            if p.returncode != 0:
                failures.append("%s -> %s" % (
                    " ".join(step[:3]),
                    p.stderr.decode("utf-8", "replace").strip() or "failed"))
        except (OSError, subprocess.SubprocessError) as e:
            failures.append("%s -> %s" % (" ".join(step[:3]), e))
    return failures


def disconnect_device(ip, nets, dry_run=False, blocked=None):
    """Remove a device from the network entirely.

    Layers, because no single one is sufficient:
      INPUT  drop by MAC  -- no DHCP, no DNS, no access to the router itself
      FORWARD drop by MAC -- no internet, no cross-subnet
      Wi-Fi ban + deauth  -- cannot re-associate
    Keyed on MAC, not IP: a device that reconnects gets a new lease and would
    walk straight past an IP rule (SESSION_LOG s4).
    """
    if blocked is not None and ip in blocked:
        return "[close SKIPPED] %s is already disconnected" % ip
    if not any(in_net(ip, n) for n in nets):
        return "[close REFUSED] %s is not on a LAN subnet" % ip
    if ip in local_addresses():
        return "[close REFUSED] %s is this router" % ip
    peer = ssh_peer()
    if peer and ip == peer:
        return ("[close REFUSED] %s is the address administering this router "
                "-- disconnecting it would lock you out" % ip)

    mac = mac_for_ip(ip)
    if not mac:
        return ("[close REFUSED] no MAC known for %s -- not in the ARP table or "
                "lease file, so the device cannot be identified" % ip)
    if peer and mac == mac_for_ip(peer):
        return "[close REFUSED] %s is the same device administering this router" % ip
    if mac in blocked_macs_in_firewall():
        # The in-memory record resets on restart; the rules do not. Without
        # this, every re-run stacks another DROP that open() must undo.
        if blocked is not None:
            blocked[ip] = mac
        return ("[close SKIPPED] %s (%s) is already blocked in the firewall"
                % (ip, mac))

    plan = [["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"]]
    wifi, method = wifi_ban_plan(mac)
    plan += wifi

    if dry_run:
        return ("[close DRY RUN] %s is %s -- wifi method: %s -- would run:\n      %s"
                % (ip, mac, method, "\n      ".join(" ".join(s) for s in plan)))

    failures = _run_plan(plan)
    if blocked is not None:
        blocked[ip] = mac

    note = ""
    if failures:
        note = ("\n      partial: %s\n      (the MAC firewall drop still applies; "
                "the device may show as associated but passes no traffic)"
                % "; ".join(failures))
    return ("*** %s (%s) DISCONNECTED *** no DHCP, no DNS, no router access, "
            "no internet; wifi ban via %s%s\n      undo: send open(%s)"
            % (ip, mac, method, note, ip))


def blocked_macs_in_firewall():
    """MACs currently dropped by a mac-source rule, read from iptables itself.

    The in-memory blocked record does not survive a restart, but the rules do.
    This is how open() recovers a MAC that nothing else can supply.
    """
    macs = set()
    for chain in ("INPUT", "FORWARD"):
        for line in run(["iptables", "-S", chain]).splitlines():
            m = re.search(r"--mac-source\s+([0-9A-Fa-f:]{17})", line)
            if m:
                macs.add(m.group(1).lower())
    return sorted(macs)


def _delete_all(chain, mac):
    """iptables -D removes ONE matching rule. Restarts stack duplicates, so
    deleting once leaves the device blocked. Repeat until none are left."""
    removed = 0
    while removed < 50:
        try:
            p = subprocess.run(
                ["iptables", "-D", chain, "-m", "mac", "--mac-source", mac,
                 "-j", "DROP"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        except (OSError, subprocess.SubprocessError):
            break
        if p.returncode != 0:
            break
        removed += 1
    return removed


def reconnect_device(ip, nets, dry_run=False, blocked=None):
    """Undo disconnect_device -- the open(x.x.x.x) command.

    MAC resolution order: the blocked record, then ARP, then the firewall
    rules themselves. A disconnected device has usually aged out of ARP, and
    the record is lost on restart, so the rules are the durable source.
    """
    mac = (blocked or {}).get(ip) or mac_for_ip(ip)
    source = "blocked record / ARP"
    if not mac:
        candidates = blocked_macs_in_firewall()
        if len(candidates) == 1:
            mac, source = candidates[0], "the only MAC blocked in the firewall"
        elif candidates:
            return ("[open FAILED] no MAC known for %s, and %d MACs are blocked: "
                    "%s -- unblock the right one manually" %
                    (ip, len(candidates), ", ".join(candidates)))
        else:
            return ("[open FAILED] no MAC known for %s and nothing is blocked in "
                    "the firewall -- there is nothing to undo" % ip)

    if dry_run:
        wifi, method = wifi_ban_plan(mac, remove=True)
        return ("[open DRY RUN] %s is %s (via %s) -- would delete every INPUT and "
                "FORWARD mac-source rule, then:\n      %s"
                % (ip, mac, source, "\n      ".join(" ".join(s) for s in wifi)))

    n_in = _delete_all("INPUT", mac)
    n_fwd = _delete_all("FORWARD", mac)

    wifi, method = wifi_ban_plan(mac, remove=True)
    failures = _run_plan(wifi)

    if blocked is not None:
        blocked.pop(ip, None)

    note = ""
    if failures:
        note = "\n      wifi unban notes: %s" % "; ".join(failures)
    if n_in == 0 and n_fwd == 0:
        note += ("\n      no firewall rules were found for this MAC -- it may "
                 "already have been unblocked")
    return ("*** %s (%s) REOPENED *** removed %d INPUT + %d FORWARD rule(s), "
            "wifi ban lifted via %s%s"
            % (ip, mac, n_in, n_fwd, method, note))


def block_ip(ip, nets, dry_run=False, blocked=None):
    """Firewall-block a LAN device at the gateway. Returns a status string.

    Refusals come first and are always announced -- the tool must not be able
    to do anything the operator did not pre-authorise (SESSION_LOG s2).
    """
    if blocked is not None and ip in blocked:
        return "[close SKIPPED] %s is already blocked" % ip
    if not any(in_net(ip, n) for n in nets):
        return ("[close REFUSED] %s is not on a LAN subnet -- this blocks local "
                "devices, not upstream or internet hosts" % ip)
    if ip in local_addresses():
        return "[close REFUSED] %s is this router -- blocking it kills the gateway" % ip
    peer = ssh_peer()
    if peer and ip == peer:
        return ("[close REFUSED] %s is the address administering this router "
                "-- blocking it would lock you out" % ip)

    rules = [["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
             ["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"]]
    undo = ("iptables -D FORWARD -s %s -j DROP ; iptables -D FORWARD -d %s -j DROP"
            % (ip, ip))

    if dry_run:
        return ("[close DRY RUN] would run:\n      %s\n      %s\n      undo with: %s"
                % (" ".join(rules[0]), " ".join(rules[1]), undo))

    for rule in rules:
        try:
            p = subprocess.run(rule, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=10)
            if p.returncode != 0:
                return "[close FAILED] %s: %s" % (
                    ip, p.stderr.decode("utf-8", "replace").strip())
        except (OSError, subprocess.SubprocessError) as e:
            return "[close FAILED] %s: %s" % (ip, e)

    if blocked is not None:
        blocked[ip] = mac_for_ip(ip)
    return ("*** %s BLOCKED *** forwarding dropped both directions\n"
            "      undo with: %s" % (ip, undo))


# --------------------------------------------------------------- the gate
#
# ADDED. Nothing above this line changed. close()/open() behave exactly as
# before; the gate sits underneath them and flips the DEFAULT.
#
# close()/open() on their own are deny-by-exception: every device is open
# until you shut it. The gate inverts that. One chain in front of FORWARD:
#
#     SW_GATE:  RETURN <always-open MAC>   <- --always-open, permanent
#               RETURN <granted MAC>       <- open(x.x.x.x) put it there
#               DROP                       <- every other device
#
# RETURN and not ACCEPT: an allowed device falls back into OpenWrt's own zone
# rules rather than skipping the firewall entirely. "Allowed", not "exempt".
#
# WHY THE GATE ONLY TOUCHES FORWARD
#     A gate on INPUT would also drop DHCP and DNS. An unknown device would
#     never get a lease, never appear in /tmp/dhcp.leases or ARP -- so it
#     would have no IP for you to name in open(x.x.x.x), and no MAC for the
#     rule to match. The gate would make its own undo impossible. Gated
#     devices therefore still get an address and still appear in the table.
#     What they do not get is anywhere to send packets.
#     close(x.x.x.x) is untouched and still cuts a device off completely.
#
# MAC AND NOT IP, for the reason disconnect_device() already gives: a device
# that reconnects gets a new lease and walks straight past an IP rule. Worse
# here than for a block -- a recycled IP would hand a stranger your allowance.

GATE_CHAIN = "SW_GATE"
GATE_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
GATE = {"on": False, "always": {}, "always_ips": set(), "ifaces": [],
        "dry_run": False}


def gate_ifaces():
    """LAN interfaces only. The WAN iface is excluded, so the gate can never
    filter upstream traffic even if the subnet detection is wrong."""
    skip = {"lo"}
    wan = wan_iface()
    if wan:
        skip.add(wan)
    out = []
    for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        c = line.split()
        if len(c) < 2 or c[1] in skip or c[1] in out:
            continue
        if "inet" in c:
            out.append(c[1])
    return out


def gate_ipt(*args):
    if GATE["dry_run"]:
        print("      [gate DRY RUN] iptables %s" % " ".join(args))
        return 0, ""
    try:
        p = subprocess.run(["iptables"] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=20)
        return p.returncode, p.stderr.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def gate_resolve(entries):
    """['192.168.8.50', 'aa:bb:...'] -> ({mac: label}, [(entry, why)]).

    An IP is resolved to a MAC once, here. A device that is offline right now
    has no ARP entry and no lease, so it cannot be resolved -- and an
    always-open device that cannot be resolved is not open at all. That is
    reported loudly rather than swallowed.
    """
    macs, unresolved = {}, []
    for raw in entries:
        item = (raw or "").split("#")[0].strip()
        if not item:
            continue
        if GATE_MAC.match(item):
            macs.setdefault(item.lower(), item.lower())
            continue
        try:
            ip_to_int(item)
        except ValueError:
            unresolved.append((item, "not an IP or a MAC"))
            continue
        GATE["always_ips"].add(item)
        mac = mac_for_ip(item)
        if not mac:
            unresolved.append((item, "no MAC in the ARP table or lease file "
                                     "-- device offline?"))
            continue
        macs.setdefault(mac, item)
    return macs, unresolved


def gate_is_always(ip):
    """True if this IP is on the permanent list -- by address or by MAC."""
    if ip in GATE["always_ips"]:
        return True
    mac = mac_for_ip(ip)
    return bool(mac and mac in GATE["always"])


def gate_grant(ip):
    """Let one device through the gate. This is what open(x.x.x.x) needs:
    reconnect_device() only removes DROP rules, which leaves the device still
    landing on the gate's catch-all."""
    mac = mac_for_ip(ip)
    if not mac:
        return ("[gate] no MAC known for %s -- cannot open it. The device has "
                "no lease and no ARP entry; wait for it to ask for an address."
                % ip)
    rc, _ = gate_ipt("-C", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                     "-j", "RETURN")
    if rc == 0:
        return "[gate] %s (%s) was already open" % (ip, mac)
    rc, err = gate_ipt("-I", GATE_CHAIN, "1", "-m", "mac", "--mac-source", mac,
                       "-j", "RETURN")
    if rc != 0:
        return "[gate] could not open %s: %s" % (ip, err or "failed")
    return "[gate] %s (%s) OPEN -- traffic now forwarded" % (ip, mac)


def gate_revoke(ip):
    """Put a device back behind the gate. iptables -D removes one rule at a
    time, so repeat -- a device opened twice would otherwise stay open."""
    mac = mac_for_ip(ip)
    if not mac:
        return "[gate] no MAC known for %s -- nothing to revoke" % ip
    n = 0
    while n < 50:
        rc, _ = gate_ipt("-D", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                         "-j", "RETURN")
        if rc != 0:
            break
        n += 1
    return "[gate] %s (%s) closed again (%d rule(s) removed)" % (ip, mac, n)


def gate_teardown():
    """The command that removes the gate. Printed, never run automatically --
    a security default that undoes itself on Ctrl-C is not a default."""
    parts = []
    for iface in GATE["ifaces"]:
        parts.append("while iptables -D FORWARD -i %s -j %s 2>/dev/null; do :; "
                     "done" % (iface, GATE_CHAIN))
    parts.append("iptables -F %s; iptables -X %s" % (GATE_CHAIN, GATE_CHAIN))
    return " ; ".join(parts)


def gate_install(entries, nets, dry_run=False):
    """Build the chain and hook it into FORWARD. Returns a report string."""
    GATE["dry_run"] = dry_run
    GATE["ifaces"] = gate_ifaces()
    if not GATE["ifaces"]:
        return "[gate] no LAN interface found -- gate NOT installed"
    if not run(["which", "iptables"]).strip():
        return ("[gate] iptables not found. On an nftables-only build these "
                "rules do not apply -- gate NOT installed")

    macs, unresolved = gate_resolve(entries)

    # The address administering this router goes on the list whether or not
    # you listed it. The gate is FORWARD-only so an SSH session survives
    # regardless, but losing your own internet while debugging is its own
    # kind of lockout.
    peer = ssh_peer()
    peer_note = ""
    if peer and any(in_net(peer, n) for n in nets):
        pmac = mac_for_ip(peer)
        if pmac and pmac not in macs:
            macs[pmac] = "%s [ssh peer, auto-added]" % peer
            GATE["always_ips"].add(peer)
            peer_note = ("\n  ssh peer %s (%s) auto-added to the always-open "
                         "list" % (peer, pmac))
        elif not pmac:
            peer_note = ("\n  WARNING: ssh peer %s has no known MAC and could "
                         "not be auto-added" % peer)

    if not macs:
        return ("[gate] the always-open list resolved to nothing. Refusing to "
                "install a rule that drops every device on the LAN.")

    # Chain first, hook last: interrupted halfway, a chain nothing jumps to
    # drops nothing.
    gate_ipt("-N", GATE_CHAIN)
    gate_ipt("-F", GATE_CHAIN)
    for mac in macs:
        gate_ipt("-A", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                 "-j", "RETURN")
    gate_ipt("-A", GATE_CHAIN, "-j", "DROP")

    hooked = []
    for iface in GATE["ifaces"]:
        rc, _ = gate_ipt("-C", "FORWARD", "-i", iface, "-j", GATE_CHAIN)
        if rc != 0:
            gate_ipt("-I", "FORWARD", "1", "-i", iface, "-j", GATE_CHAIN)
        hooked.append(iface)

    GATE["always"] = macs
    GATE["on"] = True

    lines = ["[gate] DEFAULT-DENY ACTIVE on %s%s -- %d device(s) always open, "
             "every other device is dropped until open(x.x.x.x)"
             % ("+".join(hooked), "  [DRY RUN]" if dry_run else "", len(macs))]
    for mac, label in macs.items():
        lines.append("    always open: %-17s  %s" % (mac, label))
    if unresolved:
        lines.append("    NOT OPEN -- could not resolve (%d):" % len(unresolved))
        for item, why in unresolved:
            lines.append("      %-17s  %s" % (item, why))
        lines.append("      These are blocked like anything else. Bring them "
                     "online and restart, or list them by MAC.")
    if peer_note:
        lines.append("   " + peer_note.strip())
    lines.append("    a MAC is cloneable -- this keeps unknown devices out, "
                 "it does not stop an attacker")
    lines.append("    rules do not survive a reboot or `/etc/init.d/firewall "
                 "reload`; remove them with:")
    lines.append("      %s" % gate_teardown())
    return "\n  ".join(lines)


def gated_close(ip, nets, dry_run=False, blocked=None, mode="full"):
    """close(x.x.x.x), plus the gate. Behaviour is unchanged when the gate is
    off. When it is on, an always-open device is refused -- that list is the
    one thing a forged email must not be able to touch."""
    if GATE["on"] and gate_is_always(ip):
        return ("[close REFUSED] %s is on the always-open list -- remove it "
                "from --always-open and restart to change that" % ip)
    act = disconnect_device if mode == "full" else block_ip
    msg = act(ip, nets, dry_run=dry_run, blocked=blocked)
    if GATE["on"] and not dry_run and "REFUSED" not in msg:
        msg += "\n      " + gate_revoke(ip)
    return msg


def gated_open(ip, nets, dry_run=False, blocked=None):
    """open(x.x.x.x), plus the gate.

    reconnect_device() reports failure when it finds no DROP rule to remove.
    Under the gate that is the normal case -- the device was never explicitly
    closed, it was simply never opened -- so the grant happens regardless.
    """
    msg = reconnect_device(ip, nets, dry_run=dry_run, blocked=blocked)
    if GATE["on"] and not dry_run:
        if not any(in_net(ip, n) for n in nets):
            return "[open REFUSED] %s is not on a LAN subnet" % ip
        msg += "\n      " + gate_grant(ip)
    return msg


# ----------------------------------------------------- group allow/deny lists
#
# ADDED. The authorised group as two text files on the gateway (SRS
# Group.Lists), the same files group_lists.py manages:
#
#     allow.txt  -- device MACs permitted internet access (the gate lets them
#                   through); everything NOT on it is held by the approval gate
#     deny.txt   -- device MACs blocked entirely by MAC (INPUT + FORWARD drop +
#                   wifi ban, i.e. what close() does)
#
# Three states follow (Model A), with a block beating an allow (BR-2):
#
#     on allow, not deny  -> internet          (gate RETURN)
#     on deny             -> nothing           (blocked by MAC)
#     on neither          -> held at the gate  (address + DNS, no internet)
#
# THE FILES ARE THE INTERFACE, NOT AN IMPORT
#     StreamWatch (here) and group_lists.py share these files, not code: the
#     admin edits them with group_lists.py or by hand, StreamWatch reads and
#     writes the same format and enforces. One store, several readers -- the
#     same arrangement the SRS uses for the calibration model. So this parses
#     the file itself rather than importing, which also keeps the gateway's
#     standard-library-only constraint (CON-1) with no cross-file dependency.
#
# MAC, NOT IP (Data.Identity)
#     Lines are MACs. close(ip)/open(ip) name a device by the IP you read off
#     the map, resolve it to its MAC once, and store the MAC. A line that
#     cannot be resolved to a MAC is refused, never guessed.
#
# NEVER LOCK YOURSELF OUT
#     The deny path reuses disconnect_device(), which already refuses the
#     router and the SSH peer. Startup/hand-edit deny enforcement skips the
#     SSH peer's MAC for the same reason. The gate is FORWARD-only, so an SSH
#     session survives regardless; a deny is INPUT+FORWARD, so it must not land
#     on the peer.

GROUP = {"on": False, "allow": "/etc/streamwatch/allow.txt",
         "deny": "/etc/streamwatch/deny.txt",
         "granted": set(), "blocked": set(), "mtimes": {}}


def group_file_load(path):
    """{mac: comment} from a list file. Missing file is empty, not an error."""
    out = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                body, _, comment = line.partition("#")
                tok = body.strip()
                if GATE_MAC.match(tok):
                    out[tok.lower()] = comment.strip()
    except OSError:
        pass
    return out


def group_mac_set(path):
    return set(group_file_load(path))


def group_file_save(path, entries):
    """Atomic write, mode 600 -- same format group_lists.py writes."""
    d = os.path.dirname(path) or "."
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for mac, comment in entries.items():
            f.write("%-17s  # %s\n" % (mac, comment) if comment else "%s\n" % mac)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def group_file_add(path, mac, label=""):
    entries = group_file_load(path)
    if mac in entries:
        return False
    entries[mac] = label
    group_file_save(path, entries)
    return True


def group_file_remove(path, mac):
    entries = group_file_load(path)
    if mac not in entries:
        return False
    del entries[mac]
    group_file_save(path, entries)
    return True


def _group_label(ip):
    return "%s %s" % (ip or "-",
                      datetime.now().strftime("set %Y-%m-%dT%H:%M:%S"))


def _group_peer_mac():
    peer = ssh_peer()
    return mac_for_ip(peer) if peer else None


def group_touch():
    """Record the list files' mtimes, so a change WE made does not read back as
    a hand-edit on the next reconcile."""
    for key in ("allow", "deny"):
        try:
            GROUP["mtimes"][key] = os.path.getmtime(GROUP[key])
        except OSError:
            GROUP["mtimes"][key] = 0.0


def group_files_changed():
    for key in ("allow", "deny"):
        try:
            if os.path.getmtime(GROUP[key]) != GROUP["mtimes"].get(key):
                return True
        except OSError:
            if GROUP["mtimes"].get(key):
                return True
    return False


def gate_grant_mac(mac, label=""):
    """Grant one MAC through the gate directly (no IP needed), and record it on
    the always list so gate_is_always() agrees."""
    if not GATE["on"]:
        return
    rc, _ = gate_ipt("-C", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                     "-j", "RETURN")
    if rc != 0:
        gate_ipt("-I", GATE_CHAIN, "1", "-m", "mac", "--mac-source", mac,
                 "-j", "RETURN")
    GATE["always"][mac] = label or mac


def gate_revoke_mac(mac):
    if not GATE["on"]:
        return
    n = 0
    while n < 50:
        rc, _ = gate_ipt("-D", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                         "-j", "RETURN")
        if rc != 0:
            break
        n += 1
    GATE["always"].pop(mac, None)


def group_block_mac(mac):
    """Block one MAC entirely -- INPUT + FORWARD drop + wifi ban -- for a deny
    entry that may have no current IP (startup, hand-edit). The SSH peer is
    never blocked. Honours --gate-dry-run."""
    if mac == _group_peer_mac():
        return "[deny SKIPPED] %s is the SSH peer -- not blocking it" % mac
    if GATE["dry_run"]:
        print("      [group DRY RUN] block %s: iptables -I INPUT/-I FORWARD "
              "-m mac --mac-source %s -j DROP (+ wifi ban)" % (mac, mac))
        return "[deny DRY RUN] %s" % mac
    plan = [["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac,
             "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac,
             "-j", "DROP"]]
    wifi, _ = wifi_ban_plan(mac)
    _run_plan(plan + wifi)
    return "[deny] %s blocked" % mac


def group_unblock_mac(mac):
    if GATE["dry_run"]:
        print("      [group DRY RUN] unblock %s" % mac)
        return
    _delete_all("INPUT", mac)
    _delete_all("FORWARD", mac)
    wifi, _ = wifi_ban_plan(mac, remove=True)
    _run_plan(wifi)


def group_deny(ip, nets, dry_run=False, blocked=None):
    """close(ip) under group lists: fully block the device AND move it from the
    allow list to the deny list, so the decision persists (Control.Persist)."""
    msg = disconnect_device(ip, nets, dry_run=dry_run, blocked=blocked)
    if dry_run or "REFUSED" in msg or "SKIPPED" in msg:
        return msg
    mac = (blocked or {}).get(ip) or mac_for_ip(ip)
    if not mac:
        return msg + "\n      [deny] no MAC known for %s -- lists not updated" % ip
    gate_revoke_mac(mac)
    GROUP["granted"].discard(mac)
    group_file_remove(GROUP["allow"], mac)
    added = group_file_add(GROUP["deny"], mac, _group_label(ip))
    GROUP["blocked"].add(mac)
    group_touch()
    return msg + ("\n      deny-listed %s (%s)%s"
                  % (ip, mac, "" if added else " (already listed)"))


def group_allow(ip, nets, dry_run=False, blocked=None):
    """open(ip) under group lists: unblock the device, move it from the deny
    list to the allow list, and let it through the gate."""
    if not dry_run and not any(in_net(ip, n) for n in nets):
        return "[open REFUSED] %s is not on a LAN subnet" % ip
    msg = reconnect_device(ip, nets, dry_run=dry_run, blocked=blocked)
    if dry_run:
        return msg
    mac = mac_for_ip(ip) or (blocked or {}).get(ip)
    if not mac:
        return msg + ("\n      [allow] no MAC known for %s -- lists not updated; "
                      "wait for the device to ask for an address" % ip)
    group_file_remove(GROUP["deny"], mac)
    GROUP["blocked"].discard(mac)
    group_file_add(GROUP["allow"], mac, _group_label(ip))
    gate_grant_mac(mac, ip)
    GROUP["granted"].add(mac)
    group_touch()
    return msg + "\n      allow-listed %s (%s) -- internet now permitted" % (ip, mac)


def group_reconcile(nets):
    """Bring the live gate and firewall in line with the files -- the path a
    hand edit of allow.txt / deny.txt takes effect through (Group.ListReload).
    A block beats an allow (BR-2); the SSH peer is never denied."""
    allow = group_mac_set(GROUP["allow"])
    deny = group_mac_set(GROUP["deny"])
    peer = _group_peer_mac()
    allow_eff = allow - deny
    deny_eff = {m for m in deny if m != peer}

    changes = []
    for m in allow_eff - GROUP["granted"]:
        gate_grant_mac(m)
        GROUP["granted"].add(m)
        changes.append("grant %s" % m)
    for m in set(GROUP["granted"]) - allow_eff:
        gate_revoke_mac(m)
        GROUP["granted"].discard(m)
        changes.append("ungrant %s" % m)
    for m in deny_eff - GROUP["blocked"]:
        group_block_mac(m)
        GROUP["blocked"].add(m)
        changes.append("block %s" % m)
    for m in set(GROUP["blocked"]) - deny_eff:
        group_unblock_mac(m)
        GROUP["blocked"].discard(m)
        changes.append("unblock %s" % m)
    group_touch()
    if not changes:
        return "[group] files changed, no net effect"
    return "[group] reload: %s" % ", ".join(changes)


def group_install(nets, cli_always):
    """Set up the gate from allow.txt and enforce deny.txt at startup. Returns
    report lines. The gate's own install builds the chain; this seeds it with
    the allow list and blocks the deny list."""
    allow = group_mac_set(GROUP["allow"])
    deny = group_mac_set(GROUP["deny"])
    allow_eff = allow - deny
    lines = ["[group] allow=%s deny=%s (%d allowed, %d denied)"
             % (GROUP["allow"], GROUP["deny"], len(allow_eff), len(deny))]
    if not allow_eff and not cli_always and not ssh_peer():
        lines.append("  WARNING: the allow list is empty and nothing else is "
                     "always-open, so the gate would drop every device "
                     "(including yours). Add your admin device to %s first; "
                     "the gate is NOT being installed." % GROUP["allow"])
        return lines, []
    GROUP["granted"] = set(allow_eff)
    peer = _group_peer_mac()
    for m in deny:
        if m == peer:
            lines.append("  deny %s skipped -- it is the SSH peer" % m)
            continue
        group_block_mac(m)
        GROUP["blocked"].add(m)
    if deny:
        lines.append("  %d device(s) on the deny list blocked by MAC"
                     % len(GROUP["blocked"]))
    group_touch()
    return lines, list(allow_eff)


def gate_reensure():
    """Re-apply the gate if something flushed it. OpenWrt rebuilds the whole
    firewall on `/etc/init.d/firewall reload` (and on many LuCI changes), which
    drops SW_GATE while StreamWatch keeps running -- default-deny would silently
    become default-ALLOW. Each poll checks the chain is still there and hooked,
    and rebuilds it from GATE["always"] (and re-applies the deny blocks) if not.

    Returns True if it had to re-apply. Never runs under --gate-dry-run (nothing
    was ever applied to restore)."""
    if not GATE["on"] or GATE["dry_run"] or not GATE["ifaces"]:
        return False
    chain = run(["iptables", "-S", GATE_CHAIN])
    chain_ok = bool(chain.strip()) and "-j DROP" in chain
    hooked_ok = True
    for iface in GATE["ifaces"]:
        rc, _ = gate_ipt("-C", "FORWARD", "-i", iface, "-j", GATE_CHAIN)
        if rc != 0:
            hooked_ok = False
            break
    if chain_ok and hooked_ok:
        return False

    gate_ipt("-N", GATE_CHAIN)
    gate_ipt("-F", GATE_CHAIN)
    for mac in GATE["always"]:
        gate_ipt("-A", GATE_CHAIN, "-m", "mac", "--mac-source", mac,
                 "-j", "RETURN")
    gate_ipt("-A", GATE_CHAIN, "-j", "DROP")
    for iface in GATE["ifaces"]:
        rc, _ = gate_ipt("-C", "FORWARD", "-i", iface, "-j", GATE_CHAIN)
        if rc != 0:
            gate_ipt("-I", "FORWARD", "1", "-i", iface, "-j", GATE_CHAIN)
    if GROUP["on"]:
        for mac in list(GROUP["blocked"]):
            group_block_mac(mac)
    return True


# ------------------------------------------------------ malfunction detect
#
# ADDED. Whiteboard item 9 / SRS Detect.NoInternet and Detect.NotConnected.
#
# NO INTERNET
#     The speed probe only hinted at an outage ("probe failed", and only with
#     --speed-report on). This is a dedicated check: a TCP handshake to two
#     independent upstream targets every --detect-every seconds -- a few
#     hundred bytes, no download. The internet counts as DOWN only after
#     --detect-fails probes in a row reach NEITHER target, so one lost packet
#     or one provider's hiccup is not an outage; the outage is then dated from
#     the FIRST failed probe, not the moment it was confirmed.
#
#     An alert email cannot leave while the internet is down, so the DOWN
#     event is logged and printed at once and the email is held: it goes out
#     the moment the link is back, carrying both times and the duration
#     (ROB-2, queued alerts delivered once the connection returns). If that
#     first send fails it is retried (DETECT_MAIL_RETRY), not dropped.
#
# DEVICE NOT CONNECTED
#     Devices that should be present -- the allow list under --group-lists,
#     plus any --watch-device -- are checked each round. Seen = associated to
#     a radio, or a REACHABLE/DELAY/PROBE neighbour entry (a STALE ARP entry
#     lingers for minutes after a device leaves, so it does not count). Absent
#     for --missing-after seconds -> one alert; seen again -> one alert. One
#     message per transition is Detect.Suppress by construction.
#
# HISTORY
#     Every event is a JSON line in HEALTH_LOG, which the Recorder on the
#     companion host pulls into the AI CSV as `malfunction` rows with their
#     own date and time -- the outage history.

HEALTH_LOG = "/root/.streamwatch_health.log"
HEALTH_LOG_KEEP = 2000
_HEALTH_LOCK = threading.Lock()
DETECT_ANCHORS = (("1.1.1.1", 443), ("8.8.8.8", 53))


def health_log(kind, t=None, **kw):
    rec = {"t": round(t if t is not None else time.time(), 3), "kind": kind}
    rec.update({k: v for k, v in kw.items() if v not in (None, "")})
    try:
        import json
        with _HEALTH_LOCK:
            with open(HEALTH_LOG, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            if os.path.getsize(HEALTH_LOG) > HEALTH_LOG_KEEP * 400:
                with open(HEALTH_LOG) as f:
                    keep = f.readlines()[-HEALTH_LOG_KEEP:]
                with open(HEALTH_LOG + ".tmp", "w") as f:
                    f.writelines(keep)
                os.replace(HEALTH_LOG + ".tmp", HEALTH_LOG)
    except OSError:
        pass


def human_dur(sec):
    sec = int(round(sec))
    h, rem = divmod(sec, 3600)
    m, s_ = divmod(rem, 60)
    if h:
        return "%d h %d min" % (h, m)
    if m:
        return "%d min %d s" % (m, s_)
    return "%d s" % s_


def upstream_reachable(anchors=DETECT_ANCHORS, timeout=3):
    """True if ANY anchor completes a TCP handshake."""
    import socket
    for host, port in anchors:
        sk = socket.socket()
        sk.settimeout(timeout)
        try:
            sk.connect((host, port))
            return True
        except OSError:
            pass
        finally:
            try:
                sk.close()
            except OSError:
                pass
    return False


class OutageMonitor:
    """Decision logic only -- fed (time, reachable?) and returns events."""

    def __init__(self, fail_n=3):
        self.fail_n = max(1, fail_n)
        self.fails = 0
        self.first_fail = None
        self.down_since = None

    def step(self, now, ok):
        if ok:
            self.fails, self.first_fail = 0, None
            if self.down_since is not None:
                ev = {"kind": "internet_up", "t": now, "down_since": self.down_since,
                      "duration_s": round(now - self.down_since)}
                self.down_since = None
                return ev
            return None
        self.fails += 1
        if self.fails == 1:
            self.first_fail = now
        if self.down_since is None and self.fails >= self.fail_n:
            self.down_since = self.first_fail
            return {"kind": "internet_down", "t": self.first_fail,
                    "confirmed_at": now}
        return None


class PresenceMonitor:
    """Decision logic only -- fed (time, watched macs, present macs)."""

    def __init__(self, missing_after=300):
        self.missing_after = missing_after
        self.last_seen = {}
        self.missing = {}

    def step(self, now, watched, present):
        events = []
        for mac in watched:
            self.last_seen.setdefault(mac, now)     # new on the list: grace period
            if mac in present:
                if mac in self.missing:
                    gone = self.missing.pop(mac)
                    events.append({"kind": "device_back", "t": now, "mac": mac,
                                   "missing_since": gone,
                                   "duration_s": round(now - gone)})
                self.last_seen[mac] = now
            elif mac not in self.missing and \
                    now - self.last_seen[mac] >= self.missing_after:
                self.missing[mac] = self.last_seen[mac]
                events.append({"kind": "device_missing", "t": now, "mac": mac,
                               "last_seen": self.last_seen[mac]})
        for mac in list(self.missing):              # removed from the watch list
            if mac not in watched:
                self.missing.pop(mac)
        return events


def present_macs():
    """MACs on the radio now, or a live (not STALE) neighbour entry."""
    out = set(wifi_rssi_map(ttl=0))
    for line in run(["ip", "neigh", "show"]).splitlines():
        p = line.split()
        if "lladdr" in p and p[-1] in ("REACHABLE", "DELAY", "PROBE"):
            out.add(p[p.index("lladdr") + 1].lower())
    return out


def _stamp(t):
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")


# The outage email goes out seconds after the link returns, while the uplink
# may still be settling (seen live: one SMTP timeout 10 s after restore), so
# a failed send is retried over ~18 min instead of the alert being lost.
DETECT_MAIL_RETRY = (30, 60, 120, 300, 600)


def _detect_mail(cfg, subject, body):
    if not cfg:
        return
    try:
        send_email_alert(cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                         cfg["to"], subject, body, retry_waits=DETECT_MAIL_RETRY)
    except Exception as e:
        print("  [detect: email FAILED: %s]" % e)


# The monitors run on the monotonic clock, not the wall clock: the router has
# no RTC, boots with a stale time and NTP then steps it -- seen live, by 18 h
# 33 min -- which on the wall clock fakes a "missing since yesterday" alert
# and stretches any outage it falls inside. Event times become wall-clock
# times only when reported, by which point NTP has normally fixed the clock,
# so the dates come out right too.
_TIME_KEYS = ("t", "down_since", "confirmed_at", "last_seen", "missing_since")


def _to_wall(ev):
    if not ev:
        return ev
    now_wall, now_mono = time.time(), time.monotonic()
    ev = dict(ev)
    for k in _TIME_KEYS:
        if k in ev:
            ev[k] = now_wall - (now_mono - ev[k])
    return ev


def outage_watcher(cfg, every, fail_n, anchors=DETECT_ANCHORS):
    mon = OutageMonitor(fail_n)
    while True:
        ev = _to_wall(mon.step(time.monotonic(), upstream_reachable(anchors)))
        if ev and ev["kind"] == "internet_down":
            health_log("internet_down", t=ev["t"], down_since=ev["t"],
                       detail="no answer from %s; confirmed %s" % (
                           ", ".join("%s:%d" % a for a in anchors),
                           _stamp(ev["confirmed_at"])))
            print("NO INTERNET  down since %s (confirmed after %d failed checks). "
                  "Still monitoring the LAN; the alert email goes out when the "
                  "link is back." % (_stamp(ev["t"]), fail_n))
        elif ev:
            dur = human_dur(ev["duration_s"])
            health_log("internet_up", t=ev["t"], duration_s=ev["duration_s"],
                       down_since=ev["down_since"], restored=ev["t"],
                       detail="down from %s to %s" % (_stamp(ev["down_since"]),
                                                      _stamp(ev["t"])))
            print("INTERNET BACK  outage %s -> %s (%s)"
                  % (_stamp(ev["down_since"]), _stamp(ev["t"]), dur))
            _detect_mail(cfg, "[streamwatch] internet was DOWN for %s" % dur,
                         "streamwatch - internet outage\n\n"
                         "Down from : %s\nRestored  : %s\nDuration  : %s\n\n"
                         "Upstream checks to %s all failed for that period. Local\n"
                         "devices kept being monitored and enforced throughout.\n"
                         % (_stamp(ev["down_since"]), _stamp(ev["t"]), dur,
                            ", ".join("%s:%d" % a for a in anchors)))
        time.sleep(every)


def watched_macs():
    macs = set(DETECT_WATCH)
    if GROUP["on"]:
        macs |= group_mac_set(GROUP["allow"]) - group_mac_set(GROUP["deny"])
    return macs


DETECT_WATCH = set()


def presence_watcher(cfg, every, missing_after):
    mon = PresenceMonitor(missing_after)
    names_at, names = float("-inf"), {}
    while True:
        now = time.monotonic()
        if now - names_at > 60:
            names, names_at = hostname_map(), now
        for ev in map(_to_wall, mon.step(now, watched_macs(), present_macs())):
            ip = ip_for_mac(ev["mac"]) or ""
            label = "%s (%s)" % (names.get(ip) or ev["mac"], ip or ev["mac"])
            if ev["kind"] == "device_missing":
                health_log("device_missing", t=ev["t"], mac=ev["mac"], ip=ip,
                           name=names.get(ip, ""),
                           detail="not seen since %s" % _stamp(ev["last_seen"]))
                print("NOT CONNECTED  %s -- not seen since %s"
                      % (label, _stamp(ev["last_seen"])))
                _detect_mail(cfg, "[streamwatch] device not connected: %s" % label,
                             "streamwatch - device not connected\n\n"
                             "Device    : %s\nMAC       : %s\nLast seen : %s\n\n"
                             "It is on the allow/watch list but has not been on the\n"
                             "Wi-Fi or answered on the network for %s.\n"
                             % (label, ev["mac"], _stamp(ev["last_seen"]),
                                human_dur(missing_after)))
            else:
                dur = human_dur(ev["duration_s"])
                health_log("device_back", t=ev["t"], mac=ev["mac"], ip=ip,
                           name=names.get(ip, ""), duration_s=ev["duration_s"],
                           detail="missing from %s" % _stamp(ev["missing_since"]))
                print("RECONNECTED  %s after %s" % (label, dur))
                _detect_mail(cfg, "[streamwatch] device back: %s" % label,
                             "streamwatch - device reconnected\n\n"
                             "Device  : %s\nMissing : %s -> %s (%s)\n"
                             % (label, _stamp(ev["missing_since"]),
                                _stamp(ev["t"]), dur))
        time.sleep(every)


# --------------------------------------------------------------- speed test
#
# ADDED. Measures the gateway's own internet link and mails a report.
#
# TWO NUMBERS, DIFFERENT COSTS
#     Latency is a TCP handshake -- a few hundred bytes, effectively free, so
#     it can run as often as you like. Throughput requires actually pulling
#     data down the link, and every byte measured is a byte spent. At the
#     defaults that is 10 MB a probe; once a minute that is 14 GB a day. The
#     startup banner does this arithmetic for your settings and says so.
#
# THE PROBE DOES NOT POLLUTE THE METER
#     The download originates from the router, so neither end of the flow is
#     a LAN address and Meter.local_side() returns None -- the bytes are not
#     attributed to any device and cannot trip a threshold alert. The gate
#     hooks FORWARD -i <lan>, so router-originated traffic bypasses it too.
#     Measuring the link does not disturb what is being measured.
#
# LATENCY BY TCP HANDSHAKE, NOT ping
#     busybox ping formats its summary differently across builds and parsing
#     it is a portability tax for no gain. Timing socket.connect() needs no
#     external command and no root beyond what the script already has.

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=%d"
SPEED_LATENCY_HOST = ("1.1.1.1", 443)

# http, not https, on purpose: the free tier of this service is http-only, and
# it keeps the lookup working on builds with no CA bundle installed. Nothing
# secret is being sent -- the endpoint learns the same public IP it would
# learn from any connection you make to it.
GEO_URL = ("http://ip-api.com/json/?fields=status,message,query,country,"
           "regionName,city,isp,org,as,lat,lon")
GEO_TTL = 3600
GEO_CACHE = {"when": 0.0, "data": None, "last_ip": None}


def public_ip_geo(url=GEO_URL, ttl=GEO_TTL, timeout=10):
    """Public IP and where it registers, cached.

    Cached because it barely changes and the report runs every minute: an
    hourly lookup is enough to catch a dynamic-IP renewal, and it keeps the
    tool well inside the service's free rate limit.

    Returns a dict, or None if the lookup failed. Never raises -- a geo
    service being down must not stop a speed report from going out.
    """
    now = time.time()
    if GEO_CACHE["data"] and (now - GEO_CACHE["when"]) < ttl:
        return GEO_CACHE["data"]
    try:
        import json
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "streamwatch"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return GEO_CACHE["data"] or {"error": str(e)}
    if data.get("status") != "success":
        return {"error": data.get("message", "lookup refused")}

    prev = GEO_CACHE["last_ip"]
    data["changed_from"] = prev if prev and prev != data.get("query") else None
    GEO_CACHE.update({"when": now, "data": data, "last_ip": data.get("query")})
    return data


def geo_lines(geo):
    """The location block at the top of the report."""
    if not geo:
        return []
    if geo.get("error"):
        return ["public IP : lookup failed (%s)" % geo["error"], ""]
    out = ["public IP : %s" % geo.get("query", "?")]
    where = ", ".join(x for x in (geo.get("city"), geo.get("regionName"),
                                  geo.get("country")) if x)
    if where:
        out.append("location  : %s" % where)
    if geo.get("isp"):
        out.append("ISP       : %s" % geo["isp"])
    if geo.get("as"):
        out.append("network   : %s" % geo["as"])
    if geo.get("lat") is not None and geo.get("lon") is not None:
        out.append("map       : https://www.openstreetmap.org/?mlat=%s&mlon=%s"
                   "#map=11/%s/%s" % (geo["lat"], geo["lon"],
                                      geo["lat"], geo["lon"]))
    if geo.get("changed_from"):
        out.append("NOTE      : public IP changed from %s since the last "
                   "lookup" % geo["changed_from"])
    out.append("            (city is where the address is registered -- an "
               "ISP exchange, not the router. Behind CGNAT it is the "
               "carrier's.)")
    out.append("")
    return out


def tcp_latency(host, port, tries=3, timeout=5):
    """Best-of-N milliseconds to complete a TCP handshake. Best, not mean:
    one scheduling hiccup should not be reported as a slow link."""
    import socket
    best = None
    for _ in range(tries):
        s = socket.socket()
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((host, port))
            dt = (time.time() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    return best


def speed_probe(url_tpl, nbytes, timeout=60, latency_only=False):
    """Pull nbytes and time it. Returns a dict, never raises."""
    out = {"when": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    out["latency"] = tcp_latency(*SPEED_LATENCY_HOST)
    if latency_only:
        if out["latency"] is None:
            out["error"] = "no route to %s:%d" % SPEED_LATENCY_HOST
        return out

    try:
        import urllib.request
    except ImportError:
        out["error"] = "urllib missing -- opkg install python3-urllib"
        return out

    url = url_tpl % nbytes if "%d" in url_tpl else url_tpl
    got, ttfb, t0 = 0, None, time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "streamwatch"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                if ttfb is None:
                    ttfb = (time.time() - t0) * 1000.0
                got += len(chunk)
    except Exception as e:
        msg = str(e)
        if "CERTIFICATE" in msg.upper() or "SSL" in msg.upper():
            msg += "  (try: opkg install ca-bundle python3-openssl, or pass "
            msg += "--speed-url with an http:// address)"
        out.update({"error": msg, "bytes": got,
                    "elapsed": time.time() - t0})
        return out

    elapsed = max(time.time() - t0, 1e-6)
    out.update({"bytes": got, "elapsed": elapsed, "ttfb": ttfb,
                "mbps": (got * 8.0) / elapsed / 1e6})
    if got < nbytes * 0.5:
        out["error"] = ("server returned %s, expected about %s -- the URL may "
                        "ignore the size parameter" % (human(got), human(nbytes)))
    return out


def speed_line(s):
    """One-line summary, for the console and the email subject."""
    bits = []
    if s.get("mbps") is not None:
        bits.append("down %.1f Mbit/s (%s in %.1fs)"
                    % (s["mbps"], human(s["bytes"]), s["elapsed"]))
    if s.get("ttfb") is not None:
        bits.append("ttfb %.0f ms" % s["ttfb"])
    if s.get("latency") is not None:
        bits.append("latency %.0f ms" % s["latency"])
    if s.get("error"):
        bits.append("ERROR: %s" % s["error"])
    return "  ".join(bits) or "no measurement"


def speed_body(samples, history, geo=None):
    """Email body: where the link comes out, the batch just taken, then the
    session so far. The session stats are the point -- a single number tells
    you nothing about whether the link is degrading."""
    lines = ["streamwatch - internet speed report", ""]
    lines += geo_lines(geo)
    for s in samples:
        lines.append("%s  %s" % (s["when"], speed_line(s)))

    rates = [h for h in history if h is not None]
    if rates:
        lines += ["", "session: %d successful probe(s)" % len(rates),
                  "  fastest %.1f Mbit/s" % max(rates),
                  "  slowest %.1f Mbit/s" % min(rates),
                  "  average %.1f Mbit/s" % (sum(rates) / len(rates))]
    fails = sum(1 for s in samples if s.get("error"))
    if fails:
        lines.append("  %d probe(s) in this batch failed" % fails)
    return "\n".join(lines) + "\n"


def speed_watcher(cfg, every, nbytes, url, latency_only, email_every,
                  csv_path, geo=True):
    """Background thread: probe, log, and mail a report every N probes."""
    history, batch = [], []

    if csv_path and not os.path.exists(csv_path):
        try:
            with open(csv_path, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "mbps", "bytes", "elapsed_s", "ttfb_ms",
                     "latency_ms", "error"])
        except OSError as e:
            print("  [speed: cannot write %s: %s]" % (csv_path, e))
            csv_path = None

    while True:
        s = speed_probe(url, nbytes, latency_only=latency_only)
        print("  [speed] %s" % speed_line(s))
        history.append(s.get("mbps"))
        batch.append(s)

        if csv_path:
            try:
                with open(csv_path, "a", newline="") as f:
                    csv.writer(f).writerow(
                        [s["when"], "%.2f" % s["mbps"] if s.get("mbps") else "",
                         s.get("bytes", ""),
                         "%.2f" % s["elapsed"] if s.get("elapsed") else "",
                         "%.0f" % s["ttfb"] if s.get("ttfb") else "",
                         "%.0f" % s["latency"] if s.get("latency") else "",
                         s.get("error", "")])
            except OSError:
                pass

        if cfg and len(batch) >= email_every:
            newest = batch[-1]
            g = public_ip_geo() if geo else None
            if g and not g.get("error") and g.get("changed_from"):
                print("  [speed] public IP changed: %s -> %s"
                      % (g["changed_from"], g.get("query")))
            subject = "[streamwatch] speed %s" % (
                "%.1f Mbit/s" % newest["mbps"] if newest.get("mbps")
                else "latency %.0f ms" % newest["latency"]
                if newest.get("latency") else "probe failed")
            if g and not g.get("error") and g.get("city"):
                subject += " from %s" % g["city"]
            try:
                # include_latest stays off: this is a scheduled report, not an
                # alert, and it must never consume close()/open() commands.
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"], subject,
                                 speed_body(batch, history, g))
            except Exception as e:
                print("  [speed: email FAILED: %s]" % e)
            batch = []

        time.sleep(every)


# ------------------------------------------------------------------ quotas
#
# ADDED. limit(x.x.x.x, 500MB) caps a device; exceeding it closes the device
# the same way close(x.x.x.x) does.
#
# USAGE IS PERSISTED, AND THAT IS THE WHOLE POINT
#     Meter counts from process start -- it says so at boot. A quota built on
#     that alone would reset every time the script restarted, so anyone who
#     could get the router to reboot would get a fresh allowance. Usage is
#     therefore accumulated into a file and reloaded on start.
#
#     Accumulated by DELTA, not by copying the meter total: on restart the
#     meter goes back to zero, so a device's counter is advanced by how much
#     the meter has moved since the last check, and a negative move is read
#     as a restart rather than as negative traffic.
#
# WHAT IT CANNOT SEE
#     Only forwarded traffic through this gateway, the same as every other
#     number here. LAN-to-LAN copying between two devices on the same bridge
#     does not pass FORWARD in a way this meters, and nothing on the device
#     itself is visible. It is an internet quota, not a disk quota.

QUOTA_FILE = "/root/.streamwatch_quotas.json"
QUOTAS = {}                  # ip -> {limit, used, period, since, blocked}
QUOTA_METER_SEEN = {}        # ip -> last meter total, for delta accumulation
QUOTA_SAVE_EVERY = 30.0
_quota_saved_at = 0.0


def quota_load():
    try:
        import json
        with open(QUOTA_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            QUOTAS.update(data)
    except Exception:
        pass                 # no file, or corrupt -- start clean, never crash
    return QUOTAS


def quota_save(force=False):
    global _quota_saved_at
    now = time.time()
    if not force and (now - _quota_saved_at) < QUOTA_SAVE_EVERY:
        return
    _quota_saved_at = now
    try:
        import json
        tmp = QUOTA_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(QUOTAS, f)
        os.replace(tmp, QUOTA_FILE)      # atomic: a killed write cannot
    except Exception:                    # leave a half-written quota file
        pass


def quota_period_start(period, now=None):
    """Start of the current window, or None for an absolute quota."""
    now = now or time.time()
    d = datetime.fromtimestamp(now)
    if period == "daily":
        return time.mktime(d.replace(hour=0, minute=0, second=0,
                                     microsecond=0).timetuple())
    if period == "weekly":
        midnight = d.replace(hour=0, minute=0, second=0, microsecond=0)
        return time.mktime(midnight.timetuple()) - d.weekday() * 86400
    if period == "monthly":
        return time.mktime(d.replace(day=1, hour=0, minute=0, second=0,
                                     microsecond=0).timetuple())
    return None


def quota_set(ip, nbytes, period="none"):
    q = QUOTAS.get(ip, {})
    QUOTAS[ip] = {"limit": nbytes,
                  "used": q.get("used", 0) if q.get("period") == period else 0,
                  "period": period,
                  "since": time.time(),
                  "blocked": False}
    quota_save(force=True)
    extra = ""
    if GATE["on"] and gate_is_always(ip):
        extra = ("\n      note: %s is on the always-open list. The quota still "
                 "applies -- exceeding it will close the device." % ip)
    return ("[limit] %s capped at %s%s%s"
            % (ip, human(nbytes),
               " per %s" % period if period != "none" else "", extra))


def quota_clear(ip):
    if ip not in QUOTAS:
        return "[unlimit] %s had no quota" % ip
    was = QUOTAS.pop(ip)
    QUOTA_METER_SEEN.pop(ip, None)
    quota_save(force=True)
    return ("[unlimit] %s quota removed (was %s, used %s). If it was closed by "
            "the quota, send open(%s) to let it back on."
            % (ip, human(was.get("limit", 0)), human(was.get("used", 0)), ip))


def quota_status_lines():
    if not QUOTAS:
        return ["no quotas set"]
    out = []
    for ip, q in sorted(QUOTAS.items()):
        pct = (q["used"] * 100.0 / q["limit"]) if q.get("limit") else 0
        out.append("  %-16s %9s / %-9s  %5.1f%%%s%s"
                   % (ip, human(q.get("used", 0)), human(q.get("limit", 0)),
                      pct,
                      "  per %s" % q["period"] if q.get("period", "none")
                      != "none" else "",
                      "  [CLOSED]" if q.get("blocked") else ""))
    return out


def quota_check(meter, nets, cfg, mode, dry_run, blocked):
    """Advance each quota by the traffic since the last call and close any
    device that has gone over. Called from the poll loop."""
    now = time.time()
    for ip, q in list(QUOTAS.items()):
        start = quota_period_start(q.get("period", "none"), now)
        if start and q.get("since", 0) < start:
            q.update({"used": 0, "since": now, "blocked": False})
            print("  [quota] %s window rolled over, counter reset" % ip)

        e = meter.dev.get(ip)
        current = (e["in"] + e["out"]) if e else 0
        seen = QUOTA_METER_SEEN.get(ip, 0)
        delta = current - seen
        if delta < 0:            # meter restarted underneath us
            delta = current
        QUOTA_METER_SEEN[ip] = current
        if delta:
            q["used"] = q.get("used", 0) + delta

        if q.get("blocked") or q["used"] < q["limit"]:
            continue

        q["blocked"] = True
        quota_save(force=True)
        act = disconnect_device if mode == "full" else block_ip
        msg = act(ip, nets, dry_run=dry_run, blocked=blocked)
        if GATE["on"] and not dry_run:
            msg += "\n      " + gate_revoke(ip)
        print("  [quota] %s EXCEEDED %s (used %s) -- closing\n      %s"
              % (ip, human(q["limit"]), human(q["used"]), msg))

        if cfg:
            try:
                send_email_alert(
                    cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                    cfg["to"],
                    "[streamwatch] %s hit its %s limit - closed"
                    % (ip, human(q["limit"])),
                    "streamwatch - data limit reached\n\n"
                    "IP       : %s\n"
                    "Limit    : %s%s\n"
                    "Used     : %s\n"
                    "Action   : device closed (mode: %s)\n"
                    "Time     : %s\n\n"
                    "To let it back on:  open(%s)\n"
                    "To lift the cap  :  unlimit(%s)\n"
                    "To raise the cap :  limit(%s, 2GB)\n\n"
                    "Counts forwarded traffic through this gateway only, and\n"
                    "survives a restart of streamwatch.\n"
                    % (ip, human(q["limit"]),
                       " per %s" % q["period"] if q.get("period", "none")
                       != "none" else "",
                       human(q["used"]), mode,
                       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       ip, ip, ip))
            except Exception as ex:
                print("  [quota: email FAILED: %s]" % ex)
    quota_save()


# ------------------------------------------------------------ usage report
#
# ADDED. A scheduled roll-up of every device on the LAN and what it has used.
#
# WHY A SNAPSHOT AND NOT THE METER DIRECTLY
#     Meter.dev is written by the poll loop in the main thread. A reporting
#     thread walking that dict while it grows can raise "dictionary changed
#     size during iteration" -- rarely, and therefore at the worst time. The
#     poll loop instead publishes a finished list of rows each cycle and the
#     reporter reads that. One writer, one reader, no lock needed.
#
# "CONNECTED" IS WIDER THAN "METERED"
#     A device with a lease and an ARP entry but no traffic yet never appears
#     in the meter. Leaving it out would answer a different question from the
#     one asked, so the report unions the meter with the lease and ARP tables
#     and shows the idle ones at 0 B. A device that is present and silent is
#     worth seeing -- especially one the gate is blocking.

USAGE_SNAPSHOT = {"when": 0.0, "rows": []}
USAGE_PREV = {}                  # ip -> total at the last report


def usage_snapshot_update(meter, names):
    """Called from the poll loop. Cheap: a handful of devices."""
    rows = []
    for ip, e in list(meter.dev.items()):
        rows.append({"ip": ip, "name": names.get(ip, ""),
                     "in": e["in"], "out": e["out"],
                     "total": e["in"] + e["out"]})
    USAGE_SNAPSHOT["rows"] = rows
    USAGE_SNAPSHOT["when"] = time.time()


def connected_devices(nets):
    """{ip: hostname} for everything holding a lease or sitting in ARP."""
    out = {}
    try:
        with open("/tmp/dhcp.leases", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 4:
                    out.setdefault(p[2], p[3] if p[3] != "*" else "")
    except OSError:
        pass
    try:
        with open("/proc/net/arp", errors="replace") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[3] != "00:00:00:00:00:00":
                    out.setdefault(c[0], "")
    except OSError:
        pass
    return {ip: n for ip, n in out.items()
            if any(in_net(ip, net) for net in nets)}


def usage_report_body(nets, period_sec):
    """The report text. Two usage columns on purpose: what a device used in
    this window answers "who is busy now", the running total answers "who is
    heavy overall", and they are different devices more often than not."""
    rows = {r["ip"]: r for r in USAGE_SNAPSHOT["rows"]}
    for ip, name in connected_devices(nets).items():
        if ip not in rows:
            rows[ip] = {"ip": ip, "name": name, "in": 0, "out": 0, "total": 0}
        elif not rows[ip]["name"]:
            rows[ip]["name"] = name

    ordered = sorted(rows.values(), key=lambda r: -r["total"])

    # One iwinfo sweep for the whole report. Calling rssi_for_ip() per row
    # would re-resolve every MAC and re-shell out per device; the cache in
    # wifi_rssi_map() makes that harmless but the intent is clearer this way,
    # and the detail block below needs the raw dBm anyway.
    radio = wifi_rssi_map()
    wifi = []                        # rows that have a signal, for the detail

    row_fmt = "%-16s %-14s %9s %9s %11s %9s %8s %10s"
    lines = ["streamwatch - data usage report", "",
             "Window   : last %s" % human_time(period_sec),
             "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "Devices  : %d on the LAN" % len(ordered), "",
             row_fmt % ("IP", "HOSTNAME", "IN", "OUT", "THIS WINDOW", "TOTAL",
                        "SIGNAL", "DISTANCE"),
             "-" * 93]

    sum_win = sum_tot = 0
    for r in ordered:
        prev = USAGE_PREV.get(r["ip"], 0)
        window = r["total"] - prev
        if window < 0:                 # counters reset under us
            window = r["total"]
        USAGE_PREV[r["ip"]] = r["total"]
        sum_win += window
        sum_tot += r["total"]

        mac = mac_for_ip(r["ip"])
        info = radio.get(mac) if mac else None
        if info:
            signal = "%d dBm" % info["rssi"]
            distance = rssi_distance_short(info["rssi"], mac)
            wifi.append((r, mac, info))
        else:
            # A wired device has no RSSI and never will, so there is no
            # distance to estimate. A dash says that; a 0 would sort and
            # average as though it were a measurement.
            signal, distance = "wired", "-"

        lines.append(row_fmt
                     % (r["ip"], (r["name"] or "-")[:14],
                        human(r["in"]), human(r["out"]),
                        human(window), human(r["total"]), signal, distance))

    lines += ["-" * 93,
              "%-31s %9s %9s %11s %9s"
              % ("TOTAL", "", "", human(sum_win), human(sum_tot))]

    lines += _distance_block(wifi)

    if QUOTAS:
        lines += ["", "Quotas:"] + quota_status_lines()

    closed = [r["ip"] for r in ordered
              if QUOTAS.get(r["ip"], {}).get("blocked")]
    if closed:
        lines += ["", "Currently closed by quota: %s" % ", ".join(closed),
                  "  send open(x.x.x.x) to restore, unlimit(x.x.x.x) to "
                  "drop the cap"]

    lines += ["",
              "Counts forwarded traffic through this gateway since streamwatch",
              "started. Devices listed at 0 B hold a lease or an ARP entry but",
              "have sent nothing -- present and silent, which for a gated",
              "device is exactly what you would expect to see."]
    return "\n".join(lines) + "\n"


def _distance_block(wifi):
    """The per-device distance detail printed under the usage table.

    The table gives one number per device because a column has room for one.
    That number alone reads as a measurement, which it is not: it is a model
    output, and the range around it is wide. This block prints the range, the
    model each device was estimated with, and where that model came from.
    """
    if not wifi:
        return ["", "No device is associated to a radio right now, so there",
                "is no signal to turn into a distance. Wired devices never",
                "have one."]

    out = ["", "Distance from the router (Wi-Fi devices only)", ""]
    for r, mac, info in wifi:
        rng, how = rssi_distance_range(info["rssi"], mac)
        out.append("  %-15s %-14s %4d dBm (%s)  ->  %s"
                   % (r["ip"], (r["name"] or "-")[:14], info["rssi"],
                      rssi_quality(info["rssi"]),
                      rssi_distance_short(info["rssi"], mac)))
        out.append("      %-17s on %-8s  likely %s   [%s]"
                   % (mac, info.get("iface", "?"), rng, how))

    out += ["",
            "HOW TO READ THESE",
            "  Distance is computed from signal strength, not measured. A 6 dB",
            "  swing is ordinary indoors from multipath and a hand near the",
            "  antenna, and that alone is the width of the range shown. One",
            "  concrete wall costs around 15 dB, which the model reads as",
            "  roughly three times further away rather than as an obstacle -- so",
            "  a device behind a wall reports too far, every time.",
            "",
            "  Model in use: RSSI = A - 10*n*log10(distance),",
            "                A=%.1f dBm at 1 m, n=%.2f"
            % (RSSI_CAL["ref"], RSSI_CAL["n"])]
    out += txt_calib_lines()
    if TXT_CALIB["ref"] is None:
        out += ["  No three-point calibration is loaded (%s: %s), so these are",
                "  generic indoor numbers. Run rssi_dist.py calibrate to fix that."]
        out[-2] = out[-2] % (TXT_CALIB["path"], TXT_CALIB["error"] or "unread")
    out.append("  The reference file decides for every device. A per-device")
    out.append("  calibrate(x.x.x.x) is used only where no reference file is")
    out.append("  loaded, unless streamwatch was started with "
               "--prefer-per-device.")
    return out


def human_time(sec):
    if sec >= 3600 and sec % 3600 == 0:
        return "%d hour(s)" % (sec // 3600)
    if sec >= 60:
        return "%d min" % (sec // 60)
    return "%ds" % sec


def usage_reporter(cfg, nets, every):
    """Background thread: mail the roll-up on a fixed interval."""
    while True:
        time.sleep(every)            # sleep first: an instant report at boot
        if not USAGE_SNAPSHOT["rows"] and not connected_devices(nets):
            continue                 # would show nothing but zeroes
        body = usage_report_body(nets, every)
        n = len(USAGE_SNAPSHOT["rows"])
        print("  [usage report: %d device(s) -> %s]"
              % (n, cfg["to"] if cfg else "console only"))
        if not cfg:
            print(body)
            continue
        try:
            send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                             cfg["password"], cfg["to"],
                             "[streamwatch] usage report - %d device(s)" % n,
                             body)
        except Exception as e:
            print("  [usage report: email FAILED: %s]" % e)


# ----------------------------------------------------------------- shaping
#
# ADDED. throttle(x.x.x.x, 2mbit) caps a device's SPEED. It keeps working,
# it just cannot go faster. Distinct from limit(), which grants an amount of
# data and then closes the device.
#
# WHY tc AND NOT iptables
#     iptables decides yes or no per packet. Rate limiting needs a queue: hold
#     packets back, release them at a set pace, let TCP notice and slow down.
#     That is a queueing discipline, which is tc's job. HTB (hierarchical
#     token bucket) gives one class per device with its own ceiling.
#
# SHAPING ONLY WORKS ON THE WAY OUT OF AN INTERFACE
#     So a device's DOWNLOAD is shaped on the LAN interface (packets leaving
#     the router toward the device) and its UPLOAD on the WAN interface
#     (packets leaving the router toward the internet). Two qdiscs, one job.
#
#     A consequence worth stating plainly: download shaping happens after the
#     bytes have already crossed your internet link. It cannot stop them
#     arriving -- it drops and delays them at the router so TCP backs off and
#     the sender slows down. The device sees the cap; your ISP link still
#     briefly carried the excess. Only the ISP can police it any earlier.
#
# RULES DO NOT SURVIVE A REBOOT
#     Same as the gate. The throttle table is persisted and reapplied at
#     startup, so a restart restores them -- a reboot needs streamwatch to
#     run again.

THROTTLE_FILE = "/root/.streamwatch_throttles.json"
THROTTLES = {}               # ip -> {"down": kbit, "up": kbit, "slot": n}
SHAPER = {"roots": set()}      # interfaces that already carry an HTB root
SHAPER_ROOT_RATE = "1000mbit"
RATE_RE = re.compile(r"^\s*([0-9.]+)\s*([kmg]?)(bit|bps|b)?\s*$", re.I)


def parse_rate(text):
    """'2mbit' / '512kbit' / '1.5M' -> kilobits per second. A bare number is
    read as kbit, which is what tc itself assumes."""
    m = RATE_RE.match(text or "")
    if not m:
        raise ValueError("bad rate: %r" % text)
    val, unit = float(m.group(1)), (m.group(2) or "k").lower()
    kbit = {"k": val, "m": val * 1000, "g": val * 1000000}[unit]
    if kbit <= 0:
        raise ValueError("rate must be positive")
    return int(kbit)


def human_rate(kbit):
    if kbit >= 1000000:
        return "%.2f Gbit/s" % (kbit / 1000000.0)
    if kbit >= 1000:
        return "%.2f Mbit/s" % (kbit / 1000.0)
    return "%d kbit/s" % kbit


def tc_run(*args):
    try:
        p = subprocess.run(["tc"] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=20)
        return p.returncode, p.stderr.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def iface_for_ip(ip):
    """Which interface actually reaches this address.

    Taking the first LAN bridge was wrong: a router with br-guest and br-lan
    would get the shaper built on whichever sorted first, and a device on the
    other bridge would be "throttled" by a queue its packets never touch --
    silently, because every tc command succeeds.

    `ip route get` asks the kernel the same question it answers when routing
    the packet, so the queue lands where the traffic is.
    """
    out = run(["ip", "route", "get", ip])
    m = re.search(r"\bdev\s+(\S+)", out or "")
    return m.group(1) if m else None


def shaper_ensure_root(iface):
    """Idempotent HTB root on one interface. Returns None, or why it failed."""
    if not iface:
        return "no interface"
    if iface in SHAPER["roots"]:
        return None
    if not run(["which", "tc"]).strip():
        return "tc is not installed -- run: opkg update && opkg install tc"
    if "htb" not in run(["tc", "qdisc", "show", "dev", iface]):
        rc, err = tc_run("qdisc", "add", "dev", iface, "root", "handle", "1:",
                         "htb", "default", "9999")
        if rc != 0:
            return ("could not create the queue on %s: %s (missing HTB? "
                    "opkg install kmod-sched)" % (iface, err))
        tc_run("class", "add", "dev", iface, "parent", "1:", "classid", "1:1",
               "htb", "rate", SHAPER_ROOT_RATE)
        tc_run("class", "add", "dev", iface, "parent", "1:1", "classid",
               "1:9999", "htb", "rate", SHAPER_ROOT_RATE, "ceil",
               SHAPER_ROOT_RATE)
    SHAPER["roots"].add(iface)
    return None


def _next_slot():
    used = {t["slot"] for t in THROTTLES.values()}
    n = 10
    while n in used:
        n += 1
    return n


def throttle_load():
    try:
        import json
        with open(THROTTLE_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            THROTTLES.update(data)
    except Exception:
        pass
    return THROTTLES


def throttle_save():
    try:
        import json
        tmp = THROTTLE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(THROTTLES, f)
        os.replace(tmp, THROTTLE_FILE)
    except Exception:
        pass


def _apply_one(ip, down_kbit, up_kbit, slot, dev_iface, wan):
    """One HTB class plus one filter per direction.

    Each device gets its own filter priority as well as its own class id.
    Deleting by priority removes that device's filter and nothing else --
    tc has no way to delete a u32 filter by the address it matches.
    """
    errs = []
    for iface, rate, match in ((dev_iface, down_kbit, "dst"),
                               (wan, up_kbit, "src")):
        if not rate or not iface:
            continue
        problem = shaper_ensure_root(iface)
        if problem:
            errs.append(problem)
            continue
        # `replace` and not `add`: re-sending a throttle for a device that
        # already has one is normal (raising a cap, reapplying after a
        # restart), and `add` fails with "File exists" -- which previously
        # aborted the rest of this direction and left the class without its
        # filter, so nothing was classified into it and nothing was shaped.
        rc, err = tc_run("class", "replace", "dev", iface, "parent", "1:1",
                         "classid", "1:%d" % slot, "htb",
                         "rate", "%dkbit" % rate, "ceil", "%dkbit" % rate,
                         "burst", "15k")
        if rc != 0:
            errs.append("%s class: %s" % (iface, err))
            continue
        # sfq under the class so one greedy flow cannot starve the others
        # within the device's own allowance.
        tc_run("qdisc", "replace", "dev", iface, "parent", "1:%d" % slot,
               "handle", "%d:" % slot, "sfq", "perturb", "10")
        # The filter has no replace form keyed on the address, so clear this
        # device's priority first. Repeated: one delete removes one filter.
        for _ in range(10):
            drc, _e = tc_run("filter", "del", "dev", iface, "parent", "1:",
                             "prio", str(slot))
            if drc != 0:
                break
        rc, err = tc_run("filter", "add", "dev", iface, "protocol", "ip",
                         "parent", "1:", "prio", str(slot), "u32",
                         "match", "ip", match, "%s/32" % ip,
                         "flowid", "1:%d" % slot)
        if rc != 0:
            errs.append("%s filter: %s" % (iface, err))
    return errs


def throttle_set(ip, down_kbit, up_kbit, lan_ifaces=None, wan=None):
    dev_iface = iface_for_ip(ip)
    wan = wan or wan_iface()
    if not dev_iface:
        return ("[throttle] cannot shape %s: no route to it, so there is no "
                "interface to queue on" % ip)
    slot = THROTTLES.get(ip, {}).get("slot") or _next_slot()
    errs = _apply_one(ip, down_kbit, up_kbit, slot, dev_iface, wan)
    if errs:
        return "[throttle] %s FAILED: %s" % (ip, "; ".join(errs))

    # Read the rules back rather than trusting exit codes. The class alone
    # shapes nothing -- without a filter, no packet is ever classified into
    # it, which is exactly how this failed silently before.
    #
    # Check the FILTER, not the class: `tc class show` prints nothing on
    # tc-tiny even when classes exist, so requiring it produced a false
    # warning on a working setup. And tc renders the address in hex --
    # c0a80874 is 192.168.8.116 -- so the dotted form never appears.
    filt = (run(["tc", "filter", "show", "dev", dev_iface]) or "").lower()
    try:
        ip_hex = "%08x" % ip_to_int(ip)
    except ValueError:
        ip_hex = ""
    landed = ("flowid 1:%d" % slot) in filt and (ip in filt or
                                                (ip_hex and ip_hex in filt))
    THROTTLES[ip] = {"down": down_kbit, "up": up_kbit, "slot": slot,
                     "iface": dev_iface, "wan": wan}
    throttle_save()
    return ("[throttle] %s capped at %s down (%s) / %s up (%s)%s"
            % (ip, human_rate(down_kbit), dev_iface, human_rate(up_kbit), wan,
               "" if landed else
               "  -- WARNING: tc accepted the rules but no matching filter is "
               "visible; verify with a speed test"))


def throttle_clear(ip):
    if ip not in THROTTLES:
        return "[unthrottle] %s was not throttled" % ip
    t = THROTTLES.pop(ip)
    throttle_save()
    for iface in (t.get("iface") or iface_for_ip(ip), t.get("wan") or wan_iface()):
        if not iface:
            continue
        tc_run("filter", "del", "dev", iface, "parent", "1:",
               "prio", str(t["slot"]))
        tc_run("class", "del", "dev", iface, "classid", "1:%d" % t["slot"])
    return "[unthrottle] %s back to full speed" % ip


def throttle_status_lines():
    if not THROTTLES:
        return ["no throttles set"]
    return ["  %-16s %12s down  %12s up   on %s" % (ip, human_rate(t["down"]),
                                                    human_rate(t["up"]),
                                                    t.get("iface", "?"))
            for ip, t in sorted(THROTTLES.items())]


def throttle_reapply(lan_ifaces=None, wan=None):
    """tc rules are gone after a reboot. Put back what the file remembers.
    The interface is resolved again rather than trusted from the file -- a
    device may have moved bridges since it was saved."""
    if not THROTTLES:
        return None
    n = 0
    for ip, t in THROTTLES.items():
        dev = iface_for_ip(ip) or t.get("iface")
        w = wan or wan_iface()
        if dev and not _apply_one(ip, t["down"], t["up"], t["slot"], dev, w):
            t["iface"], t["wan"] = dev, w
            n += 1
    throttle_save()
    return "  [throttle] reapplied %d of %d saved throttle(s)" % (
        n, len(THROTTLES))


def shaper_teardown():
    """Printed at startup so the shaper can be removed by hand."""
    ifaces = SHAPER["roots"] or {t.get("iface") for t in THROTTLES.values()}
    ifaces = sorted(i for i in ifaces if i)
    if not ifaces:
        return "tc qdisc del dev <iface> root"
    return " ; ".join("tc qdisc del dev %s root" % i for i in ifaces)


# --------------------------------------------------------- device identity
#
# ADDED. A durable record of every device that has ever appeared.
#
# THE MAC IS THE ONLY PERMANENT HANDLE A GATEWAY GETS
#     Not the IP -- that is a lease and moves. Not the hostname -- a device
#     sets it and can change it. Not an IMEI -- that identifies a cellular
#     modem, is exchanged only with the carrier, and never crosses Wi-Fi in
#     any frame, so no router can read one.
#
#     The MAC is durable, with one large exception: modern phones randomise
#     it per network. A randomised MAC is stable for as long as the device
#     remembers the network and changes if it forgets and rejoins. That is
#     detectable -- the second-least-significant bit of the first octet is
#     the "locally administered" flag -- so the registry marks those devices
#     as having an identity that can expire, rather than pretending they are
#     permanent.
#
# WHAT THE REGISTRY ADDS OVER A LEASE TABLE
#     Leases expire and are recycled. This keeps first-seen, last-seen, every
#     hostname a MAC has used and every IP it has held, so "is this new" has
#     an answer that outlives the lease file.

DEVICES_FILE = "/root/.streamwatch_devices.json"
DEVICES = {}                 # mac -> record

# Enough of the OUI space to name the common cases. A full IEEE list is 30k
# entries; if the box has one from another tool, that wins.
OUI_FALLBACK = {
    "00:03:93": "Apple", "00:1b:63": "Apple", "00:25:00": "Apple",
    "3c:15:c2": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "00:16:32": "Samsung", "00:23:39": "Samsung", "5c:0a:5b": "Samsung",
    "00:1a:11": "Google", "f4:f5:e8": "Google", "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "24:0a:c4": "Espressif",
    "a0:20:a6": "Espressif", "50:02:91": "Espressif",
    "44:65:0d": "Amazon", "fc:65:de": "Amazon", "00:24:e4": "Withings",
    "00:17:88": "Philips Hue", "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link",
    "00:1d:0f": "TP-Link", "8c:85:90": "Xiaomi", "64:09:80": "Xiaomi",
    "00:e0:4c": "Realtek", "00:1c:c4": "HP", "3c:97:0e": "Wistron",
    "00:15:5d": "Microsoft Hyper-V", "94:9f:3e": "Sonos",
    "b8:e9:37": "Sonos", "cc:9e:a2": "Roku", "d8:31:34": "Roku",
    "18:b4:30": "Nest", "00:04:20": "Slim Devices", "e4:5e:37": "Intel",
    "94:e6:f7": "Intel", "00:1e:c2": "Apple", "6c:ad:f8": "Azurewave",
}


def mac_is_randomised(mac):
    """True when the locally-administered bit is set -- a MAC the device made
    up rather than one burned in at the factory. Apple, Android and Windows
    all do this per network now, and it is why 'the MAC' is not automatically
    a permanent identity."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, AttributeError, IndexError):
        return False
    return bool(first & 0x02)


def oui_vendor(mac):
    """Manufacturer from the first three octets. Meaningless for a randomised
    MAC -- there is no vendor in an address the device invented -- so that is
    said rather than guessed."""
    if mac_is_randomised(mac):
        return "(randomised - no vendor)"
    prefix = mac.lower()[:8]
    for path in ("/etc/manuf", "/usr/share/nmap/nmap-mac-prefixes",
                 "/usr/share/wireshark/manuf"):
        try:
            key = prefix.replace(":", "").upper()
            with open(path, errors="replace") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    parts = line.split(None, 2)
                    if not parts:
                        continue
                    cand = parts[0].replace(":", "").replace("-", "").upper()
                    if cand[:6] == key[:6]:
                        return parts[1] if len(parts) > 1 else "?"
        except OSError:
            continue
    return OUI_FALLBACK.get(prefix, "unknown")


def devices_load():
    try:
        import json
        with open(DEVICES_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            DEVICES.update(data)
    except Exception:
        pass
    return DEVICES


def devices_save():
    try:
        import json
        tmp = DEVICES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(DEVICES, f)
        os.replace(tmp, DEVICES_FILE)
    except Exception:
        pass


def devices_scan(nets):
    """Every MAC visible right now, from leases, ARP and the radios.

    Three sources because each misses something: a lease exists before the
    device sends anything, ARP holds devices with static addresses that never
    asked for a lease, and assoclist sees a station that associated but has
    not yet been given an address -- which is exactly what a gated device
    looks like.
    """
    seen = {}
    try:
        with open("/tmp/dhcp.leases", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 4 and any(in_net(p[2], n) for n in nets):
                    seen.setdefault(p[1].lower(), {}).update(
                        {"ip": p[2],
                         "hostname": p[3] if p[3] != "*" else ""})
    except OSError:
        pass
    try:
        with open("/proc/net/arp", errors="replace") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[3] != "00:00:00:00:00:00" \
                        and any(in_net(c[0], n) for n in nets):
                    seen.setdefault(c[3].lower(), {}).setdefault("ip", c[0])
    except OSError:
        pass
    for mac, info in wifi_rssi_map(ttl=0).items():
        seen.setdefault(mac, {})["radio"] = info.get("iface", "")
        seen[mac]["rssi"] = info.get("rssi")
    return seen


def devices_update(nets):
    """Fold the current scan into the registry. Returns newly-seen MACs."""
    now = time.time()
    new = []
    for mac, info in devices_scan(nets).items():
        rec = DEVICES.get(mac)
        if rec is None:
            rec = {"first_seen": now, "hostnames": [], "ips": [],
                   "vendor": oui_vendor(mac),
                   "randomised": mac_is_randomised(mac)}
            DEVICES[mac] = rec
            new.append(mac)
        rec["last_seen"] = now
        if info.get("hostname") and info["hostname"] not in rec["hostnames"]:
            rec["hostnames"].append(info["hostname"])
        if info.get("ip") and info["ip"] not in rec["ips"]:
            rec["ips"].append(info["ip"][:64])
            del rec["ips"][:-10]         # keep the last ten, not a lifetime
        if info.get("radio"):
            rec["radio"] = info["radio"]
        if info.get("rssi") is not None:
            rec["rssi"] = info["rssi"]
    devices_save()
    return new


def device_line(mac, rec):
    age = time.time() - rec.get("first_seen", 0)
    days = age / 86400.0
    return ("  %-17s  %-16s  %-22s  first seen %s  %s%s"
            % (mac,
               (rec.get("hostnames") or ["-"])[-1][:16],
               rec.get("vendor", "?")[:22],
               ("%.1f days ago" % days) if days >= 1
               else ("%.0f min ago" % (age / 60.0)),
               (rec.get("ips") or ["-"])[-1],
               "  [RANDOMISED MAC - identity can change]"
               if rec.get("randomised") else ""))


def devices_report_body(nets):
    live = set(devices_scan(nets))
    lines = ["streamwatch - device registry", "",
             "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "Known    : %d device(s), %d on the network right now"
             % (len(DEVICES), len(live)), "", "ON THE NETWORK NOW:"]
    for mac in sorted(live):
        if mac in DEVICES:
            lines.append(device_line(mac, DEVICES[mac]))
    absent = [m for m in DEVICES if m not in live]
    if absent:
        lines += ["", "SEEN BEFORE, NOT PRESENT NOW:"]
        for mac in sorted(absent,
                          key=lambda m: -DEVICES[m].get("last_seen", 0))[:30]:
            lines.append(device_line(mac, DEVICES[mac]))

    randomised = [m for m in live if DEVICES.get(m, {}).get("randomised")]
    if randomised:
        lines += ["",
                  "%d device(s) here use a randomised MAC. That address is the"
                  % len(randomised),
                  "only permanent handle this router has for them, and it will",
                  "change if the device forgets and rejoins the network -- at",
                  "which point an --always-open entry stops matching and the",
                  "device is silently blocked. On iOS: Wi-Fi > (i) > Private",
                  "Wi-Fi Address > off. On Android: network > Privacy > Use",
                  "device MAC.",
                  "",
                  "A gateway cannot read an IMEI: that identifies a cellular",
                  "modem, is exchanged only with the carrier, and appears in no",
                  "Wi-Fi, DHCP, ARP or IP field."]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ dns watching
#
# ADDED. Which domains a device is looking up.
#
# HOW
#     dnsmasq already resolves for every device on the LAN; it just does not
#     record the queries unless asked. With logqueries on it writes one line
#     per lookup to syslog, and a thread following `logread -f` turns those
#     into per-device counts. No packet capture, no extra daemon.
#
# WHAT THIS DOES AND DOES NOT SHOW
#     It shows DOMAINS LOOKED UP, which is not the same as pages visited:
#
#     - A cached lookup produces no query. A device can browse a site all
#       afternoon after one lookup and appear here once.
#     - One page visit produces dozens of lookups -- fonts, analytics, CDNs,
#       ad exchanges. The list is mostly infrastructure, not intent.
#     - There is no URL path, ever. DNS carries the host, nothing after it.
#     - Encrypted DNS bypasses this completely. A device using DoH or DoT
#       resolves over HTTPS to Cloudflare or Google directly, and the router
#       never sees the name. iCloud Private Relay hides everything. Modern
#       phones and browsers increasingly do this by default, so absence of
#       queries from a device is not absence of browsing.
#
#     Read it as a rough picture of what a device talks to, not a record of
#     what someone did.

DNS_QUERY = re.compile(
    r"query\[[A-Z]+\]\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})")
DNS_LOG = {}                 # ip -> {domain: [count, last_seen, first_seen]}
DNS_MAX_DOMAINS = 400
DNS_STATE = {"on": False, "lines": 0}

# Lookups every device makes constantly; they drown the interesting ones.
DNS_NOISE = (".lan", ".local", "in-addr.arpa", "ip6.arpa", "_tcp.local",
             "_udp.local",
             ".local", "wpad.", "isatap.")

# Category before hostname, because "what kind of thing is this device doing"
# is the question a list of 60 hostnames does not answer.
#
# The last three categories are BACKGROUND: content delivery, advertising and
# operating-system telemetry. Those are the overwhelming majority of lookups
# on any device and none of them represent a person choosing to go somewhere.
# Mixing them into the same list is what made the previous report unreadable.
DNS_CATEGORIES = (
    ("Social media", ("facebook", "fbcdn", "instagram", "twitter", "x.com",
                      "tiktok", "snapchat", "linkedin", "reddit", "pinterest",
                      "threads.net", "tumblr", "mastodon")),
    ("Video / streaming", ("youtube", "googlevideo", "ytimg", "netflix",
                           "twitch", "vimeo", "dailymotion", "shahid",
                           "primevideo", "disneyplus", "hulu", "spotify",
                           "soundcloud", "anghami")),
    ("Messaging / calls", ("whatsapp", "telegram", "signal", "discord",
                           "slack", "messenger", "zoom.us", "teams.microsoft",
                           "skype", "botim")),
    ("Email", ("gmail", "mail.google", "outlook", "hotmail", "imap.",
               "smtp.", "protonmail", "yahoo.mail", "zoho")),
    ("Search", ("google.com/search", "bing.com", "duckduckgo", "yandex",
                "ecosia", "brave.com/search")),
    ("Shopping", ("amazon", "ebay", "aliexpress", "noon.com", "jarir",
                  "extra.com", "shein", "namshi", "temu", "etsy", "ikea")),
    ("News", ("bbc.", "cnn.", "aljazeera", "nytimes", "reuters", "sabq",
              "okaz", "arabnews", "theguardian", "spa.gov")),
    ("Banking / finance", ("bank", "alrajhi", "sabb", "riyadbank", "stcpay",
                           "paypal", "visa.com", "mastercard", "tadawul")),
    ("Government / services", (".gov.sa", "absher", "tawakkalna", "moi.gov",
                               "elm.sa", "najiz")),
    ("AI tools", ("openai", "chatgpt", "anthropic", "claude.ai", "gemini",
                  "perplexity", "copilot", "huggingface")),
    ("Developer", ("github", "gitlab", "stackoverflow", "npmjs", "pypi",
                   "docker", "readthedocs", "bitbucket", "openwrt")),
    ("Maps / travel", ("openstreetmap", "maps.google", "waze", "booking.com",
                       "airbnb", "almosafer", "flyadeal", "saudia")),
    ("Remote access", ("anydesk", "teamviewer", "rustdesk", "logmein",
                       "splashtop")),
    ("Gaming", ("steampowered", "epicgames", "playstation", "xbox",
                "riotgames", "roblox", "minecraft", "battle.net")),
    ("Cloud / CDN", ("gstatic", "googleapis", "akamai", "cloudfront",
                     "cloudflare", "fastly", "azureedge", "licdn", "cdn.",
                     "amazonaws", "edgekey", "edgesuite", "jsdelivr")),
    ("Ads / tracking", ("doubleclick", "googlesyndication", "google-analytics",
                        "adservice", "scorecardresearch", "criteo", "taboola",
                        "outbrain", "adnxs", "moatads", "branch.io",
                        "appsflyer", "adjust.com", "segment.io")),
    ("OS / telemetry", ("windowsupdate", "msftconnecttest", "msftncsi",
                        "apple.com", "icloud", "mesu.apple", "push.apple",
                        "gvt1.com", "gvt2.com", "connectivitycheck",
                        "ntp.", "pool.ntp", "time.", "dns.msftncsi")),
)
DNS_BACKGROUND = ("Cloud / CDN", "Ads / tracking", "OS / telemetry")


def _key_matches(domain, key):
    """Substring matching alone put signaler-pa.clients6.google.com under
    Messaging because it contains "signal". A key must sit on a label
    boundary: preceded by start, dot or hyphen, and followed by end, dot or
    hyphen. Keys that already contain a dot are matched as written."""
    if "." in key:
        return key in domain
    start = 0
    while True:
        i = domain.find(key, start)
        if i < 0:
            return False
        before = domain[i - 1] if i else "."
        after = domain[i + len(key)] if i + len(key) < len(domain) else "."
        if before in ".-" and after in ".-":
            return True
        start = i + 1


def dns_categorise(domain):
    d = domain.lower()
    for name, keys in DNS_CATEGORIES:
        if any(_key_matches(d, k) for k in keys):
            return name
    return "Other"


def dns_logging_enabled():
    return "1" in run(["uci", "-q", "get", "dhcp.@dnsmasq[0].logqueries"])


def dns_enable_logging():
    """Turn on dnsmasq query logging. Restarts dnsmasq, which drops DNS for
    about a second -- worth saying out loud since it briefly interrupts every
    device on the network."""
    if dns_logging_enabled():
        return "already on"
    run(["uci", "set", "dhcp.@dnsmasq[0].logqueries=1"])
    run(["uci", "commit", "dhcp"])
    out = run(["/etc/init.d/dnsmasq", "restart"])
    if dns_logging_enabled():
        return ("enabled (dnsmasq restarted -- DNS paused for a moment). "
                "Undo with: uci delete dhcp.@dnsmasq[0].logqueries ; "
                "uci commit dhcp ; /etc/init.d/dnsmasq restart")
    return "FAILED to enable: %s" % (out or "uci refused")


def dns_watcher():
    """Follow syslog and count lookups per device.

    `logread -f` rather than polling `logread`: the log rotates and a poll
    would double-count or miss lines depending on timing. A follower sees
    each line exactly once.
    """
    try:
        p = subprocess.Popen(["logread", "-f"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, bufsize=1,
                             universal_newlines=True)
    except (OSError, subprocess.SubprocessError) as e:
        print("  [dns: cannot follow the log: %s]" % e)
        return
    DNS_STATE["on"] = True
    for line in p.stdout:
        m = DNS_QUERY.search(line)
        if not m:
            continue
        domain, ip = m.group(1).lower(), m.group(2)
        if any(n in domain for n in DNS_NOISE):
            continue
        DNS_STATE["lines"] += 1
        per = DNS_LOG.setdefault(ip, {})
        rec = per.get(domain)
        now = time.time()
        if rec:
            rec[0] += 1
            rec[1] = now
        else:
            per[domain] = [1, now, now]      # count, last, first
            if len(per) > DNS_MAX_DOMAINS:
                # Drop the least-recently-seen, not the least-frequent: a site
                # visited once today is more interesting than a CDN hit a
                # thousand times last week.
                oldest = min(per, key=lambda d: per[d][1])
                per.pop(oldest, None)


def dns_group(domain):
    """Fold sub-domains into the registrable name. Kept for the compact view
    only -- the detailed report classifies the FULL hostname instead, because
    the sub-domain is where the useful signal lives. Collapsing
    edge-mqtt.facebook.com to facebook.com discards the fact that it was
    Instagram's push channel, not someone browsing Facebook."""
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain
    if len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# Registrable domain -> service. Several services share one company's
# infrastructure, which is why a domain alone identifies the wrong thing:
# Instagram's app resolves facebook.com hostnames for push and graph calls.
SERVICE_DOMAINS = {
    "instagram.com": "Instagram", "cdninstagram.com": "Instagram",
    "facebook.com": "Facebook/Meta", "fbcdn.net": "Facebook/Meta",
    "fb.com": "Facebook/Meta", "messenger.com": "Messenger",
    "whatsapp.com": "WhatsApp", "whatsapp.net": "WhatsApp",
    "youtube.com": "YouTube", "googlevideo.com": "YouTube",
    "ytimg.com": "YouTube", "youtu.be": "YouTube",
    "tiktokv.com": "TikTok", "tiktokcdn.com": "TikTok",
    "byteoversea.com": "TikTok", "tiktok.com": "TikTok",
    "snapchat.com": "Snapchat", "sc-cdn.net": "Snapchat",
    "twitter.com": "X/Twitter", "x.com": "X/Twitter",
    "twimg.com": "X/Twitter", "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix", "nflximg.net": "Netflix",
    "spotify.com": "Spotify", "scdn.co": "Spotify",
    "telegram.org": "Telegram", "t.me": "Telegram",
    "twitch.tv": "Twitch", "ttvnw.net": "Twitch",
    "reddit.com": "Reddit", "redd.it": "Reddit",
    "linkedin.com": "LinkedIn", "licdn.com": "LinkedIn",
    "discord.com": "Discord", "discordapp.com": "Discord",
    "zoom.us": "Zoom", "anydesk.com": "AnyDesk",
    "netflix.net": "Netflix", "disneyplus.com": "Disney+",
    "icloud.com": "Apple/iCloud", "apple.com": "Apple",
    "mzstatic.com": "Apple", "apple-dns.net": "Apple",
    "google.com": "Google", "googleapis.com": "Google APIs",
    "gstatic.com": "Google", "googlesyndication.com": "Google Ads",
    "doubleclick.net": "Google Ads", "google-analytics.com": "Google Analytics",
    "microsoft.com": "Microsoft", "windows.com": "Microsoft",
    "live.com": "Microsoft", "office.com": "Microsoft 365",
    "windowsupdate.com": "Windows Update", "msftncsi.com": "Windows",
    "amazonaws.com": "AWS-hosted", "amazon.com": "Amazon",
    "cloudflare.com": "Cloudflare", "akamai.net": "Akamai CDN",
    "anthropic.com": "Claude", "claude.ai": "Claude",
    "openstreetmap.org": "OpenStreetMap", "gmail.com": "Gmail",
}

# Hostnames a native app asks for. A browser fetches www.<site> or the bare
# domain; an app calls its API, push, or telemetry endpoints directly.
APP_PREFIXES = ("graph.", "api.", "a-api.", "i.", "b.i.", "edge-mqtt.",
                "mqtt.", "gateway.", "push.", "sync.", "telemetry.",
                "config.", "settings.", "g.", "mmg.", "media.", "client.",
                "clients", "app.", "mobile.", "reg.", "collector.", "logs.",
                "events.", "self.events.", "imap.", "smtp.", "pop.", "cdn.",
                "chat.cdn.", "assets-proxy.", "data.", "sdk.", "device.",
                "gsp.", "init.", "keepalive.", "connectivity.", "ssl.",
                "static.", "assets.", "upload.", "content.")
WEB_PREFIXES = ("www.", "m.", "web.", "login.", "accounts.", "search.",
                "signin.", "auth.")


def classify_domain(fqdn):
    """(service, kind) for one hostname. kind is 'app', 'web' or '?'.

    A HEURISTIC, and named as one in the report. DNS carries no field saying
    what asked. The inference is behavioural: browsers request the hostname a
    person would type, apps request endpoints a person never sees. It reads a
    push endpoint as app traffic and www as a browser, which is usually right
    and sometimes not -- a web app calling its own API looks like an app.
    """
    fqdn = fqdn.rstrip(".").lower()
    base = dns_group(fqdn)
    service = SERVICE_DOMAINS.get(base, base)

    prefix = fqdn[:-len(base)] if fqdn.endswith(base) and fqdn != base else ""
    if prefix.startswith(WEB_PREFIXES) or not prefix:
        kind = "web"
    elif prefix.startswith(APP_PREFIXES):
        kind = "app"
    elif base in ("googleapis.com", "cdninstagram.com", "fbcdn.net",
                  "googlevideo.com", "ttvnw.net", "scdn.co", "twimg.com",
                  "sc-cdn.net", "nflxvideo.net", "amazonaws.com"):
        kind = "app"          # CDN and API estates: never typed by a person
    elif "-pa." in fqdn or prefix.count(".") >= 2:
        # Google's private-API pattern (taskassist-pa.clients6.google.com) and
        # any deeply-nested host. Nobody types three levels of sub-domain.
        kind = "app"
    else:
        kind = "app"          # a sub-domain that is not a browser entry point
    return service, kind


def dns_report_body(ip=None, top=25, names=None, show_background=False):
    """Per device: what kind of thing, which service, app or browser, and the
    hostnames behind each.

    Three levels because one alone misleads. The CATEGORY says what sort of
    activity it was. The SERVICE names it, resolved from the full hostname --
    Meta shares infrastructure, so Instagram's app resolves facebook.com
    endpoints and a report keyed on the registrable domain reports the wrong
    app. The HOSTNAMES are shown so the classification can be checked rather
    than trusted.
    """
    names = names or {}
    lines = ["streamwatch - dns lookup report", "",
             "Generated : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "Observed  : %d lookup(s) since streamwatch started"
             % DNS_STATE["lines"], ""]
    if not DNS_STATE["on"]:
        lines.append("WARNING: the dns watcher is not running.")

    targets = [ip] if ip else sorted(DNS_LOG)
    if not targets or (ip and ip not in DNS_LOG):
        lines += ["No lookups recorded for %s." % (ip or "any device"),
                  "Either it has not resolved anything yet, or it uses",
                  "encrypted DNS and does not ask this router at all."]
        return "\n".join(lines) + "\n"

    for tgt in targets:
        per = DNS_LOG.get(tgt, {})
        if not per:
            continue
        if tgt.startswith("127.") or tgt == "::1":
            label = "%s -- THIS ROUTER, not a device" % tgt
        else:
            label = ("%s (%s)" % (tgt, names[tgt]) if names.get(tgt) else tgt)

        # category -> service -> {count, last, kinds, hosts}
        tree, total = {}, 0
        for domain, rec in per.items():
            count, last = rec[0], rec[1]
            total += count
            cat = dns_categorise(domain)
            service, kind = classify_domain(domain)
            e = tree.setdefault(cat, {}).setdefault(
                service, {"count": 0, "last": 0, "kinds": set(), "hosts": {}})
            e["count"] += count
            e["last"] = max(e["last"], last)
            e["kinds"].add(kind)
            e["hosts"][domain] = e["hosts"].get(domain, 0) + count

        lines.append("=" * 68)
        lines.append(label)
        lines.append("  %d hostname(s), %d lookup(s)" % (len(per), total))
        if tgt.startswith("127."):
            lines.append("  The router's own lookups -- streamwatch reaching "
                         "Gmail, ntp, updates.")
            lines.append("  Not browsing by anyone.")
        lines.append("")

        fore = {c: v for c, v in tree.items() if c not in DNS_BACKGROUND}
        back = {c: v for c, v in tree.items() if c in DNS_BACKGROUND}
        if not fore:
            lines.append("  Nothing but background traffic -- no service this "
                         "device's user chose.")

        for cat in sorted(fore, key=lambda c: -sum(e["count"]
                                                   for e in fore[c].values())):
            lines.append("  %s" % cat.upper())
            for service, e in sorted(fore[cat].items(),
                                     key=lambda kv: -kv[1]["count"])[:top]:
                kinds = e["kinds"]
                kind = ("app" if kinds == {"app"} else
                        "browser" if kinds == {"web"} else
                        "app+browser" if {"app", "web"} <= kinds else "?")
                mins = (time.time() - e["last"]) / 60.0
                lines.append("    %-22s %-12s %4d   last %s"
                             % (service[:22], kind, e["count"],
                                "%.0f min ago" % mins if mins >= 1
                                else "just now"))
                shown = sorted(e["hosts"].items(), key=lambda kv: -kv[1])
                for host, n in shown[:4]:
                    lines.append("        %-50s %4d" % (host[:50], n))
                if len(shown) > 4:
                    lines.append("        ... and %d more hostname(s), %d "
                                 "lookup(s)"
                                 % (len(shown) - 4,
                                    sum(n for _, n in shown[4:])))
            lines.append("")

        if back:
            bcount = sum(e["count"] for v in back.values() for e in v.values())
            bhosts = sum(len(e["hosts"]) for v in back.values()
                         for e in v.values())
            lines.append("  BACKGROUND: %d lookup(s), %d hostname(s) -- %s"
                         % (bcount, bhosts, ", ".join(sorted(back))))
            lines.append("  CDNs, ads and OS telemetry. Not chosen by anyone.")
            lines.append("")

    lines += [
        "=" * 68,
        "READING THIS",
        "  app vs browser is a HEURISTIC, not a fact. DNS carries no field",
        "  saying what asked. A browser requests the hostname a person would",
        "  type (www.instagram.com); an app calls endpoints nobody types",
        "  (i.instagram.com, edge-mqtt.facebook.com). That is the whole",
        "  inference, and a web app calling its own API can look like an app.",
        "",
        "  Service names come from the FULL hostname, listed underneath so you",
        "  can check the call. This matters most for Meta: Instagram's app",
        "  resolves facebook.com endpoints for push and API traffic, so",
        "  facebook.com appearing does NOT mean Facebook was opened.",
        "",
        "  Domains looked up, not pages visited. A cached lookup makes no",
        "  query, one page makes dozens across CDNs and analytics, and DNS",
        "  never carries the path -- which post, video or page was viewed is",
        "  not visible here and cannot be. A device on encrypted DNS (DoH/DoT)",
        "  or iCloud Private Relay resolves elsewhere and shows little or",
        "  nothing at all."]
    return "\n".join(lines) + "\n"




def fetch_commands(user, password, imap_server, allow_from, scan=20, seen=None,
                   window=900):
    """Scan recent mail for close(ip) / open(ip), wherever they appear.

    Not limited to the newest message: an alert sent after a command would
    otherwise bury it forever. Every message is examined once -- Message-ID is
    recorded in `seen` so a command never re-fires on later polls.

    `window` (seconds) bounds how old a command may be. This replaces the old
    "ignore everything present at startup" rule, which silently dropped a
    command emailed moments before the tool was launched.

    Email sender addresses are trivially forged. The allowlist is a gate, not
    proof of identity, which is why block_ip/disconnect_device carry their own
    refusals independently of this check.
    """
    try:
        import email
        import imaplib
        from email.utils import parsedate_to_datetime
    except ImportError:
        return [], [], ["[commands: imaplib not installed]"], {}

    closes, opens, notes = [], [], []
    limits, unlimits = [], []
    throttles, unthrottles = [], []
    want_devices = [False]
    want_zones = [False]
    want_rules = [False]
    browsing = []
    locating = []
    forbids = []                  # [(value, unit), ...]  unit in {"m","dbm"}
    unforbid = [False]
    ports = []                    # [(verb, target, lo, hi, proto), ...]
    calibrations = []
    examined = 0
    box = None
    try:
        box = imaplib.IMAP4_SSL(imap_server, 993)
        box.login(user, password)
        box.select("INBOX", readonly=True)
        typ, data = box.search(None, "ALL")
        ids = data[0].split()

        for num in reversed(ids[-scan:]):
            typ, raw = box.fetch(num, "(RFC822)")
            if not raw or not raw[0]:
                continue
            msg = email.message_from_bytes(raw[0][1])
            mid = msg.get("Message-ID", "") or str(num)
            if seen is not None and mid in seen:
                continue
            examined += 1
            if seen is not None:
                seen.add(mid)

            subject = msg.get("Subject", "")
            # Never take orders from our own mail -- the inbox-line email
            # quotes command text straight back into this inbox.
            if subject.startswith("[streamwatch]"):
                continue

            sender = msg.get("From", "")
            body = "%s %s" % (subject, _first_text_line(msg, limit=2000))
            c = parse_close_targets(body)
            o = parse_open_targets(body)
            lim = parse_limit_targets(body)
            unlim = _parse_targets(UNLIMIT_CMD, body)
            thr = parse_throttle_targets(body)
            unthr = _parse_targets(UNTHROTTLE_CMD, body)
            devq = bool(DEVICES_CMD.search(body))
            brw = BROWSING_CMD.findall(body)
            loc = LOCATE_CMD.findall(body)
            zoneq = bool(ZONES_CMD.search(body))
            fbd = FORBID_CMD.findall(body)
            unfbd = bool(UNFORBID_CMD.search(body))
            prt = parse_port_rules(body)
            rulesq = bool(RULES_CMD.search(body))
            cal = CALIBRATE_CMD.findall(body)
            if not (c or o or lim or unlim or thr or unthr or devq or brw
                    or loc or zoneq or fbd or unfbd or prt or rulesq or cal):
                continue
            found = []
            for label, hits in (("close", c), ("open", o), ("limit", lim),
                                ("unlimit", unlim), ("throttle", thr),
                                ("unthrottle", unthr), ("browsing", brw),
                                ("locate", loc), ("forbid", fbd), ("port", prt),
                                ("calibrate", cal)):
                if hits:
                    found.append("%s %s" % (label, hits))
            for label, flag in (("devices()", devq), ("zones()", zoneq),
                                ("unforbid()", unfbd), ("rules()", rulesq)):
                if flag:
                    found.append(label)
            cmd_text = "; ".join(found)
            if not any(a.lower() in sender.lower() for a in allow_from):
                email_log("refused", sender, user, subject,
                          "sender not on the allowed list: " + cmd_text, mid)
                notes.append("[command REFUSED] command from %s is not on the "
                             "allowed-sender list" % sender)
                continue

            try:
                age = time.time() - parsedate_to_datetime(
                    msg.get("Date", "")).timestamp()
            except Exception:
                age = 0
            if age > window:
                email_log("stale", sender, user, subject,
                          "%d min old, not acted on: %s" % (age // 60, cmd_text), mid)
                notes.append("[commands: ignoring a command %d min old (limit %d)]"
                             % (age // 60, window // 60))
                continue

            email_log("received", sender, user, subject, cmd_text, mid)
            closes.extend(x for x in c if x not in closes)
            opens.extend(x for x in o if x not in opens)
            limits.extend(x for x in lim if x not in limits)
            unlimits.extend(x for x in unlim if x not in unlimits)
            throttles.extend(x for x in thr if x not in throttles)
            unthrottles.extend(x for x in unthr if x not in unthrottles)
            if devq:
                want_devices[0] = True
            if zoneq:
                want_zones[0] = True
            if rulesq:
                want_rules[0] = True
            if unfbd:
                unforbid[0] = True
            for item in prt:
                if item not in ports:
                    ports.append(item)
            for target in brw:
                if target not in browsing:
                    browsing.append(target)
            for target in loc:
                if target not in locating:
                    locating.append(target)
            for val, unit in fbd:
                if (val, unit) not in forbids:
                    forbids.append((val, unit))
            for cip, cm in cal:
                if (cip, cm) not in calibrations:
                    calibrations.append((cip, cm))

        if examined:
            notes.append("[commands: examined %d new message(s), found %d close, "
                         "%d open, %d limit, %d unlimit, %d throttle, "
                         "%d unthrottle]"
                         % (examined, len(closes), len(opens), len(limits),
                            len(unlimits), len(throttles), len(unthrottles)))
        return closes, opens, notes, {"limits": limits, "unlimits": unlimits,
                                      "throttles": throttles,
                                      "unthrottles": unthrottles,
                                      "devices": want_devices[0],
                                      "browsing": browsing,
                                      "locating": locating,
                                      "zones": want_zones[0],
                                      "forbids": forbids,
                                      "unforbid": unforbid[0],
                                      "ports": ports,
                                      "rules": want_rules[0],
                                      "calibrations": calibrations}
    except Exception as e:
        return [], [], ["[commands: could not read inbox: %s]" % e], {}
    finally:
        if box is not None:
            try:
                box.close()
                box.logout()
            except Exception:
                pass


def fetch_close_commands(user, password, imap_server, allow_from, scan=20,
                         seen=None):
    """Backwards-compatible wrapper returning closes only."""
    closes, _opens, notes = fetch_commands(user, password, imap_server,
                                           allow_from, scan, seen)[:3]
    return closes, notes


def command_watcher(cfg, nets, interval, dry_run, allow_from, mode="full",
                    blocked=None):
    """Background thread: poll for close(ip) commands and act on them.

    Secondary to the first-line reader in send_email_alert -- this fires even
    when no alert is due. `blocked` is shared with that path so one device is
    never acted on twice.
    """
    seen = set()
    if blocked is None:
        blocked = {}

    print("  [command watcher running: polling every %ds, commands honoured "
          "up to 15 min old]" % interval)

    while True:
        closes, opens, notes, extra = fetch_commands(
            cfg["user"], cfg["password"], cfg["imap_server"], allow_from, seen=seen)
        for note in notes:
            print("  " + note)
        for ip in closes:
            # Under --group-lists, close(ip) also deny-lists the device; with
            # the plain gate it just revokes the pass; with no gate it is an
            # unchanged disconnect_device/block_ip.
            if GROUP["on"]:
                print("  " + group_deny(ip, nets, dry_run=dry_run, blocked=blocked))
            else:
                print("  " + gated_close(ip, nets, dry_run=dry_run,
                                         blocked=blocked, mode=mode))
        for ip in opens:
            if GROUP["on"]:
                print("  " + group_allow(ip, nets, dry_run=dry_run, blocked=blocked))
            else:
                print("  " + gated_open(ip, nets, dry_run=dry_run,
                                        blocked=blocked))
        for ip, nbytes, period in extra.get("limits", []):
            print("  " + quota_set(ip, nbytes, period))
        for ip in extra.get("unlimits", []):
            print("  " + quota_clear(ip))
        for ip, down, up in extra.get("throttles", []):
            print("  " + throttle_set(ip, down, up, gate_ifaces(), wan_iface()))
        for ip in extra.get("unthrottles", []):
            print("  " + throttle_clear(ip))
        for cip, cm in extra.get("calibrations", []):
            try:
                metres = float(cm) if cm else 1.0
            except ValueError:
                metres = 1.0
            print("  " + rssi_calibrate(cip, metres))
        for target in extra.get("browsing", []):
            who = target or "all devices"
            print("  [browsing: report for %s sent]" % who)
            try:
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"],
                                 "[streamwatch] dns lookups - %s" % who,
                                 dns_report_body(target or None,
                                                 names=hostname_map()))
            except Exception as e:
                print("  [browsing: email FAILED: %s]" % e)
        for val, unit in extra.get("forbids", []):
            print("  " + forbid_runtime(val, unit, nets))
        if extra.get("unforbid"):
            print("  " + unforbid_runtime())
        for target in extra.get("locating", []):
            who = target or "all located devices"
            print("  [locate: report for %s sent]" % who)
            try:
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"],
                                 "[streamwatch] location - %s" % who,
                                 locate_report_body(target or None, nets,
                                                    names=hostname_map()))
            except Exception as e:
                print("  [locate: email FAILED: %s]" % e)
        if extra.get("zones"):
            print("  [zones: forbidden-area status sent]")
            try:
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"],
                                 "[streamwatch] forbidden-area status",
                                 "streamwatch - forbidden area\n\n"
                                 + "\n".join(zone_status_lines()) + "\n")
            except Exception as e:
                print("  [zones: email FAILED: %s]" % e)
        for verb, target, lo, hi, proto in extra.get("ports", []):
            print("  " + port_rule_cmd(verb, target, lo, hi, proto, nets))
        if extra.get("rules"):
            print("  [rules: %d port rule(s), report sent]" % len(PORT_RULES))
            try:
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"],
                                 "[streamwatch] port rules - %d" % len(PORT_RULES),
                                 port_rules_body(names=hostname_map()))
            except Exception as e:
                print("  [rules: email FAILED: %s]" % e)
        # close(), forbid() and the gate insert at the head of FORWARD; an
        # allow must stay in front of every drop, so put the hook back.
        if PORT_RULES and ports_rehook():
            print("  [ports: chain moved back to the head of FORWARD]")
        if extra.get("devices"):
            devices_update(nets)
            body = devices_report_body(nets)
            print("  [devices: %d known, report sent]" % len(DEVICES))
            try:
                send_email_alert(cfg["server"], cfg["port"], cfg["user"],
                                 cfg["password"], cfg["to"],
                                 "[streamwatch] device registry - %d known"
                                 % len(DEVICES), body)
            except Exception as e:
                print("  [devices: email FAILED: %s]" % e)
        time.sleep(interval)


def first_line_segment(blob):
    """The 'First line: ...' part of what latest_email_first_line() returns.

    The blob also carries From: and Subject:, and the subject of a streamwatch
    alert contains its own size ('crossed 500.0 KB'). Searching the whole blob
    finds that instead of the body's number.
    """
    marker = "First line:"
    idx = blob.find(marker)
    return blob[idx + len(marker):].strip() if idx != -1 else blob


ENTITIES = {"&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
            "&#39;": "'", "&apos;": "'", "&mdash;": "-", "&ndash;": "-",
            "&rsquo;": "'", "&lsquo;": "'", "&ldquo;": '"', "&rdquo;": '"',
            "&zwnj;": "", "&#8203;": ""}


def _html_to_text(raw):
    """Strip markup to readable text. Hand-rolled: no html.parser dependency."""
    low = raw.lower()
    # Drop whole blocks whose contents are code, not prose.
    for tag in ("script", "style", "head"):
        while True:
            start = low.find("<" + tag)
            if start == -1:
                break
            end = low.find("</" + tag, start)
            end = len(raw) if end == -1 else low.find(">", end) + 1
            raw = raw[:start] + " " + raw[end:]
            low = raw.lower()

    out, depth = [], 0
    for ch in raw:
        if ch == "<":
            depth += 1
        elif ch == ">":
            if depth:
                depth -= 1
            out.append(" ")
        elif depth == 0:
            out.append(ch)
    text = "".join(out)

    for ent, rep in ENTITIES.items():
        text = text.replace(ent, rep)
    try:
        import html
        text = html.unescape(text)
    except ImportError:
        pass
    return text


def _part_text(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, "replace")
    except LookupError:
        return payload.decode("utf-8", "replace")


def _first_text_line(msg, limit=300):
    """First readable line of a message body. Prefers text/plain, falls back
    to text/html with the markup stripped -- many senders ship HTML only."""
    plain, html_part = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not plain:
                plain = _part_text(part)
            elif ctype == "text/html" and not html_part:
                html_part = _part_text(part)
    else:
        text = _part_text(msg)
        if msg.get_content_type() == "text/html":
            html_part = text
        else:
            plain = text

    body = plain.strip() or _html_to_text(html_part)

    for line in body.splitlines():
        line = " ".join(line.split())        # collapse runs of whitespace
        if len(line) > 1:                    # skip blanks and stray characters
            return line[:limit] + ("..." if len(line) > limit else "")
    return "(no readable text)"


def latest_email_first_line(user, password, imap_server="imap.gmail.com",
                            skip_from=None, scan=20, wait=0, poll=3):
    """Subject + first body line of the newest INBOX message.

    Opened read-only, so nothing is marked as read. `wait` gives Gmail time to
    deliver a message we just sent to ourselves -- the inbox is polled until a
    new message appears or the budget runs out. `skip_from` is optional: pass
    the sending address to ignore our own mail, or leave it None to read
    whatever is genuinely newest, including our own alert.
    """
    try:
        import email
        import imaplib
    except ImportError:
        return "[imaplib/email not installed on this router]"

    deadline = time.time() + max(0, wait)
    baseline = None

    while True:
        box = None
        try:
            box = imaplib.IMAP4_SSL(imap_server, 993)
            box.login(user, password)
            box.select("INBOX", readonly=True)
            typ, data = box.search(None, "ALL")
            ids = data[0].split()

            if not ids:
                result = "[inbox empty]"
            else:
                if baseline is None:
                    baseline = len(ids)
                # Still waiting for the message we just sent to show up?
                if wait and len(ids) <= baseline and time.time() < deadline:
                    raise _NotYet()

                result = "[nothing readable in the last %d messages]" % scan
                for num in reversed(ids[-scan:]):
                    typ, raw = box.fetch(num, "(RFC822)")
                    if not raw or not raw[0]:
                        continue
                    msg = email.message_from_bytes(raw[0][1])
                    sender = msg.get("From", "")
                    if skip_from and skip_from.lower() in sender.lower():
                        continue
                    result = "From: %s\nSubject: %s\nFirst line: %s" % (
                        sender, msg.get("Subject", "(no subject)"),
                        _first_text_line(msg))
                    break
            return result

        except _NotYet:
            pass
        except Exception as e:
            return "[could not read inbox: %s]" % e
        finally:
            if box is not None:
                try:
                    box.close()
                    box.logout()
                except Exception:
                    pass
        time.sleep(poll)


class _NotYet(Exception):
    """Internal: the awaited message has not been delivered yet."""


# Every email StreamWatch sends, and every command email it receives, acts on
# or refuses, is appended to EMAIL_LOG as one JSON line, so the Recorder on the
# companion host can put it in the AI CSV with its date and time. Content is
# kept to the subject plus a first line / the commands found (PRV-4: no
# message content); ordinary non-command mail in the inbox is not logged.
EMAIL_LOG = "/root/.streamwatch_emails.log"
EMAIL_LOG_KEEP = 2000
_EMAIL_LOG_LOCK = threading.Lock()


def email_log(direction, frm, to, subject, detail="", ident=""):
    """direction: sent | failed | received | refused | stale."""
    rec = {"t": round(time.time(), 3), "dir": direction, "from": frm or "",
           "to": to or "", "subject": (subject or "")[:200],
           "detail": (detail or "")[:300], "id": ident or ""}
    try:
        import json
        with _EMAIL_LOG_LOCK:
            with open(EMAIL_LOG, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            if os.path.getsize(EMAIL_LOG) > EMAIL_LOG_KEEP * 600:
                with open(EMAIL_LOG) as f:
                    keep = f.readlines()[-EMAIL_LOG_KEEP:]
                with open(EMAIL_LOG + ".tmp", "w") as f:
                    f.writelines(keep)
                os.replace(EMAIL_LOG + ".tmp", EMAIL_LOG)
    except OSError:
        pass


def _first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def send_email_alert(smtp_server, smtp_port, user, password, to_addr, subject, body,
                     include_latest=False, imap_server="imap.gmail.com",
                     latest_wait=20, state=None, cmd_cfg=None, retry_waits=()):
    """Send the alert in a background thread so metering never blocks on SMTP.

    Lifted from portwatch.py. Two deviations: smtplib/email are imported inside
    the thread so a python3-light install still runs the metering half; and
    when include_latest is set a second email follows, carrying the first line
    of whatever is newest in the inbox by then -- normally the alert itself.

    retry_waits: seconds to wait before each further attempt if sending fails
    (empty = one attempt). Every failed attempt is still logged.
    """
    def _post(subj, text, attachment=None, fail_note=""):
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subj
        msg["From"] = user
        msg["To"] = to_addr
        msg.set_content(text)
        if attachment:
            filename, payload = attachment
            msg.add_attachment(payload.encode("utf-8"), maintype="text",
                               subtype="plain", filename=filename)
        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
                s.starttls()
                s.login(user, password)
                s.send_message(msg)
        except Exception as e:
            email_log("failed", user, to_addr, subj,
                      "%s%s | %s" % (e, fail_note, _first_line(text)))
            raise
        email_log("sent", user, to_addr, subj, _first_line(text))

    def _send():
        try:
            import smtplib                      # noqa: F401  (availability check)
            from email.message import EmailMessage  # noqa: F401
        except ImportError:
            print("  [email alert FAILED: install python3-email and python3-openssl]")
            return

        waits = list(retry_waits)
        while True:
            note = "; retrying in %d s" % waits[0] if waits else ""
            try:
                _post(subject, body, fail_note=note)
                print("  [email alert sent to %s]" % to_addr)
                break
            except Exception as e:
                print("  [email alert FAILED: %s%s]" % (e, note))
                if not waits:
                    return
                time.sleep(waits.pop(0))

        if not include_latest:
            return

        # The alert has to arrive before it can be read back, so the inbox is
        # polled until a new message lands or the wait budget runs out.
        line = latest_email_first_line(user, password, imap_server,
                                       skip_from=None, wait=latest_wait)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fname = "latest_inbox_line_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")
        attachment_text = ("streamwatch - most recent inbox message\n"
                           "Mailbox : %s\nRead at : %s\n\n%s\n" % (user, stamp, line))
        try:
            _post("[streamwatch] most recent inbox message",
                  "Read from %s at %s.\n\n%s\n\n(also attached as %s)\n"
                  % (user, stamp, line, fname),
                  attachment=(fname, attachment_text))
            print("  [inbox-line email + %s sent to %s]" % (fname, to_addr))
        except Exception as e:
            print("  [inbox-line email FAILED: %s]" % e)

        # --- close(x.x.x.x) in that first line ---
        # This is the reader that has been verified working end to end, so the
        # command is taken from here rather than a second, separate IMAP scan.
        if cmd_cfg is not None:
            segment = first_line_segment(line)
            if "Subject: [streamwatch]" in line:
                print("  [commands: newest message is streamwatch's own mail, "
                      "ignoring]")
            else:
                closes = parse_close_targets(segment)
                opens = parse_open_targets(segment)
                for ip, nbytes, period in parse_limit_targets(segment):
                    print("  " + quota_set(ip, nbytes, period))
                for ip in _parse_targets(UNLIMIT_CMD, segment):
                    print("  " + quota_clear(ip))
                for ip, down, up in parse_throttle_targets(segment):
                    print("  " + throttle_set(ip, down, up, gate_ifaces(),
                                              wan_iface()))
                for ip in _parse_targets(UNTHROTTLE_CMD, segment):
                    print("  " + throttle_clear(ip))
                if not closes and not opens:
                    print("  [commands: no close(ip) or open(ip) in that first line]")
                for ip in closes:
                    if GROUP["on"]:
                        print("  " + group_deny(ip, cmd_cfg["nets"],
                                                dry_run=cmd_cfg["dry_run"],
                                                blocked=cmd_cfg["blocked"]))
                    else:
                        print("  " + gated_close(ip, cmd_cfg["nets"],
                                                 dry_run=cmd_cfg["dry_run"],
                                                 blocked=cmd_cfg["blocked"],
                                                 mode=cmd_cfg["mode"]))
                for ip in opens:
                    if GROUP["on"]:
                        print("  " + group_allow(ip, cmd_cfg["nets"],
                                                 dry_run=cmd_cfg["dry_run"],
                                                 blocked=cmd_cfg["blocked"]))
                    else:
                        print("  " + gated_open(ip, cmd_cfg["nets"],
                                                dry_run=cmd_cfg["dry_run"],
                                                blocked=cmd_cfg["blocked"]))

        # Optional: take the data size named in that line as the new limit.
        # The main loop applies it -- this thread only proposes.
        if state is not None:
            segment = first_line_segment(line)
            found = extract_threshold(segment)
            if not found:
                print("  [threshold-from-email: no number found, keeping current]")
            else:
                status, value, raw = found
                if status == "clamped":
                    print("  [threshold-from-email: %s out of range, clamped to %s]"
                          % (human(raw), human(value)))
                state["proposed"] = value

    threading.Thread(target=_send, daemon=True).start()


# --------------------------------------------------------------- wifi signal
#
# ADDED. Per-device radio signal, for the devices that have one.
#
# A wired device has no RSSI and never will, so the absence of a number is
# information too -- these helpers return "" for it rather than a zero that
# would sort and average as though it were a real measurement.
#
# iwinfo assoclist is the source: it is already on the box (wireless_ifaces()
# above shells out to iwinfo), it is keyed by MAC, and mac_for_ip() already
# turns a LAN address into a MAC. `iw station dump` would work too but is not
# present on every GL.iNet build.

RSSI_CACHE = {"when": 0.0, "map": {}}
RSSI_TTL = 5.0

# AA:BB:CC:DD:EE:FF  -55 dBm / -95 dBm (SNR 40)  120 ms ago
ASSOC_LINE = re.compile(
    r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(-?\d+)\s*dBm"
    r"(?:\s*/\s*(-?\d+)\s*dBm)?(?:\s*\(SNR\s*(-?\d+)\))?", re.M)


def wifi_rssi_map(ttl=RSSI_TTL):
    """{mac: {"rssi":dBm, "noise":dBm, "snr":dB, "iface":name}} for associated
    stations. Cached briefly -- the table print and the alert path both ask
    for this within the same second and one iwinfo call per radio is enough."""
    now = time.time()
    if RSSI_CACHE["map"] and (now - RSSI_CACHE["when"]) < ttl:
        return RSSI_CACHE["map"]
    out = {}
    for iface in wireless_ifaces():
        text = run(["iwinfo", iface, "assoclist"], timeout=8)
        for m in ASSOC_LINE.finditer(text):
            mac, rssi, noise, snr = m.groups()
            out[mac.lower()] = {
                "rssi": int(rssi),
                "noise": int(noise) if noise else None,
                "snr": int(snr) if snr else None,
                "iface": iface}
    RSSI_CACHE.update({"when": now, "map": out})
    return out


def rssi_quality(dbm):
    """Words for a number most people do not read fluently. -67 dBm is the
    usual floor for reliable video and voice; below -75 things start dropping."""
    if dbm >= -50:
        return "excellent"
    if dbm >= -60:
        return "good"
    if dbm >= -67:
        return "ok"
    if dbm >= -75:
        return "weak"
    return "poor"


# Log-distance path loss: RSSI = A - 10*n*log10(d), so d = 10^((A-RSSI)/(10n)).
# A is the RSSI at exactly 1 m, n the path loss exponent.
RSSI_CAL = {"ref": -40.0, "n": 3.0, "per_mac": {}}
RSSI_UNCERTAINTY_DB = 6.0     # ordinary indoor swing from multipath alone


def rssi_to_distance(rssi, ref=None, n=None):
    """(low_m, mid_m, high_m). A RANGE, never a single figure.

    The model is sound in free space and rough indoors. A ±6 dB swing is
    ordinary from multipath and a hand near the antenna, and at n=3 that is a
    factor of 2.5 in distance -- so a point estimate would imply a precision
    the physics does not support. Walls are worse: one concrete wall costs
    around 15 dB, which the model reads as three times the distance rather
    than as an obstacle.
    """
    ref = RSSI_CAL["ref"] if ref is None else ref
    n = RSSI_CAL["n"] if n is None else n
    if not n:
        return None
    def d(r):
        return 10 ** ((ref - r) / (10.0 * n))
    try:
        return (d(rssi + RSSI_UNCERTAINTY_DB), d(rssi),
                d(rssi - RSSI_UNCERTAINTY_DB))
    except (OverflowError, ValueError):
        return None


def rssi_distance_text(rssi, mac=None):
    ref, n, cal = rssi_model_for(mac)
    got = rssi_to_distance(rssi, ref=ref, n=n)
    if not got:
        return "n/a"
    lo, mid, hi = got
    if hi < 1.5:
        return "under ~1.5 m (%s; too close to resolve - signal saturates)" % cal
    return ("roughly %.1f m, range %.1f-%.1f m (%s, n=%.1f)"
            % (mid, lo, hi, cal, n if n else RSSI_CAL["n"]))


CALIB_FILE = "/root/.streamwatch_calibration.json"


def _fit_path_loss(points):
    """Least-squares fit of RSSI = A - 10*n*log10(d) over measured points.

    Taking log10(d) as x makes the model a straight line: slope is -10n and
    intercept is A, the RSSI at 1 m. Two unknowns, so two points is the
    minimum and three or more is what makes the fit worth having -- with two
    the line passes exactly through both and R^2 says 1.0 regardless of how
    wrong the measurements were.

    Returns (A, n, r2, why_not).
    """
    import math
    if len(points) < 2:
        return None, None, None, "need at least two distances"
    xs = [math.log10(max(d, 0.05)) for d, _ in points]
    ys = [float(r) for _, r in points]
    N = len(xs)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = N * sxx - sx * sx
    if abs(denom) < 1e-9:
        return None, None, None, ("every sample is at the same distance -- "
                                  "the fit needs different ranges")
    slope = (N * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / N
    n = -slope / 10.0

    mean_y = sy / N
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-9 else 1.0
    return intercept, n, r2, None


def calib_load():
    try:
        import json
        with open(CALIB_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            RSSI_CAL["per_mac"].update(data)
    except Exception:
        pass


def calib_save():
    try:
        import json
        tmp = CALIB_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(RSSI_CAL["per_mac"], f)
        os.replace(tmp, CALIB_FILE)
    except Exception:
        pass


# --- the three-point walk from rssi_dist.py --------------------------------
#
# ADDED. rssi_dist.py writes a plain key=value text file, not this script's
# per-MAC JSON, so nothing here would have read it. Its A and n come from
# walking ONE device to three marked distances.
#
# WHY IT BECOMES THE DEFAULT FOR EVERY DEVICE
#     n, the path loss exponent, describes the BUILDING -- how much signal a
#     given wall and room geometry eat per decade of distance. That is shared
#     by everything on this LAN, and a measured n beats the generic 3.0 guess
#     for all of them. A, the reading at 1 m, is the weaker half: it also
#     carries the calibrated handset's antenna and transmit power, which
#     another device does not share. So the walk is the right FALLBACK and a
#     per-MAC calibration still beats it -- see rssi_model_for().

TXT_CALIB_FILE = "/root/rssi_calibration.txt"
TXT_CALIB = {"path": TXT_CALIB_FILE, "mtime": 0.0, "mac": "", "ref": None,
             "n": None, "points": [], "created": "", "error": ""}

RSSI_DEFAULTS = (-40.0, 3.0)
RSSI_OVERRIDE = {"ref": None, "n": None}     # --rssi-ref / --rssi-exponent


def calib_load_txt(path=None):
    """Parse rssi_dist.py's calibration file into TXT_CALIB. Returns True when
    a usable A and n were found. Does not touch RSSI_CAL -- rssi_apply_fallback
    decides that, so a command-line override is not silently clobbered when
    this is re-read mid-run.

    A file with n <= 0 is REJECTED rather than used. n <= 0 means the signal
    read stronger the further the phone walked, which inverts the model: every
    distance in the report would then grow as a device came closer. That is a
    bad calibration, not a usable one, and the walk has to be redone.
    """
    path = path or TXT_CALIB["path"]
    TXT_CALIB["path"] = path
    try:
        st = os.stat(path)
    except OSError:
        TXT_CALIB["error"] = "not found"
        return False
    if st.st_mtime <= TXT_CALIB["mtime"] and TXT_CALIB["ref"] is not None:
        return True                       # unchanged since the last read
    kv = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                kv[k.strip().lower()] = v.strip()
    except OSError as e:
        TXT_CALIB["error"] = str(e)
        return False
    try:
        ref, n = float(kv["a"]), float(kv["n"])
    except (KeyError, ValueError):
        TXT_CALIB["error"] = "no usable A= and n= lines"
        return False
    if n <= 0:
        TXT_CALIB["error"] = ("n=%s is not positive -- signal rose with "
                              "distance, redo the walk" % kv.get("n"))
        TXT_CALIB["mtime"] = st.st_mtime
        TXT_CALIB["ref"] = TXT_CALIB["n"] = None
        return False
    points = []
    for i in range(1, 13):
        d = kv.get("point%d_distance_m" % i)
        r = kv.get("point%d_rssi_dbm" % i)
        if d is None or r is None:
            continue
        try:
            points.append((float(d), float(r)))
        except ValueError:
            pass
    TXT_CALIB.update({"mtime": st.st_mtime, "mac": kv.get("mac", "").lower(),
                      "ref": ref, "n": n, "points": points,
                      "created": kv.get("created", ""), "error": ""})
    return True


def rssi_apply_fallback():
    """Set the global model. Precedence, highest first:

        1. --rssi-ref / --rssi-exponent   an explicit override for this run
        2. rssi_calibration.txt           the three-point walk
        3. -40 dBm, n=3.0                 a generic indoor guess

    Returns (ref_source, n_source) so the startup line can say which. A
    per-MAC record still beats all three for that one device.
    """
    ref, n = RSSI_DEFAULTS
    ref_src = n_src = "built-in default"
    if TXT_CALIB["ref"] is not None:
        ref, n = TXT_CALIB["ref"], TXT_CALIB["n"]
        ref_src = n_src = os.path.basename(TXT_CALIB["path"])
    if RSSI_OVERRIDE["ref"] is not None:
        ref, ref_src = RSSI_OVERRIDE["ref"], "--rssi-ref"
    if RSSI_OVERRIDE["n"] is not None:
        n, n_src = RSSI_OVERRIDE["n"], "--rssi-exponent"
    RSSI_CAL["ref"], RSSI_CAL["n"] = ref, n
    return ref_src, n_src


def apply_rssi_calibration(args, announce=False):
    """Called once per entry path in main(), before anything estimates a
    distance."""
    RSSI_OVERRIDE["ref"] = args.rssi_ref
    RSSI_OVERRIDE["n"] = args.rssi_exponent
    RSSI_PREFER_PER_DEVICE["on"] = bool(getattr(args, "prefer_per_device",
                                                False))
    calib_load_txt(getattr(args, "rssi_calib_file", None))
    ref_src, n_src = rssi_apply_fallback()
    if announce:
        print("Distance model: A=%.1f dBm at 1 m [%s], n=%.2f [%s]"
              % (RSSI_CAL["ref"], ref_src, RSSI_CAL["n"], n_src))
        for line in txt_calib_lines():
            print(line)
        if TXT_CALIB["ref"] is None and TXT_CALIB["error"]:
            print("  %s: %s -- distances fall back to the generic model"
                  % (TXT_CALIB["path"], TXT_CALIB["error"]))
    return ref_src, n_src


def txt_calib_lines():
    """Provenance of the fallback model, for the startup print and the footer
    of the emailed report. An estimate without its source invites more trust
    than it has earned."""
    if TXT_CALIB["ref"] is None:
        return []
    overridden = (RSSI_OVERRIDE["ref"] is not None
                  and RSSI_OVERRIDE["n"] is not None)
    out = ["  from %s%s%s" % (TXT_CALIB["path"],
                              ", " + TXT_CALIB["created"]
                              if TXT_CALIB["created"] else "",
                              "  (loaded, but overridden on the command line)"
                              if overridden else "")]
    if TXT_CALIB["points"]:
        out.append("    walked: %s"
                   % ", ".join("%.1f m -> %.0f dBm" % p
                               for p in TXT_CALIB["points"]))
    if TXT_CALIB["mac"]:
        out.append("    measured on %s -- other devices inherit n (the room) "
                   "but not that handset's antenna" % TXT_CALIB["mac"].upper())
    return out


# rssi_calibration.txt is THE REFERENCE. Everything that turns a signal into
# a distance -- the report column, the detail block, the movement emails --
# resolves its model here, and this is the one place that decides.
#
# ORDER, HIGHEST FIRST
#     1. --rssi-ref / --rssi-exponent   typed by hand for this run, so it wins
#     2. rssi_calibration.txt           THE REFERENCE: the measured walk
#     3. a per-device record            only when there is no reference file
#     4. -40 dBm / n=3.0                a generic guess, when nothing exists
#
# WHY THE FILE OUTRANKS A PER-DEVICE RECORD
#     It was measured on purpose, at marked distances, and it is the one model
#     that can be checked against a tape measure. A per-device record is built
#     from calibrate() calls that may have been taken casually, months apart,
#     or at a distance guessed rather than measured -- and when two models
#     disagree the report should follow the one that was actually walked.
#     --prefer-per-device restores the older order for anyone who would rather
#     trust the per-device fit, which IS the better model when it was measured
#     with the same care.

RSSI_PREFER_PER_DEVICE = {"on": False}


def _per_mac_model(mac):
    """(ref, n, how) from the JSON per-device record, or None."""
    rec = RSSI_CAL["per_mac"].get(mac) if mac else None
    if not (isinstance(rec, dict) and rec.get("ref") is not None
            and rec.get("n")):
        return None
    npts = len(rec.get("points", []))
    how = "this device, %d point%s" % (npts, "" if npts == 1 else "s")
    if rec.get("r2") is not None:
        how += ", R2=%.2f" % rec["r2"]
    return rec["ref"], rec["n"], how


def _txt_model():
    """(ref, n, how) from the reference file, or None."""
    if TXT_CALIB["ref"] is None:
        return None
    how = "reference file"
    if TXT_CALIB["points"]:
        how += ", %d points" % len(TXT_CALIB["points"])
    return TXT_CALIB["ref"], TXT_CALIB["n"], how


def rssi_model_for(mac):
    """(ref, n, how) for one device, and the words for how it was obtained."""
    calib_reload_if_changed()
    if RSSI_OVERRIDE["ref"] is not None or RSSI_OVERRIDE["n"] is not None:
        return RSSI_CAL["ref"], RSSI_CAL["n"], "command line"
    order = ((_per_mac_model(mac), _txt_model())
             if RSSI_PREFER_PER_DEVICE["on"]
             else (_txt_model(), _per_mac_model(mac)))
    for got in order:
        if got:
            return got
    return RSSI_DEFAULTS[0], RSSI_DEFAULTS[1], "uncalibrated"


def rssi_distance_short(rssi, mac=None):
    """One table cell. The range is dropped here and printed once per device
    in the detail block instead -- a column too narrow for both would have to
    drop the range, and the range is the honest half."""
    ref, n, _ = rssi_model_for(mac)
    got = rssi_to_distance(rssi, ref=ref, n=n)
    if not got:
        return "n/a"
    lo, mid, hi = got
    if hi < 1.5:
        return "<1.5 m"
    if mid >= 100:
        return ">100 m"
    return "%.1f m" % mid


def rssi_distance_range(rssi, mac=None):
    """(range_text, how). The pair the detail block prints."""
    ref, n, how = rssi_model_for(mac)
    got = rssi_to_distance(rssi, ref=ref, n=n)
    if not got:
        return "n/a", how
    lo, mid, hi = got
    return "%.1f-%.1f m" % (lo, hi), "%s, n=%.2f" % (how, n)


def _steady_rssi(mac, live):
    """Median of the recent samples rather than the instant reading. One
    sample can be several dB off from a hand moving; a calibration built on
    that poisons every later estimate."""
    hist = [v for _, v in RSSI_HISTORY.get(mac, [])[-8:]]
    if len(hist) >= 3:
        return _median(hist + [live])
    return live


def rssi_calibrate(ip, metres=1.0):
    """Record one (distance, signal) point and refit that device's model.

    Each call adds a measurement. One point can only set the 1 m reference and
    has to assume a path loss exponent; two or more solve for both, which is
    what makes the estimate the device's own rather than a generic guess.
    """
    mac = mac_for_ip(ip)
    if not mac:
        return "[calibrate] no MAC known for %s" % ip
    info = wifi_rssi_map(ttl=0).get(mac)
    if not info:
        return ("[calibrate] %s is not associated to a radio -- is it on "
                "Wi-Fi rather than mobile data?" % ip)

    rssi = _steady_rssi(mac, info["rssi"])
    rec = RSSI_CAL["per_mac"].setdefault(mac, {"points": []})
    if not isinstance(rec, dict):                 # upgrade an older entry
        rec = {"points": []}
        RSSI_CAL["per_mac"][mac] = rec
    rec["points"] = [p for p in rec.get("points", [])
                     if abs(p[0] - metres) > 0.01]     # replace a re-measure
    rec["points"].append([round(metres, 2), round(rssi, 1)])
    rec["points"].sort()

    pts = [(p[0], p[1]) for p in rec["points"]]
    out = ["[calibrate] %s (%s): %.1f dBm at %.1f m recorded (%d point(s))"
           % (ip, mac, rssi, metres, len(pts))]

    if len(pts) == 1:
        rec["ref"] = pts[0][1] + 10.0 * RSSI_CAL["n"] * math_log10(
            max(pts[0][0], 0.1))
        rec["n"] = RSSI_CAL["n"]
        out.append("      1 m reference %.1f dBm, exponent assumed %.1f. Send "
                   "two more at different distances to fit the exponent too."
                   % (rec["ref"], rec["n"]))
    else:
        A, n, r2, why = _fit_path_loss(pts)
        if why:
            out.append("      %s" % why)
        else:
            rec.update({"ref": A, "n": n, "r2": r2})
            out.append("      fit over %d point(s): 1 m reference %.1f dBm, "
                       "exponent n=%.2f, R2=%.3f" % (len(pts), A, n, r2))
            out.append("      %s" % _fit_verdict(n, r2, len(pts)))
            out.append("      points: %s"
                       % ", ".join("%.1fm/%.0fdBm" % (d, r) for d, r in pts))
    calib_save()
    return "\n".join(out)


def _fit_verdict(n, r2, npts):
    """Say plainly whether the fit is usable. A bad exponent or a scattered
    fit means the estimates built on it will be wrong, and silence about that
    is worse than a number."""
    if n < 1.5:
        return ("n=%.2f is below free space (2.0) -- physically implausible; "
                "check the distances were right" % n)
    if n > 6.0:
        return ("n=%.2f is very high -- likely measured through walls, so "
                "estimates along other paths will be too short" % n)
    if npts == 2:
        return ("two points fit any line exactly, so R2 means nothing here; "
                "add a third at a different distance")
    if r2 >= 0.95:
        return "good fit -- estimates should track reality in this environment"
    if r2 >= 0.80:
        return "workable fit; expect the usual factor-of-two spread"
    return ("poor fit (R2=%.2f) -- the readings do not follow one path loss "
            "curve, which usually means walls differ along the paths measured"
            % r2)


CALIB_MTIME = {"t": 0.0}


def calib_reload_if_changed():
    """Re-read the calibration file when it changes on disk.

    Calibration is done from the terminal while walking around, in a separate
    process from the running service. Without this the service would keep
    using whatever it loaded at startup and quietly ignore every measurement
    taken since -- so the emails would disagree with the numbers printed at
    the point of measurement.
    """
    # The three-point file is written by a separate program entirely, so it
    # gets the same treatment: re-read on change, never cached for the life
    # of the service.
    if calib_load_txt():
        rssi_apply_fallback()
    try:
        mt = os.stat(CALIB_FILE).st_mtime
    except OSError:
        return
    if mt > CALIB_MTIME["t"]:
        CALIB_MTIME["t"] = mt
        calib_load()


def calibrate_interactive(ip, metres, samples=8, gap=1.0):
    """Measure from the terminal: sample for several seconds, take the median.

    The email path reads the signal once, at whatever instant the poll lands.
    A single sample swings several dB from a hand or a turn of the body, and
    a calibration point is used forever after -- so this spends eight seconds
    to get a number worth keeping.
    """
    mac = mac_for_ip(ip)
    if not mac:
        return 1, ("No MAC known for %s. It needs a lease and an ARP entry -- "
                   "is it on Wi-Fi rather than mobile data?" % ip)
    print("Measuring %s (%s) at %.1f m -- hold still, %d samples over %ds"
          % (ip, mac, metres, samples, int(samples * gap)))
    got = []
    for i in range(samples):
        info = wifi_rssi_map(ttl=0).get(mac)
        if info:
            got.append(info["rssi"])
            print("  %2d/%d  %d dBm" % (i + 1, samples, info["rssi"]))
        else:
            print("  %2d/%d  not associated" % (i + 1, samples))
        if i < samples - 1:
            time.sleep(gap)
    if len(got) < 3:
        return 1, ("Only %d usable reading(s). The device must stay associated "
                   "for the whole measurement." % len(got))

    med = _median(got)
    spread = max(got) - min(got)
    calib_load()
    rec = RSSI_CAL["per_mac"].setdefault(mac, {"points": []})
    if not isinstance(rec, dict):
        rec = {"points": []}
        RSSI_CAL["per_mac"][mac] = rec
    rec["points"] = [p for p in rec.get("points", [])
                     if abs(p[0] - metres) > 0.01]
    rec["points"].append([round(metres, 2), round(med, 1)])
    rec["points"].sort()
    pts = [(p[0], p[1]) for p in rec["points"]]

    out = ["", "Recorded: %.1f dBm at %.1f m  (median of %d, spread %d dB)"
           % (med, metres, len(got), spread)]
    if spread > 8:
        out.append("  NOTE: %d dB spread while stationary is high. Something "
                   "moved, or the path is reflective -- consider re-measuring."
                   % spread)

    if len(pts) == 1:
        rec["ref"] = med + 10.0 * RSSI_CAL["n"] * math_log10(max(metres, 0.1))
        rec["n"] = RSSI_CAL["n"]
        out.append("  1 point so far: 1 m reference %.1f dBm, exponent assumed "
                   "%.1f." % (rec["ref"], rec["n"]))
        out.append("  Measure two more distances to fit the exponent as well.")
    else:
        A, n, r2, why = _fit_path_loss(pts)
        if why:
            out.append("  %s" % why)
        else:
            rec.update({"ref": A, "n": n, "r2": r2})
            out.append("  Fit over %d points: 1 m reference %.1f dBm, "
                       "n=%.2f, R2=%.3f" % (len(pts), A, n, r2))
            out.append("  %s" % _fit_verdict(n, r2, len(pts)))
            out.append("")
            out.append("  Model checked against the points it was built from:")
            for d, r in pts:
                est = rssi_to_distance(r, ref=A, n=n)
                out.append("    measured %5.1f m at %4.0f dBm -> model says "
                           "%.1f m" % (d, r, est[1] if est else 0))
    calib_save()
    out.append("")
    out.append("  Points: %s" % ", ".join("%.1fm/%.0fdBm" % (d, r)
                                          for d, r in pts))
    out.append("  Saved to %s -- the running service picks it up within a "
               "poll." % CALIB_FILE)
    return 0, "\n".join(out)


def calibrate_wizard(ip, want=3, samples=8, gap=1.0, settle=3):
    """Guided calibration: prompt, wait for the user to walk, then measure.

    Three separate command invocations made it easy to lose track of which
    points existed -- a stale point from an earlier session silently joined
    the fit and produced a nonsense exponent. This owns the whole session:
    it clears what was there, walks you through each position, and only fits
    once there are enough points for the fit to mean anything.
    """
    mac = mac_for_ip(ip)
    if not mac:
        return 1, ("No MAC known for %s. It needs a lease and an ARP entry -- "
                   "is it on Wi-Fi rather than mobile data?" % ip)
    if not wifi_rssi_map(ttl=0).get(mac):
        return 1, ("%s (%s) is not associated to any radio. Connect it to "
                   "Wi-Fi first." % (ip, mac))

    print("=" * 62)
    print("Distance calibration for %s (%s)" % (ip, mac))
    print("=" * 62)
    print("You will be asked for %d positions." % want)
    print("For each one: walk there, put the phone DOWN (not in your hand),")
    print("then type the distance in metres and press Enter.")
    print("")
    print("Spread the positions out. Close together gives the fit nothing to")
    print("work with, and under ~1.5 m the signal saturates and barely moves.")
    print("Make the last one as far as you can get -- ideally where the phone")
    print("reads -60 dBm or weaker.")
    print("")
    print("Type q at any prompt to stop.")
    print("")

    calib_load()
    existing = RSSI_CAL["per_mac"].get(mac)
    if isinstance(existing, dict) and existing.get("points"):
        print("Discarding %d point(s) from an earlier session: %s"
              % (len(existing["points"]),
                 ", ".join("%.1fm" % p[0] for p in existing["points"])))
        print("")
    RSSI_CAL["per_mac"][mac] = {"points": []}
    rec = RSSI_CAL["per_mac"][mac]

    n_done = 0
    while n_done < want:
        live = wifi_rssi_map(ttl=0).get(mac)
        now = "  (signal right now: %d dBm)" % live["rssi"] if live else \
              "  (not associated right now)"
        print("-" * 62)
        print("READY FOR POINT %d of %d%s" % (n_done + 1, want, now))
        try:
            raw = input("Walk there, put the phone down, then type the "
                        "distance in metres: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("")
            break
        if raw.lower() in ("q", "quit", "exit"):
            print("Stopped.")
            break
        try:
            metres = float(raw)
            if metres <= 0:
                raise ValueError
        except ValueError:
            print("  Not a number. Try again, e.g. 4 or 6.5")
            continue
        if any(abs(p[0] - metres) < 0.01 for p in rec["points"]):
            print("  Already measured %.1f m -- pick a different distance."
                  % metres)
            continue

        print("  Settling for %ds -- leave the phone alone..." % settle)
        time.sleep(settle)
        got = []
        for i in range(samples):
            info = wifi_rssi_map(ttl=0).get(mac)
            if info:
                got.append(info["rssi"])
                print("    %2d/%d  %d dBm" % (i + 1, samples, info["rssi"]))
            else:
                print("    %2d/%d  not associated" % (i + 1, samples))
            if i < samples - 1:
                time.sleep(gap)
        if len(got) < 3:
            print("  Only %d usable reading(s) -- the phone dropped off the "
                  "radio. Not recording this point." % len(got))
            continue

        med = _median(got)
        spread = max(got) - min(got)
        print("  -> %.1f dBm at %.1f m (median of %d, spread %d dB)"
              % (med, metres, len(got), spread))
        if spread > 8:
            print("     %d dB spread while stationary is high -- something "
                  "moved, or the path is reflective." % spread)
            try:
                again = input("     Redo this point? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                again = "n"
            if again.startswith("y"):
                continue
        rec["points"].append([round(metres, 2), round(med, 1)])
        rec["points"].sort()
        n_done += 1
        calib_save()

    pts = [(p[0], p[1]) for p in rec["points"]]
    out = ["", "=" * 62]
    if len(pts) < 3:
        out.append("Only %d point(s) recorded. A fit needs three: two points"
                   % len(pts))
        out.append("define any line exactly, so the result would look perfect")
        out.append("and mean nothing. Run this again to finish.")
        if pts:
            out.append("Kept: %s" % ", ".join("%.1fm/%.0fdBm" % (d, r)
                                              for d, r in pts))
        calib_save()
        return 0, "\n".join(out)

    A, n, r2, why = _fit_path_loss(pts)
    if why:
        out.append(why)
        return 1, "\n".join(out)
    rec.update({"ref": A, "n": n, "r2": r2})
    calib_save()
    out.append("CALIBRATED %s (%s)" % (ip, mac))
    out.append("  1 m reference : %.1f dBm" % A)
    out.append("  path exponent : n = %.2f" % n)
    out.append("  fit quality   : R2 = %.3f" % r2)
    out.append("  %s" % _fit_verdict(n, r2, len(pts)))
    out.append("")
    out.append("  Model checked against the points it was built from:")
    for d, r in pts:
        est = rssi_to_distance(r, ref=A, n=n)
        err = abs(est[1] - d) if est else 0
        out.append("    you said %5.1f m, %4.0f dBm -> model says %5.1f m "
                   "(off by %.1f m)" % (d, r, est[1] if est else 0, err))
    out.append("")
    out.append("  Saved to %s. The running service picks it up within a poll,"
               % CALIB_FILE)
    out.append("  so movement emails will use it without a restart.")
    return 0, "\n".join(out)


def rssi_calib_status(ip=None):
    if not RSSI_CAL["per_mac"]:
        return ["no devices calibrated"]
    out = []
    for mac, rec in sorted(RSSI_CAL["per_mac"].items()):
        if not isinstance(rec, dict):
            continue
        pts = rec.get("points", [])
        out.append("  %-17s ref %.1f dBm  n=%.2f  %d point(s)%s"
                   % (mac, rec.get("ref", 0), rec.get("n", 0), len(pts),
                      "  R2=%.3f" % rec["r2"] if rec.get("r2") is not None
                      else ""))
        if pts:
            out.append("        %s" % ", ".join("%.1fm/%.0fdBm" % (d, r)
                                                for d, r in pts))
    return out or ["no devices calibrated"]


def math_log10(x):
    """log10 without importing math at module scope -- the script is stdlib
    only and this is the one place that needs it."""
    import math
    return math.log10(x)


def rssi_for_ip(ip, verbose=False):
    """Signal for the device at this IP, or "" if it is not on the radio."""
    mac = mac_for_ip(ip)
    if not mac:
        return ""
    info = wifi_rssi_map().get(mac)
    if not info:
        return ""
    if not verbose:
        return "%d dBm" % info["rssi"]
    bits = ["%d dBm (%s)" % (info["rssi"], rssi_quality(info["rssi"]))]
    if info.get("snr") is not None:
        bits.append("SNR %d dB" % info["snr"])
    bits.append("on %s" % info["iface"])
    return "  ".join(bits)


# ------------------------------------------------------- movement from rssi
#
# ADDED. Rising signal means closer, falling means further, flat means still.
#
# THAT INFERENCE IS COARSE AND THE CODE TREATS IT AS SUCH
#     A device lying untouched on a table swings 5-10 dBm on its own. Signal
#     reflects off walls and cancels itself (multipath), a hand or a body
#     across the antenna costs several dB, rotating a phone changes its
#     antenna pattern, and the radio adapts its own transmit power. Comparing
#     one sample to the previous one would report a person pacing the room
#     every few seconds while they sat still.
#
#     So: never sample-to-sample. Each decision compares the MEDIAN of the
#     recent half of a window against the median of the older half. Medians
#     because one spike should not move the answer. A window because a trend
#     that survives a minute is a trend; one that lasts two samples is noise.
#     And a dead band -- movement is only declared past --rssi-delta dB, so a
#     device hovering at the boundary reports "idle" instead of flapping.
#
# WHAT IT STILL CANNOT DO
#     It cannot give distance: dBm to metres needs a calibrated path-loss
#     model per room, and a wall breaks it. It cannot tell walking away from
#     putting the phone in a pocket, or approaching from simply turning
#     around. Read it as "the link to this device is getting better/worse",
#     which is what is actually measured.

RSSI_HISTORY = {}          # mac -> [(timestamp, dBm), ...]
RSSI_STATE = {}            # mac -> {"state", "since", "last_report"}
RSSI_MAX_SAMPLES = 240


def ip_for_mac(mac):
    """Reverse of mac_for_ip: ARP first, then the lease table. The report is
    about a person, and an IP is the handle you actually recognise."""
    mac = (mac or "").lower()
    try:
        with open("/proc/net/arp", errors="replace") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[3].lower() == mac:
                    return c[0]
    except OSError:
        pass
    try:
        with open("/tmp/dhcp.leases", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[1].lower() == mac:
                    return p[2]
    except OSError:
        pass
    return None


def _median(vals):
    s = sorted(vals)
    n = len(s)
    if not n:
        return None
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def rssi_trend(samples, window, min_delta):
    """(state, delta_dB, n) from [(t, dBm), ...].

    Returns None when there is not enough history to judge -- a device seen
    twice has no trend, and guessing one is worse than saying nothing.
    """
    if not samples:
        return None
    now = samples[-1][0]
    recent_cut = now - window / 2.0
    old = [v for t, v in samples if t <= recent_cut and t >= now - window]
    new = [v for t, v in samples if t > recent_cut]
    if len(old) < 2 or len(new) < 2:
        return None

    delta = _median(new) - _median(old)
    if delta >= min_delta:
        return ("approaching", delta, len(old) + len(new))
    if delta <= -min_delta:
        return ("moving away", delta, len(old) + len(new))
    return ("idle", delta, len(old) + len(new))


def rssi_movement_body(ip, name, mac, info, state, prev, delta, n, window,
                       min_delta):
    quality = rssi_quality(info["rssi"])
    arrow = {"approaching": "signal rising - closer to the router",
             "moving away": "signal falling - further from the router",
             "idle": "signal steady - stationary"}[state]
    return (
        "streamwatch - device movement\n\n"
        "IP          : %s\n"
        "Hostname    : %s\n"
        "MAC         : %s\n"
        "Radio       : %s\n\n"
        "State       : %s  (was: %s)\n"
        "Reading     : %s\n"
        "Signal now  : %d dBm (%s)\n"
        "Distance    : %s\n"
        "Change      : %+.1f dB over the last %ds, from %d samples\n"
        "Time        : %s\n\n"
        "Distance is computed from signal strength with a path-loss model,\n"
        "not measured. A range is given because a 6 dB swing is ordinary\n"
        "indoors and translates to a factor of ~2.5 in distance; one wall can\n"
        "cost 15 dB, which the model reads as three times further away rather\n"
        "than as an obstacle. Send calibrate(%s) with the device one metre\n"
        "from the router to improve it.\n\n"
        "Signal strength is a coarse proxy for distance. A stationary device\n"
        "varies by several dB on its own, so this compares smoothed medians\n"
        "and only reports a change past %.0f dB. It cannot measure how far\n"
        "away the device is, and it cannot tell walking away from a phone\n"
        "going into a pocket.\n"
        % (ip or "unknown", name or "-", mac, info.get("iface", "?"),
           state, prev or "unknown", arrow, info["rssi"], quality,
           rssi_distance_text(info["rssi"], mac),
           delta, window, n,
           datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip or "x.x.x.x",
           min_delta))


def rssi_tracker(cfg, every, window, min_delta, cooldown, names_ttl=60):
    """Background thread: sample every associated station, and email when a
    device's movement state changes.

    Reports on TRANSITIONS only. A device that stays idle is not news, and
    mailing every sample would bury the one message that matters.
    """
    names, names_at = hostname_map(), time.time()

    while True:
        now = time.time()
        if now - names_at > names_ttl:
            names, names_at = hostname_map(), now

        seen = wifi_rssi_map(ttl=0)      # fresh read, this is the sampler
        for mac, info in seen.items():
            hist = RSSI_HISTORY.setdefault(mac, [])
            hist.append((now, info["rssi"]))
            if len(hist) > RSSI_MAX_SAMPLES:
                del hist[:-RSSI_MAX_SAMPLES]

            found = rssi_trend(hist, window, min_delta)
            if not found:
                continue
            state, delta, n = found

            st = RSSI_STATE.setdefault(
                mac, {"state": None, "since": now, "last_report": 0})
            if state == st["state"]:
                continue                  # no transition, nothing to say

            prev, st["state"], st["since"] = st["state"], state, now
            if prev is None:
                continue                  # first classification is a baseline
            if now - st["last_report"] < cooldown:
                continue
            st["last_report"] = now

            ip = ip_for_mac(mac)
            name = names.get(ip, "") if ip else ""
            label = "%s (%s)" % (ip, name) if name else (ip or mac)
            print("MOVE   %s  %s is %s  [%+.1f dB over %ds, now %d dBm]"
                  % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     label, state, delta, window, info["rssi"]))

            if not cfg:
                continue
            try:
                send_email_alert(
                    cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                    cfg["to"],
                    "[streamwatch] %s is %s (%+.1f dB, now %d dBm)"
                    % (label, state, delta, info["rssi"]),
                    rssi_movement_body(ip, name, mac, info, state, prev,
                                       delta, n, window, min_delta))
            except Exception as e:
                print("  [movement: email FAILED: %s]" % e)

        # A device that has left the radio keeps stale history; drop it so a
        # reconnection starts from a clean baseline rather than comparing
        # against wherever it was standing an hour ago.
        for mac in list(RSSI_HISTORY):
            if mac not in seen and RSSI_HISTORY[mac]:
                if now - RSSI_HISTORY[mac][-1][0] > window * 2:
                    RSSI_HISTORY.pop(mac, None)
                    RSSI_STATE.pop(mac, None)

        time.sleep(every)


# ----------------------------------------------- location + forbidden area
#
# ADDED. Two related capabilities, both built on the same per-device signal
# the movement tracker already samples:
#
#   1. CONTINUOUS LOCATION TRACE. Every few seconds, for each associated
#      device, record which mesh radio it is on and how far from that radio
#      the path-loss model places it. A rolling per-device history is kept and
#      can be mailed back with locate(x.x.x.x) or locate(). Optional --anchor
#      entries pin each radio to an (x, y) so the trace reads as a coarse
#      coordinate rather than only a distance.
#
#   2. FORBIDDEN AREA. A proximity zone around the mesh (or around one named
#      radio). A device confirmed INSIDE it has its forwarded traffic dropped
#      -- so no internet -- while it stays associated to the radio; a device
#      confirmed back OUTSIDE has that drop removed. Internet follows the
#      device: cut while it is in the area it is not cleared for, restored once
#      it roams back out.
#
# WHY FORWARD-ONLY AND NOT A FULL DISCONNECT
#     disconnect_device() deauthenticates and bans re-association. That cuts a
#     device off -- and also blinds us: a deauthed device leaves the assoclist,
#     so we could never see it leave the zone to restore it. The forbidden area
#     therefore drops FORWARD traffic by MAC (no internet, no cross-subnet)
#     and leaves the device on the radio, exactly so the release half of the
#     loop keeps working. close(x.x.x.x) is untouched and still cuts a device
#     off completely.
#
# WHY A STATE MACHINE AND NOT dist<=radius PER SAMPLE
#     RSSI swings several dB at rest, and the distance it implies is a wide
#     range, not a point. Toggling internet on every sample that crosses the
#     line would flap a device's connection at the boundary. Entry is therefore
#     confirmed over several consecutive inside samples, exit requires the
#     device to be clear of the radius by a margin for several samples, and a
#     cooldown bounds how often an email fires. This mirrors the movement
#     tracker's "a trend that survives is a trend" rule.
#
# WHAT IT CANNOT DO -- READ THIS BEFORE RELYING ON THE BOUNDARY
#     The zone edge is only as sharp as the distance estimate, which is coarse:
#     a 6 dB swing is a factor of ~2.5 in distance, and one wall costs ~15 dB,
#     so a device just behind a wall reads as far away even when it is close.
#     Where the boundary must be dependable, calibrate the device
#     (calibrate(x.x.x.x)) or set the zone by signal strength (--forbidden-rssi)
#     rather than metres. A MAC is also cloneable: this enforces a location
#     policy on cooperating devices, it is not a defence against someone
#     forging a MAC. And this is access control on a network you operate --
#     where people are subject to it, say so; it is not covert tracking.

ZONE_CHAIN = "SW_ZONE"

FORBIDDEN = {
    "on": False,
    "radius_m": None,        # inside when the distance estimate <= this
    "rssi_dbm": None,        # or (preferred) inside when RSSI >= this
    "iface": None,           # restrict the zone to one radio, or any
    "margin": 0.35,          # exit needs dist > radius*(1+margin) (metres mode)
    "rssi_margin_db": RSSI_UNCERTAINTY_DB,   # exit needs rssi <= thr-this (rssi mode)
    "enter_n": 2,            # consecutive inside samples that confirm entry
    "exit_n": 3,             # consecutive outside samples that confirm exit
    "cooldown": 60,          # min seconds between emails for one device
    "applies": "unauthorized",   # "unauthorized" exempts the authorised list; "all"
    "exempt": {},            # mac -> label, never enforced against
    "exempt_ips": set(),
    "dry_run": False,
    "ifaces": [],
}

ZONE_STATE = {}          # mac -> {inside, in_streak, out_streak, since,
                         #         last_report, blocked}
LOCATION_HISTORY = {}    # mac -> [(t, rssi, iface, dist_mid), ...]
LOCATION_MAX = 240
LOC_LAST_PRINT = {}      # mac -> (iface, dist_bucket, inside) last printed
ANCHORS = {}             # iface -> {"name", "x", "y"}

# One supervised sampler thread feeds both the location trace and the zone
# enforcement. Keeping its config here lets a runtime forbid(...) start it on
# demand, so the forbidden area works even if the tool was launched without it.
LOC_TRACKER = {"running": False, "cfg": None, "nets": None, "every": 8,
               "csv": None, "quiet": False}


def parse_anchor(spec):
    """'iface=wlan0;name=Lab;x=10;y=4' -> (iface, {name,x,y}) or (None, why).

    An anchor pins one radio to a position, so a device associated to it reads
    as 'near <name> (x,y)' instead of only a distance. It is optional sugar:
    without anchors the trace still gives the radio and the distance range.
    """
    fields = {}
    for part in re.split(r"[;,]", spec or ""):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        fields[k.strip().lower()] = v.strip()
    iface = fields.get("iface") or fields.get("radio")
    if not iface:
        return None, "no iface= in %r" % spec
    try:
        x = float(fields.get("x", "nan"))
        y = float(fields.get("y", "nan"))
    except ValueError:
        return None, "x= and y= must be numbers in %r" % spec
    if x != x or y != y:                   # NaN -> not supplied
        return None, "need both x= and y= in %r" % spec
    return iface, {"name": fields.get("name") or iface, "x": x, "y": y}


def _zone_membership(iface, rssi, dist_mid):
    """(inside, outside_clear, basis_text) for one sample against the zone.

    inside and outside_clear are deliberately NOT negations of each other: the
    gap between them is the dead band the state machine holds in, so a device
    hovering at the edge neither enters nor leaves.
    """
    if not FORBIDDEN["on"]:
        return False, True, ""
    if FORBIDDEN["iface"] and iface != FORBIDDEN["iface"]:
        # Not even on the radio that defines the area -> definitively outside.
        return False, True, "not on %s" % FORBIDDEN["iface"]

    # RSSI criterion wins when set: it is what we actually measure, with none
    # of the distance model's wall/multipath error folded in.
    if FORBIDDEN["rssi_dbm"] is not None:
        thr = FORBIDDEN["rssi_dbm"]
        inside = rssi >= thr
        outside_clear = rssi <= thr - FORBIDDEN["rssi_margin_db"]
        return inside, outside_clear, "signal %d dBm vs >= %d dBm" % (rssi, thr)

    if FORBIDDEN["radius_m"] is not None and dist_mid is not None:
        r = FORBIDDEN["radius_m"]
        inside = dist_mid <= r
        outside_clear = dist_mid > r * (1.0 + FORBIDDEN["margin"])
        return inside, outside_clear, "~%.1f m vs radius %.1f m" % (dist_mid, r)

    # Zone is on but this device has no usable distance (no model / no fix).
    return False, True, "no distance estimate"


def device_location(mac, info):
    """Everything known about where one associated device is, as a dict."""
    rssi = info["rssi"]
    iface = info.get("iface", "?")
    ref, n, how = rssi_model_for(mac)
    got = rssi_to_distance(rssi, ref=ref, n=n)
    lo = mid = hi = None
    if got:
        lo, mid, hi = got
    inside, outside_clear, basis = _zone_membership(iface, rssi, mid)
    return {"mac": mac, "rssi": rssi, "iface": iface, "lo": lo, "mid": mid,
            "hi": hi, "how": how, "quality": rssi_quality(rssi),
            "anchor": ANCHORS.get(iface), "inside": inside,
            "outside_clear": outside_clear, "basis": basis}


def location_text(loc):
    """One human line for a device's current location."""
    bits = ["on %s" % loc["iface"]]
    if loc["mid"] is not None:
        if loc["hi"] is not None and loc["hi"] < 1.5:
            bits.append("<1.5 m")
        else:
            bits.append("~%.1f m (%.1f-%.1f m)" % (loc["mid"], loc["lo"], loc["hi"]))
    bits.append("%d dBm %s" % (loc["rssi"], loc["quality"]))
    if loc["anchor"]:
        a = loc["anchor"]
        bits.append("near %s (%.1f, %.1f)" % (a["name"], a["x"], a["y"]))
    if FORBIDDEN["on"]:
        bits.append("[INSIDE forbidden area]" if loc["inside"]
                    else "[clear]" if loc["outside_clear"] else "[at edge]")
    return "  ".join(bits)


# --------------------------------------------------------- zone enforcement

def zone_ipt(*args):
    if FORBIDDEN["dry_run"]:
        print("      [forbidden DRY RUN] iptables %s" % " ".join(args))
        return 0, ""
    try:
        p = subprocess.run(["iptables"] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=20)
        return p.returncode, p.stderr.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def zone_resolve_exempt(entries, nets):
    """Turn --forbidden-exempt IPs/MACs into a MAC set, like the gate does.

    An IP is resolved to a MAC once, at startup. A device offline right now
    cannot be resolved and is reported rather than silently left enforceable.
    """
    unresolved = []
    for raw in entries or []:
        item = (raw or "").split("#")[0].strip()
        if not item:
            continue
        if GATE_MAC.match(item):
            FORBIDDEN["exempt"][item.lower()] = item.lower()
            continue
        try:
            ip_to_int(item)
        except ValueError:
            unresolved.append((item, "not an IP or a MAC"))
            continue
        FORBIDDEN["exempt_ips"].add(item)
        mac = mac_for_ip(item)
        if mac:
            FORBIDDEN["exempt"][mac] = item
        else:
            unresolved.append((item, "no MAC yet (device offline?) -- it will "
                                     "still be exempted by IP"))
    return unresolved


def zone_is_exempt(ip, mac, nets):
    """(bool, reason). The refusals a location policy must never override."""
    if ip and ip in local_addresses():
        return True, "this router"
    peer = ssh_peer()
    if peer and (ip == peer or (mac and mac == mac_for_ip(peer))):
        return True, "the SSH peer administering this router"
    if ip and nets and not any(in_net(ip, n) for n in nets):
        return True, "not on a LAN subnet"
    if (mac and mac in FORBIDDEN["exempt"]) or (ip and ip in FORBIDDEN["exempt_ips"]):
        return True, "on the forbidden-area exempt list"
    if FORBIDDEN["applies"] != "all":
        if (mac and mac in GATE["always"]) or (ip and ip in GATE["always_ips"]):
            return True, "on the authorised (always-open) list"
    return False, ""


def zone_install(nets):
    """Create SW_ZONE and hook it into FORWARD on the LAN interfaces.

    Flushed on install: the iptables rules outlive a restart but the in-memory
    ZONE_STATE does not, so a device blocked before a restart would otherwise
    stay blocked with nothing tracking it. A clean slate is re-evaluated from
    live signal within a couple of samples.
    """
    FORBIDDEN["ifaces"] = gate_ifaces()
    if not FORBIDDEN["ifaces"]:
        return "[forbidden] no LAN interface found -- zone NOT installed"
    if not run(["which", "iptables"]).strip():
        return ("[forbidden] iptables not found. On an nftables-only build these "
                "rules do not apply -- zone NOT installed")

    zone_ipt("-N", ZONE_CHAIN)
    zone_ipt("-F", ZONE_CHAIN)
    hooked = []
    for iface in FORBIDDEN["ifaces"]:
        rc, _ = zone_ipt("-C", "FORWARD", "-i", iface, "-j", ZONE_CHAIN)
        if rc != 0:
            zone_ipt("-I", "FORWARD", "1", "-i", iface, "-j", ZONE_CHAIN)
        hooked.append(iface)
    FORBIDDEN["on"] = True

    if FORBIDDEN["rssi_dbm"] is not None:
        bound = "signal stronger than %d dBm" % FORBIDDEN["rssi_dbm"]
    else:
        bound = "within ~%.1f m" % (FORBIDDEN["radius_m"] or 0)
    where = ("on radio %s" % FORBIDDEN["iface"]) if FORBIDDEN["iface"] else \
            "on any radio"
    lines = ["[forbidden] AREA ACTIVE on %s%s -- a device %s %s loses internet "
             "(forwarding dropped, stays associated); it is restored once it "
             "roams out"
             % ("+".join(hooked), "  [DRY RUN]" if FORBIDDEN["dry_run"] else "",
                bound, where)]
    who = ("every device except the exempt/authorised list"
           if FORBIDDEN["applies"] != "all" else "EVERY device (applies=all)")
    lines.append("    applies to: %s" % who)
    if FORBIDDEN["exempt"]:
        lines.append("    exempt: %s"
                     % ", ".join("%s (%s)" % (m, l)
                                 for m, l in FORBIDDEN["exempt"].items()))
    if FORBIDDEN["radius_m"] is not None and TXT_CALIB["ref"] is None \
            and not RSSI_CAL["per_mac"]:
        lines.append("    NOTE: no distance calibration loaded, so the metre "
                     "boundary is a generic estimate. calibrate(x.x.x.x) or "
                     "use --forbidden-rssi for a dependable edge.")
    lines.append("    MAC-based and cloneable -- enforces policy on cooperating "
                 "devices, not a defence against a forged MAC")
    lines.append("    rules do not survive a reboot; remove them with:")
    lines.append("      %s" % zone_teardown())
    return "\n  ".join(lines)


def zone_teardown():
    parts = []
    for iface in FORBIDDEN["ifaces"]:
        parts.append("while iptables -D FORWARD -i %s -j %s 2>/dev/null; do :; "
                     "done" % (iface, ZONE_CHAIN))
    parts.append("iptables -F %s; iptables -X %s" % (ZONE_CHAIN, ZONE_CHAIN))
    return " ; ".join(parts)


def zone_block(mac):
    """Drop this MAC's forwarded traffic. Idempotent."""
    rc, _ = zone_ipt("-C", ZONE_CHAIN, "-m", "mac", "--mac-source", mac,
                     "-j", "DROP")
    if rc == 0:
        return "already blocked"
    rc, err = zone_ipt("-I", ZONE_CHAIN, "1", "-m", "mac", "--mac-source", mac,
                       "-j", "DROP")
    if rc != 0:
        return "FAILED: %s" % (err or "iptables error")
    return "internet cut (forwarding dropped, still associated)"


def zone_release(mac):
    """Remove every drop rule for this MAC. Returns how many were removed."""
    n = 0
    while n < 50:
        rc, _ = zone_ipt("-D", ZONE_CHAIN, "-m", "mac", "--mac-source", mac,
                         "-j", "DROP")
        if rc != 0:
            break
        n += 1
    return n


def zone_blocked_macs():
    """MACs currently dropped in SW_ZONE, read from iptables itself."""
    macs = set()
    for line in run(["iptables", "-S", ZONE_CHAIN]).splitlines():
        m = re.search(r"--mac-source\s+([0-9A-Fa-f:]{17})", line)
        if m:
            macs.add(m.group(1).lower())
    return macs


def _forbidden_body(kind, ip, name, mac, loc, st):
    arrive = kind == "enter"
    head = ("entered the forbidden area -- internet CUT"
            if arrive else "left the forbidden area -- internet RESTORED")
    return (
        "streamwatch - forbidden-area %s\n\n"
        "IP          : %s\n"
        "Hostname    : %s\n"
        "MAC         : %s\n"
        "Radio       : %s\n\n"
        "Event       : %s\n"
        "Location    : %s\n"
        "Basis       : %s\n"
        "Time        : %s\n\n"
        "A device inside the area has its forwarded traffic dropped by MAC: no\n"
        "internet and no cross-subnet, while it stays associated to the radio\n"
        "so this tool can see the moment it leaves and restore access.\n\n"
        "The boundary is derived from signal strength and is coarse -- a 6 dB\n"
        "swing is ~2.5x in distance and one wall costs ~15 dB. It is checked\n"
        "over several samples with a margin so the link does not flap at the\n"
        "edge. This is location-based access control on a network you operate.\n"
        % ("entry" if arrive else "exit",
           ip or "unknown", name or "-", mac, loc.get("iface", "?"),
           head, location_text(loc), loc.get("basis", "-"),
           datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        + ("\nNOTE: allow rule(s) keep %s open for this device even inside "
           "the area.\nSend rules() to see them, unallow(...) to close them.\n"
           % ", ".join(port_allows_for(mac)) if arrive and port_allows_for(mac)
           else ""))


def zone_eval_mac(mac, loc, ip, name, nets, cfg, now):
    """One step of the per-device entry/exit state machine. Enforces promptly;
    rate-limits only the email, never the iptables action."""
    st = ZONE_STATE.setdefault(
        mac, {"inside": False, "in_streak": 0, "out_streak": 0,
              "since": now, "last_report": 0.0, "blocked": False})

    if loc["inside"]:
        st["in_streak"] += 1
        st["out_streak"] = 0
    elif loc["outside_clear"]:
        st["out_streak"] += 1
        st["in_streak"] = 0
    else:
        return                      # dead band: hold, change nothing

    label = "%s (%s)" % (ip, name) if name else (ip or mac)

    # Confirmed ENTRY.
    if not st["inside"] and st["in_streak"] >= FORBIDDEN["enter_n"]:
        st["inside"] = True
        st["since"] = now
        exempt, why = zone_is_exempt(ip, mac, nets)
        if exempt:
            print("ZONE   %s  %s entered forbidden area -- NOT cut (%s)"
                  % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), label, why))
            return
        res = zone_block(mac)
        st["blocked"] = "FAILED" not in res
        print("FORBID %s  %s entered forbidden area -- %s  [%s]"
              % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), label, res,
                 loc["basis"]))
        holes = port_allows_for(mac)
        if holes:
            print("       note: allow rule(s) keep %s open for this device"
                  % ", ".join(holes))
        _zone_email(cfg, "enter", ip, name, mac, loc, st, now, label)
        return

    # Confirmed EXIT.
    if st["inside"] and st["out_streak"] >= FORBIDDEN["exit_n"]:
        st["inside"] = False
        st["since"] = now
        if st["blocked"] or mac in zone_blocked_macs():
            n = zone_release(mac)
            st["blocked"] = False
            print("ALLOW  %s  %s left forbidden area -- internet restored "
                  "(%d rule(s) removed)  [%s]"
                  % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), label, n,
                     loc["basis"]))
            _zone_email(cfg, "exit", ip, name, mac, loc, st, now, label)
        else:
            print("ZONE   %s  %s left forbidden area (was not cut)"
                  % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), label))
        return


def _zone_email(cfg, kind, ip, name, mac, loc, st, now, label):
    if not cfg:
        return
    if now - st["last_report"] < FORBIDDEN["cooldown"]:
        return
    st["last_report"] = now
    verb = "entered" if kind == "enter" else "left"
    try:
        send_email_alert(
            cfg["server"], cfg["port"], cfg["user"], cfg["password"], cfg["to"],
            "[streamwatch] %s %s the forbidden area" % (label, verb),
            _forbidden_body(kind, ip, name, mac, loc, st))
    except Exception as e:
        print("  [forbidden: email FAILED: %s]" % e)


def location_tracker(cfg, nets, every, csv_path=None, quiet=False,
                     names_ttl=60):
    """Background thread: sample every associated station's signal, keep a
    rolling location history, optionally log it, and -- when a forbidden area
    is configured -- drive the entry/exit enforcement for each device."""
    names, names_at = hostname_map(), time.time()

    if csv_path and not os.path.exists(csv_path):
        try:
            with open(csv_path, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "mac", "ip", "hostname", "iface", "rssi_dbm",
                     "dist_mid_m", "dist_lo_m", "dist_hi_m",
                     "inside_forbidden", "blocked"])
        except OSError as e:
            print("  [location: cannot write %s: %s]" % (csv_path, e))
            csv_path = None

    while True:
        now = time.time()
        if now - names_at > names_ttl:
            names, names_at = hostname_map(), now

        seen = wifi_rssi_map(ttl=0)              # fresh read -- this is the sampler
        for mac, info in seen.items():
            loc = device_location(mac, info)
            hist = LOCATION_HISTORY.setdefault(mac, [])
            hist.append((now, info["rssi"], loc["iface"], loc["mid"]))
            if len(hist) > LOCATION_MAX:
                del hist[:-LOCATION_MAX]

            ip = ip_for_mac(mac)
            name = names.get(ip, "") if ip else ""

            if csv_path:
                try:
                    with open(csv_path, "a", newline="") as f:
                        csv.writer(f).writerow(
                            [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), mac,
                             ip or "", name,
                             loc["iface"], info["rssi"],
                             "%.1f" % loc["mid"] if loc["mid"] is not None else "",
                             "%.1f" % loc["lo"] if loc["lo"] is not None else "",
                             "%.1f" % loc["hi"] if loc["hi"] is not None else "",
                             int(loc["inside"]),
                             int(ZONE_STATE.get(mac, {}).get("blocked", False))])
                except OSError:
                    pass

            # Print on change only -- a line per device per sample would bury
            # the screen. The zone transition prints its own louder line.
            if not quiet:
                bucket = round(loc["mid"]) if loc["mid"] is not None else None
                snap = (loc["iface"], bucket, loc["inside"])
                if LOC_LAST_PRINT.get(mac) != snap:
                    LOC_LAST_PRINT[mac] = snap
                    label = "%s (%s)" % (ip, name) if name else (ip or mac)
                    print("TRACE  %s  %-22s %s"
                          % (datetime.now().strftime("%H:%M:%S"), label,
                             location_text(loc)))

            if FORBIDDEN["on"]:
                zone_eval_mac(mac, loc, ip, name, nets, cfg, now)

        # A device that left the radio while blocked would otherwise stay
        # blocked forever -- nothing samples a device that is gone. Release it
        # after it has been absent longer than the exit confirmation would take.
        grace = max(every * (FORBIDDEN["exit_n"] + 1), 30)
        for mac in list(ZONE_STATE):
            if mac in seen:
                continue
            last = LOCATION_HISTORY.get(mac)
            gone = now - (last[-1][0] if last else ZONE_STATE[mac]["since"])
            st = ZONE_STATE[mac]
            if st.get("blocked") and gone > grace:
                zone_release(mac)
                st["blocked"] = False
                st["inside"] = False
                print("ALLOW  %s  %s left radio coverage -- forbidden-area "
                      "block lifted" % (datetime.now().strftime("%H:%M:%S"),
                                        ip_for_mac(mac) or mac))
            if gone > 3600:
                ZONE_STATE.pop(mac, None)
                LOCATION_HISTORY.pop(mac, None)
                LOC_LAST_PRINT.pop(mac, None)

        time.sleep(every)


def zone_status_lines():
    """The zones() report: configuration, then who is inside / cut right now."""
    if not FORBIDDEN["on"]:
        return ["Forbidden area: OFF. Start with --forbidden-radius <m> or "
                "--forbidden-rssi <dBm>, or send forbid(<m>) by email."]
    if FORBIDDEN["rssi_dbm"] is not None:
        bound = "signal >= %d dBm" % FORBIDDEN["rssi_dbm"]
    else:
        bound = "within ~%.1f m (exit past %.1f m)" % (
            FORBIDDEN["radius_m"],
            FORBIDDEN["radius_m"] * (1.0 + FORBIDDEN["margin"]))
    lines = ["Forbidden area: ON",
             "  rule     : inside = %s%s" % (
                 bound, " on %s" % FORBIDDEN["iface"] if FORBIDDEN["iface"]
                 else " on any radio"),
             "  applies  : %s" % ("all devices" if FORBIDDEN["applies"] == "all"
                                  else "unauthorised devices (authorised list exempt)"),
             "  confirm  : enter after %d samples, exit after %d, cooldown %ds"
             % (FORBIDDEN["enter_n"], FORBIDDEN["exit_n"], FORBIDDEN["cooldown"]),
             "  hooked   : %s" % ("+".join(FORBIDDEN["ifaces"]) or "none")]
    inside = [(m, s) for m, s in ZONE_STATE.items() if s.get("inside")]
    cut = zone_blocked_macs()
    if inside:
        lines.append("  inside now:")
        for mac, s in inside:
            ip = ip_for_mac(mac)
            lines.append("    %-17s %-16s %s"
                         % (mac, ip or "-",
                            "CUT" if mac in cut else "present (not cut)"))
    else:
        lines.append("  inside now: nobody")
    if cut:
        orphan = [m for m in cut if not ZONE_STATE.get(m, {}).get("inside")]
        if orphan:
            lines.append("  cut but not currently located (stale/left): %s"
                         % ", ".join(orphan))
    return lines


def locate_report_body(ip, nets, names=None):
    """locate(x.x.x.x) for one device, or locate() for every located device."""
    names = names or hostname_map()
    radio = wifi_rssi_map(ttl=0)
    lines = ["streamwatch - device location", "",
             "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    if FORBIDDEN["on"]:
        lines.append("Forbidden area is ON -- see zones() for the rule.")
    lines.append("")

    if ip:
        mac = mac_for_ip(ip)
        info = radio.get(mac) if mac else None
        if not info:
            lines.append("%s is not associated to a radio right now (wired, "
                         "offline, or no MAC known), so there is no signal to "
                         "locate it by." % ip)
            return "\n".join(lines) + "\n"
        loc = device_location(mac, info)
        lines += ["IP       : %s" % ip,
                  "Hostname : %s" % (names.get(ip, "") or "-"),
                  "MAC      : %s" % mac,
                  "Location : %s" % location_text(loc),
                  "Model    : %s" % loc["how"]]
        hist = LOCATION_HISTORY.get(mac, [])
        if len(hist) >= 2:
            span = hist[-1][0] - hist[0][0]
            lines.append("History  : %d samples over %s"
                         % (len(hist), human_time(int(span))))
        lines += ["", "Distance is modelled from signal strength, not measured; "
                  "read the range, not the midpoint."]
        return "\n".join(lines) + "\n"

    located = sorted(radio.items(), key=lambda kv: kv[1]["rssi"], reverse=True)
    if not located:
        lines.append("No device is associated to a radio right now.")
        return "\n".join(lines) + "\n"
    lines.append("%d device(s) on the radios:" % len(located))
    for mac, info in located:
        dip = ip_for_mac(mac)
        loc = device_location(mac, info)
        label = "%s (%s)" % (dip, names.get(dip, "")) if dip and names.get(dip) \
                else (dip or mac)
        lines.append("  %-28s %s" % (label[:28], location_text(loc)))
    lines += ["", "Distances are modelled from signal strength and are coarse. "
              "Wired devices have no signal and are not listed."]
    return "\n".join(lines) + "\n"


def ensure_location_tracker():
    """Start the sampler thread once, if it is not already running. Returns
    True if it was started by this call."""
    if LOC_TRACKER["running"] or LOC_TRACKER["nets"] is None:
        return False
    LOC_TRACKER["running"] = True
    threading.Thread(
        target=location_tracker,
        args=(LOC_TRACKER["cfg"], LOC_TRACKER["nets"], LOC_TRACKER["every"],
              LOC_TRACKER["csv"], LOC_TRACKER["quiet"]),
        daemon=True).start()
    return True


def forbid_runtime(value, unit, nets):
    """Apply forbid(<n>) from a command. Negative or dBm -> signal threshold;
    positive -> metre radius. Starts the sampler if it is not already up."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "[forbid] could not read %r as a number" % value
    unit = (unit or "").lower()
    if unit == "dbm" or (not unit and v < 0):
        FORBIDDEN["rssi_dbm"] = int(v)
        FORBIDDEN["radius_m"] = None
        what = "signal stronger than %d dBm" % int(v)
    else:
        if v <= 0:
            return "[forbid] a metre radius must be positive (got %s)" % value
        FORBIDDEN["radius_m"] = v
        FORBIDDEN["rssi_dbm"] = None
        what = "within ~%.1f m" % v

    out = []
    if not FORBIDDEN["on"]:
        out.append(zone_install(nets))
    else:
        out.append("[forbid] updated: inside = %s (area already active)" % what)
    if ensure_location_tracker():
        out.append("[forbid] location sampler started to enforce it")
    elif LOC_TRACKER["nets"] is None:
        out.append("[forbid] WARNING: no sampler configured; enforcement is "
                   "not live until restarted with --track-location")
    return "\n  ".join(out)


def unforbid_runtime():
    """Turn the forbidden area off and restore everyone it had cut."""
    if not FORBIDDEN["on"]:
        return "[unforbid] the forbidden area was already off"
    released = 0
    for mac in list(zone_blocked_macs()):
        released += zone_release(mac)
    for st in ZONE_STATE.values():
        st["inside"] = False
        st["blocked"] = False
    FORBIDDEN["on"] = False
    return ("[unforbid] forbidden area OFF -- %d block rule(s) removed, internet "
            "restored for all. The (now empty) chain is left in place; remove "
            "it entirely with:\n  %s" % (released, zone_teardown()))


# ------------------------------------------------------------- port rules
#
# ADDED. Per-device, per-port control: block(ip, port) / allow(ip, port).
#
# close()/open() and the gate decide whether a DEVICE may forward at all. The
# forbidden area decides it by location. None of them can say "this device,
# but not port 443" -- that is what these rules add. One chain, at the head
# of FORWARD:
#
#     SW_PORTS:  DROP   <mac> dport 443          <- block(x.x.x.x, 443)
#                DROP         dport 23           <- block(*, 23)
#                ACCEPT <mac> dport 80           <- allow(x.x.x.x, 80)
#                ACCEPT       dport 53           <- allow(*, 53)
#                (fall through: no rule here applies to this packet)
#
# BLOCKS FIRST -- A BLOCK OVERRIDES AN ALLOW (Control.Precedence, BR-2)
#     Where an allow and a block match the same device and port, the block
#     wins. So the DROP rules are emitted AHEAD of the ACCEPT rules: a packet
#     matching a block is dropped before any allow is seen. An allow still
#     ACCEPTs traffic that no block contradicts, and because the chain sits at
#     the head of FORWARD -- re-asserted whenever close(), the gate or the
#     forbidden area inserts in front of it -- such an allow is also let
#     through ahead of the gate's own drop for that one port (the hole you
#     punch for a gated device that may reach port 80 and nothing else).
#     ACCEPT rather than RETURN, so the allow does not fall back into the very
#     drops it is meant to pass. What an allow cannot do is override a block of
#     the same traffic (BR-2), nor reach a device a full-mode close() has
#     deauthenticated.
#
# DESTINATION PORT, DEVICE AS SOURCE
#     block(x, 443) means x may not reach port 443 anywhere -- the port on
#     the far end, the one that names a service. The match is the device's
#     MAC as the frame's source on the LAN interface, for the reason every
#     other control here uses MAC: a new lease must not shed the rule. Only
#     forwarded traffic is covered; a port on the router itself (its SSH,
#     its web UI) is INPUT and is not touched.
#
# PERSISTED, LIKE QUOTAS
#     Rules are written to PORT_RULES_FILE and re-applied at startup, so a
#     restart of the tool does not silently undo a policy. The chain is
#     rebuilt from the list on every change rather than edited in place:
#     one source of truth, so the live chain cannot drift from the list.

PORT_CHAIN = "SW_PORTS"
PORT_RULES_FILE = "/root/.streamwatch_ports.json"
PORT_RULES = []        # [{"action","mac","label","lo","hi","proto","added"}]
PORTS = {"on": False, "ifaces": [], "dry_run": False}
PORTS_LOCK = threading.RLock()   # the poll loop and the command thread both
                                 # touch the chain; one at a time
PORT_PROTOS = ("tcp", "udp")

# block(192.168.8.50, 443)   block(*, 23)   block(192.168.8.50, 6881-6889, udp)
# allow(192.168.8.50, 80)    unblock(...)   unallow(...)   -- the same shapes.
# \b in front of the verb keeps "block(" from matching inside "unblock(".
PORT_CMD = re.compile(
    r"\b(block|allow|unblock|unallow)\s*\(\s*(\*|\d{1,3}(?:\.\d{1,3}){3})"
    r"\s*[,;\s]\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?"
    r"(?:\s*[,;\s]\s*(tcp|udp|both|any))?\s*\)", re.I)
RULES_CMD = re.compile(r"\brules\s*\(\s*\)", re.I)


def parse_port_rules(text):
    """[(verb, target, lo, hi, proto), ...] from block/allow/unblock/unallow.

    A port outside 1-65535, a backwards range, or a target that is not an IP
    is dropped rather than guessed at -- the same stance as limit(): a rule
    built from a misread number blocks the wrong thing with no feedback.
    """
    out = []
    for verb, target, lo, hi, proto in PORT_CMD.findall(text or ""):
        try:
            lo_n = int(lo)
            hi_n = int(hi) if hi else lo_n
        except ValueError:
            continue
        if not (1 <= lo_n <= 65535 and lo_n <= hi_n <= 65535):
            continue
        if target != "*":
            try:
                ip_to_int(target)
            except ValueError:
                continue
        p = (proto or "both").lower()
        if p == "any":
            p = "both"
        item = (verb.lower(), target, lo_n, hi_n, p)
        if item not in out:
            out.append(item)
    return out


def port_span_text(lo, hi, proto):
    span = "%d" % lo if lo == hi else "%d-%d" % (lo, hi)
    return "%s %s" % ("tcp+udp" if proto == "both" else proto, span)


def _port_rule_key(r):
    return (r["action"], r["mac"], r["lo"], r["hi"], r["proto"])


def ports_ipt(*args):
    if PORTS["dry_run"]:
        print("      [ports DRY RUN] iptables %s" % " ".join(args))
        return 0, ""
    try:
        p = subprocess.run(["iptables"] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=20)
        return p.returncode, p.stderr.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def ports_load():
    try:
        import json
        with open(PORT_RULES_FILE) as f:
            data = json.load(f)
    except Exception:
        return PORT_RULES
    if not isinstance(data, list):
        return PORT_RULES
    good = []
    for r in data:
        if not isinstance(r, dict):
            continue
        try:
            lo, hi = int(r["lo"]), int(r["hi"])
            mac = str(r["mac"]).lower()
            proto = str(r.get("proto", "both")).lower()
        except (KeyError, TypeError, ValueError):
            continue
        if r.get("action") not in ("allow", "block"):
            continue
        if not (1 <= lo <= hi <= 65535):
            continue
        if mac != "*" and not GATE_MAC.match(mac):
            continue
        if proto not in PORT_PROTOS + ("both",):
            continue
        rec = {"action": r["action"], "mac": mac, "label": str(r.get("label", mac)),
               "lo": lo, "hi": hi, "proto": proto,
               "added": float(r.get("added", 0) or 0)}
        if _port_rule_key(rec) not in [_port_rule_key(g) for g in good]:
            good.append(rec)
    PORT_RULES[:] = good
    return PORT_RULES


def ports_save():
    try:
        import json
        tmp = PORT_RULES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(PORT_RULES, f)
        os.replace(tmp, PORT_RULES_FILE)
    except Exception as e:
        print("  [ports: could not save %s: %s]" % (PORT_RULES_FILE, e))


def _port_match_args(r, proto):
    args = []
    if r["mac"] != "*":
        args += ["-m", "mac", "--mac-source", r["mac"]]
    args += ["-p", proto, "--dport",
             "%d" % r["lo"] if r["lo"] == r["hi"] else "%d:%d" % (r["lo"], r["hi"])]
    return args


def _ports_hook_front():
    """Delete every SW_PORTS jump from FORWARD and re-insert one per LAN
    interface at position 1. Called under PORTS_LOCK."""
    for iface in PORTS["ifaces"]:
        n = 0
        while n < 50:
            rc, _ = ports_ipt("-D", "FORWARD", "-i", iface, "-j", PORT_CHAIN)
            if rc != 0:
                break
            n += 1
    for iface in PORTS["ifaces"]:
        ports_ipt("-I", "FORWARD", "1", "-i", iface, "-j", PORT_CHAIN)


def ports_hook_is_front():
    """True if the first len(ifaces) rules of FORWARD are all our jumps --
    which is the only arrangement where nothing can drop before an allow."""
    n = len(PORTS["ifaces"])
    lines = [l for l in run(["iptables", "-S", "FORWARD"]).splitlines()
             if l.startswith("-A FORWARD")]
    head = lines[:n]
    return len(head) == n and all(("-j %s" % PORT_CHAIN) in l for l in head)


def ports_rehook():
    """Put the chain back at the head of FORWARD if something -- close(),
    the gate, the forbidden area -- has inserted in front of it since.

    Only needed while an allow exists: every hook here is inserted at
    position 1, ahead of OpenWrt's own rules, so a block drops wherever it
    sits among them; an allow must be ahead of every drop. In dry-run mode
    nothing was really inserted, so the check would fire every poll; skip it.
    Returns True if the hook was moved.
    """
    with PORTS_LOCK:
        if not PORTS["on"] or not PORTS["ifaces"] or PORTS["dry_run"]:
            return False
        if not any(r["action"] == "allow" for r in PORT_RULES):
            return False
        if ports_hook_is_front():
            return False
        _ports_hook_front()
        return True


def ports_apply():
    """Rebuild SW_PORTS from PORT_RULES and hook it. Returns a report line."""
    with PORTS_LOCK:
        if not PORTS["ifaces"]:
            PORTS["ifaces"] = gate_ifaces()
        if not PORTS["ifaces"]:
            return "[ports] no LAN interface found -- rules NOT applied"
        if not run(["which", "iptables"]).strip():
            return ("[ports] iptables not found. On an nftables-only build these "
                    "rules do not apply -- rules NOT applied")

        ports_ipt("-N", PORT_CHAIN)
        ports_ipt("-F", PORT_CHAIN)
        n, failed = 0, []
        for action in ("block", "allow"):          # blocks first: a block wins (BR-2)
            for r in PORT_RULES:
                if r["action"] != action:
                    continue
                protos = PORT_PROTOS if r["proto"] == "both" else (r["proto"],)
                for proto in protos:
                    rc, err = ports_ipt("-A", PORT_CHAIN,
                                        *(_port_match_args(r, proto)
                                          + ["-j", "ACCEPT" if action == "allow"
                                             else "DROP"]))
                    if rc == 0:
                        n += 1
                    else:
                        failed.append("%s %s: %s" % (action, port_span_text(
                            r["lo"], r["hi"], proto), err or "failed"))
        _ports_hook_front()
        PORTS["on"] = True

    out = ("[ports] %d rule(s) -> %d iptables entries on %s%s"
           % (len(PORT_RULES), n, "+".join(PORTS["ifaces"]),
              "  [DRY RUN]" if PORTS["dry_run"] else ""))
    if failed:
        out += "\n      NOT applied: %s" % "; ".join(failed)
    return out


def ports_teardown():
    parts = []
    for iface in PORTS["ifaces"]:
        parts.append("while iptables -D FORWARD -i %s -j %s 2>/dev/null; do :; "
                     "done" % (iface, PORT_CHAIN))
    parts.append("iptables -F %s; iptables -X %s" % (PORT_CHAIN, PORT_CHAIN))
    return " ; ".join(parts)


def _ports_overlap(a, b):
    """Do two rules touch the same device, port and protocol anywhere?"""
    if a["mac"] != "*" and b["mac"] != "*" and a["mac"] != b["mac"]:
        return False
    if a["lo"] > b["hi"] or b["lo"] > a["hi"]:
        return False
    if a["proto"] != "both" and b["proto"] != "both" and a["proto"] != b["proto"]:
        return False
    return True


def port_allows_for(mac):
    """Spans an allow keeps open for this device -- the forbidden area and
    close() say so when they cut a device, so the hole is not a surprise."""
    return [port_span_text(r["lo"], r["hi"], r["proto"]) for r in PORT_RULES
            if r["action"] == "allow" and r["mac"] in ("*", mac)]


def port_rule_cmd(verb, target, lo, hi, proto, nets):
    """One block/allow/unblock/unallow command. Refusals first, announced.

    The refusals are the same ones close() applies, for the same reason: a
    forged email must not be able to point this at the router or at the
    machine administering it.
    """
    action = "allow" if verb in ("allow", "unallow") else "block"
    remove = verb.startswith("un")
    span = port_span_text(lo, hi, proto)

    if target == "*":
        mac = "*"
        who = "all devices"
    else:
        if not any(in_net(target, n) for n in nets):
            return ("[%s REFUSED] %s is not on a LAN subnet -- rules apply to "
                    "local devices, not to internet hosts" % (verb, target))
        if target in local_addresses():
            return "[%s REFUSED] %s is this router" % (verb, target)
        peer = ssh_peer()
        if peer and target == peer:
            return ("[%s REFUSED] %s is the address administering this router"
                    % (verb, target))
        mac = mac_for_ip(target)
        if not mac:
            return ("[%s REFUSED] no MAC known for %s -- not in the ARP table "
                    "or lease file, so the device cannot be identified"
                    % (verb, target))
        if peer and mac == mac_for_ip(peer):
            return ("[%s REFUSED] %s is the same device administering this "
                    "router" % (verb, target))
        who = "%s (%s)" % (target, mac)

    key = (action, mac, lo, hi, proto)
    rec = {"action": action, "mac": mac, "label": target, "lo": lo, "hi": hi,
           "proto": proto, "added": time.time()}

    if remove:
        before = len(PORT_RULES)
        PORT_RULES[:] = [r for r in PORT_RULES if _port_rule_key(r) != key]
        if len(PORT_RULES) == before:
            return "[%s] no such rule: %s %s for %s" % (verb, action, span, who)
        ports_save()
        return ("*** %s %s for %s REMOVED *** %d rule(s) remain\n      %s"
                % (action.upper(), span, who, len(PORT_RULES), ports_apply()))

    if any(_port_rule_key(r) == key for r in PORT_RULES):
        return "[%s SKIPPED] %s %s for %s is already present" % (
            verb, action, span, who)

    PORT_RULES.append(rec)
    ports_save()
    note = ""
    if action == "block":
        holes = [r for r in PORT_RULES
                 if r["action"] == "allow" and _ports_overlap(r, rec)]
        if holes:
            note = ("\n      NOTE: this block overrides an overlapping allow "
                    "(%s) for this device and port -- a block always wins (BR-2)"
                    % ", ".join("%s for %s" % (port_span_text(h["lo"], h["hi"],
                                                              h["proto"]),
                                               "all devices" if h["mac"] == "*"
                                               else h["label"])
                                for h in holes))
    else:
        blocks = [r for r in PORT_RULES
                  if r["action"] == "block" and _ports_overlap(r, rec)]
        if blocks:
            note = ("\n      NOTE: a block overlaps this allow and a block wins "
                    "(BR-2), so this allow has no effect where they overlap -- "
                    "unblock to let it through")
        else:
            note = ("\n      an allow permits this device and port, and (as an "
                    "ACCEPT at the head of FORWARD) lets it through the gate and "
                    "forbidden area for that port. A block of the same traffic "
                    "overrides it (BR-2); it cannot reach a device a full-mode "
                    "close() has deauthenticated.")
    return ("*** %s %s for %s *** %s%s\n      undo: send %s(%s, %s%s)"
            % (action.upper(), span, who, ports_apply(), note,
               "unallow" if action == "allow" else "unblock", target,
               "%d" % lo if lo == hi else "%d-%d" % (lo, hi),
               "" if proto == "both" else ", %s" % proto))


def port_rules_lines(names=None):
    """One line per rule, blocks first, the order the chain applies them."""
    names = names or hostname_map()
    out = []
    for action in ("block", "allow"):
        for r in sorted((r for r in PORT_RULES if r["action"] == action),
                        key=lambda r: (r["mac"] != "*", r["label"], r["lo"])):
            if r["mac"] == "*":
                who = "* (all devices)"
            else:
                ip = ip_for_mac(r["mac"]) or r["label"]
                name = names.get(ip, "")
                who = "%s (%s)" % (ip, name or r["mac"])
            when = (datetime.fromtimestamp(r["added"]).strftime("%Y-%m-%d %H:%M")
                    if r["added"] else "-")
            out.append("%-6s %-32s %-18s added %s"
                       % (action.upper(), who[:32],
                          port_span_text(r["lo"], r["hi"], r["proto"]), when))
    return out


def port_rules_body(names=None):
    """The rules() report."""
    lines = ["streamwatch - port rules", "",
             "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "Rules    : %d  (%s)" % (len(PORT_RULES),
                                      "applied" if PORTS["on"] else "not applied"),
             ""]
    if not PORT_RULES:
        lines.append("No port rules. Add one with block(x.x.x.x, 443), "
                     "block(*, 23), or allow(x.x.x.x, 80).")
    else:
        lines += port_rules_lines(names)
    lines += ["",
              "Block rules are applied first; where an allow and a block match",
              "the same device and port, the block wins (BR-2). An allow that no",
              "block contradicts also passes the gate and forbidden area for that",
              "port. Ports are destination ports on forwarded traffic -- the",
              "router's own ports are not covered.",
              "Rules are keyed on MAC and persist across restarts.",
              "",
              "On the router: iptables -L %s -n -v   (the pkts column on a"
              % PORT_CHAIN,
              "block rule counts what it has dropped)"]
    return "\n".join(lines) + "\n"


def alert(ip, name, total, e, threshold, level, cfg, cooldown):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label = "%s (%s)" % (ip, name) if name else ip
    sig = rssi_for_ip(ip)
    print("ALERT  %s  %s crossed %s  [total %s | in %s | out %s]%s"
          % (stamp, label, human(threshold * level),
             human(total), human(e["in"]), human(e["out"]),
             "  [wifi %s]" % sig if sig else ""))

    if not cfg:
        return
    now = time.time()
    last = e["last_alert"]
    if last and (now - last) < cooldown:
        return
    kind = "first crossing" if not last else "still climbing"
    e["last_alert"] = now

    subject = "[streamwatch] %s data usage crossed %s" % (
        label, human(threshold * level))
    body = ("Device %s has used %s total (%s).\n\n"
            "Total so far: IN %s / OUT %s\n"
            "Threshold   : %s (level %d)\n"
            "Measured on : %s traffic through this gateway\n"
            "Connection  : %s\n"
            "Time        : %s\n"
            % (label, human(total), kind,
               human(e["in"]), human(e["out"]),
               human(threshold), level,
               cfg.get("direction", "total"),
               rssi_for_ip(ip, verbose=True) or "wired (no radio signal)",
               stamp))

    send_email_alert(cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                     cfg["to"], subject, body,
                     include_latest=cfg.get("include_latest", False),
                     imap_server=cfg.get("imap_server", "imap.gmail.com"),
                     latest_wait=cfg.get("latest_wait", 20),
                     state=cfg.get("state"),
                     cmd_cfg=cfg.get("cmd_cfg"))


# --------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Alert when a device's traffic through this gateway "
                    "passes a cumulative threshold.")
    ap.add_argument("--threshold", default="500K",
                    help="per-device threshold, e.g. 500K, 5M, 2G (default 500K)")
    ap.add_argument("--direction", choices=("in", "out", "total"), default="total",
                    help="which byte total the threshold applies to")
    ap.add_argument("--interval", type=int, default=10,
                    help="seconds between polls (default 10)")
    ap.add_argument("--table-every", type=int, default=6,
                    help="print the full table every N polls (0 = never)")
    ap.add_argument("--csv", metavar="PATH", help="append per-poll totals to CSV")
    ap.add_argument("--lan-net", action="append", metavar="CIDR",
                    help="override LAN subnet detection, e.g. 192.168.8.0/24")
    ap.add_argument("--email-alert", action="store_true",
                    help="Email you when a device's total data crosses --threshold.")
    ap.add_argument("--email-to",
                    help="Recipient email address (required with --email-alert).")
    ap.add_argument("--smtp-server", default="smtp.gmail.com",
                    help="SMTP server (default smtp.gmail.com).")
    ap.add_argument("--smtp-port", type=int, default=587,
                    help="SMTP STARTTLS port (default 587).")
    ap.add_argument("--include-latest-email", action="store_true",
                    help="After each alert, send a SECOND email containing the first "
                         "line of the newest inbox message -- normally the alert that "
                         "was just delivered. INBOX is read read-only over IMAP.")
    ap.add_argument("--accept-commands", action="store_true",
                    help="Poll the inbox for close(x.x.x.x) commands and firewall-block "
                         "that LAN device. Requires --email-alert. Email senders are "
                         "forgeable -- see --command-from.")
    ap.add_argument("--command-from", action="append", metavar="ADDR",
                    help="Sender address allowed to issue commands. Repeatable. "
                         "Defaults to --email-to.")
    ap.add_argument("--command-poll", type=int, default=15, metavar="SEC",
                    help="How often to check the inbox for commands (default 15). "
                         "Runs independently of alerts.")
    ap.add_argument("--close-mode", choices=("full", "forward"), default="full",
                    help="full: MAC firewall drop + deauth + re-association ban "
                         "(device fully off the router). forward: block routed "
                         "traffic only, device stays associated. Default full.")
    ap.add_argument("--close-dry-run", action="store_true",
                    help="Print the iptables command instead of running it.")
    ap.add_argument("--threshold-from-email", action="store_true",
                    help="Take the data size named in the newest inbox message's "
                         "first line as the new limit. Requires --include-latest-email. "
                         "IP octets are ignored; the value is clamped to 10 KB - 10 GB.")
    ap.add_argument("--latest-wait", type=int, default=20, metavar="SEC",
                    help="How long to wait for the alert to land in the inbox before "
                         "reading it back (default 20).")
    ap.add_argument("--imap-server", default="imap.gmail.com",
                    help="IMAP server for --include-latest-email (default imap.gmail.com).")
    ap.add_argument("--alert-repeat", type=float, default=600, metavar="SEC",
                    help="Once a device crosses the threshold, wait this many seconds "
                         "before emailing about that device again (default 600).")
    ap.add_argument("--always-open", action="append", metavar="IP", default=[],
                    help="IP (or MAC) that is ALWAYS allowed and can never be "
                         "closed. Repeatable. Using this switches the LAN to "
                         "default-deny: every other device is blocked from "
                         "forwarding until you send open(x.x.x.x). Resolved to "
                         "a MAC at startup, so list devices that are online.")
    ap.add_argument("--always-open-file", metavar="PATH",
                    help="File of always-open IPs/MACs, one per line, # for "
                         "comments. Merged with --always-open.")
    ap.add_argument("--gate-dry-run", action="store_true",
                    help="Print the default-deny iptables commands instead of "
                         "running them. Read the plan before you trust it.")
    ap.add_argument("--group-lists", action="store_true",
                    help="Drive the approval gate from two MAC text files "
                         "(SRS Group.Lists): the allow list is let through, the "
                         "deny list is blocked entirely, everything else is "
                         "held at the gate. close(ip) deny-lists a device, "
                         "open(ip) allow-lists it; both persist across restart. "
                         "Hand edits to the files are picked up live. Switches "
                         "the LAN to default-deny, like --always-open.")
    ap.add_argument("--allow-file", default="/etc/streamwatch/allow.txt",
                    metavar="PATH",
                    help="Allow list for --group-lists (default "
                         "/etc/streamwatch/allow.txt). Managed by group_lists.py "
                         "or by hand; one MAC per line, # for comments.")
    ap.add_argument("--deny-file", default="/etc/streamwatch/deny.txt",
                    metavar="PATH",
                    help="Deny list for --group-lists (default "
                         "/etc/streamwatch/deny.txt).")
    ap.add_argument("--no-detect", action="store_true",
                    help="Turn off malfunction detection (no-internet outages and "
                         "missing devices). On by default: a TCP check to "
                         "1.1.1.1:443 and 8.8.8.8:53 every --detect-every s, a few "
                         "hundred bytes each.")
    ap.add_argument("--detect-every", type=int, default=10, metavar="SEC",
                    help="Seconds between upstream / presence checks (default 10).")
    ap.add_argument("--detect-fails", type=int, default=3, metavar="N",
                    help="Failed checks in a row before the internet counts as DOWN "
                         "(default 3, so ~30 s). The outage is dated from the first.")
    ap.add_argument("--missing-after", type=int, default=300, metavar="SEC",
                    help="Seconds a watched device may be unseen before a "
                         "'not connected' alert (default 300).")
    ap.add_argument("--watch-device", action="append", default=[], metavar="IP|MAC",
                    help="A device that should always be present. Repeatable. The "
                         "allow list is watched automatically under --group-lists.")
    ap.add_argument("--speed-report", action="store_true",
                    help="Measure the gateway's internet link on a timer and "
                         "email a report. Independent of traffic alerts.")
    ap.add_argument("--speed-every", type=int, default=60, metavar="SEC",
                    help="Seconds between speed probes (default 60).")
    ap.add_argument("--speed-bytes", type=int, default=10_000_000, metavar="N",
                    help="Bytes to download per probe (default 10000000). Every "
                         "byte is spent off your connection.")
    ap.add_argument("--speed-url", default=SPEED_URL, metavar="URL",
                    help="Download source. %%d is replaced by --speed-bytes. "
                         "Default is Cloudflare's speed endpoint.")
    ap.add_argument("--speed-latency-only", action="store_true",
                    help="Skip the download; report latency only. Costs a few "
                         "hundred bytes a probe instead of megabytes.")
    ap.add_argument("--speed-email-every", type=int, default=1, metavar="N",
                    help="Email once per N probes (default 1, every probe). "
                         "Raise this to stay under your mail provider's daily "
                         "send limit.")
    ap.add_argument("--speed-csv", metavar="PATH",
                    help="Append every probe to a CSV as well.")
    ap.add_argument("--speed-no-geo", action="store_true",
                    help="Leave the public IP and its location out of the "
                         "speed report. The lookup is cached hourly.")
    ap.add_argument("--rssi-track", action="store_true",
                    help="Watch each wireless device's signal and email when it "
                         "starts approaching the router, moving away, or goes "
                         "idle. Reports transitions only.")
    ap.add_argument("--rssi-every", type=int, default=5, metavar="SEC",
                    help="Seconds between signal samples (default 5). Costs "
                         "one iwinfo call per radio, no network traffic.")
    ap.add_argument("--rssi-window", type=int, default=60, metavar="SEC",
                    help="Trend window (default 60). The recent half is "
                         "compared against the older half.")
    ap.add_argument("--rssi-delta", type=float, default=5.0, metavar="DB",
                    help="dB of change before movement is declared (default 5). "
                         "Lower it and ordinary signal noise reads as walking.")
    ap.add_argument("--calibrate", metavar="IP",
                    help="One-shot: measure this device's signal and record it "
                         "as a calibration point, then exit. Use with --at. "
                         "Samples for several seconds and takes the median.")
    ap.add_argument("--at", type=float, default=1.0, metavar="METRES",
                    help="Distance for --calibrate, in metres (default 1).")
    ap.add_argument("--calibrate-wizard", metavar="IP",
                    help="Guided calibration: prompts for each position, waits "
                         "while you walk there, measures, then fits. Clears "
                         "any earlier points for the device first.")
    ap.add_argument("--calibrate-points", type=int, default=3, metavar="N",
                    help="How many positions the wizard asks for (default 3, "
                         "the minimum for a meaningful fit).")
    ap.add_argument("--calibrate-status", action="store_true",
                    help="Print the distance model in force -- the three-point "
                         "file, any command-line override, and the stored "
                         "per-device calibrations -- then exit.")
    ap.add_argument("--calibrate-reset", metavar="IP",
                    help="Discard all calibration points for this device, "
                         "then exit.")
    # Defaults are None, not the numbers, so that "not given" is
    # distinguishable from "given the same value the default happens to be".
    # Without that, loading rssi_calibration.txt could not tell whether -40
    # came from the file or from the command line, and would have to pick one
    # to lose.
    ap.add_argument("--rssi-ref", type=float, default=None, metavar="DBM",
                    help="RSSI a device reads at 1 metre. Overrides A= from "
                         "the calibration file; falls back to -40 when neither "
                         "is present. calibrate(x.x.x.x) still beats both for "
                         "that one device.")
    ap.add_argument("--rssi-exponent", type=float, default=None, metavar="N",
                    help="Path loss exponent. Overrides n= from the "
                         "calibration file; falls back to 3.0 when neither is "
                         "present. 2.0 is open air, 2.7-3.5 a normal room, 4+ "
                         "through several walls.")
    ap.add_argument("--prefer-per-device", action="store_true",
                    help="Let a per-device calibration outrank the reference "
                         "file. Off by default: the reference file is the "
                         "model that was actually walked at marked distances, "
                         "so it decides unless you say otherwise.")
    ap.add_argument("--rssi-calib-file", default=TXT_CALIB_FILE, metavar="PATH",
                    help="Three-point calibration written by rssi_dist.py "
                         "(default %s). Supplies A and n for every device "
                         "that has no calibration of its own; re-read "
                         "automatically when it changes."
                         % TXT_CALIB_FILE)
    ap.add_argument("--rssi-cooldown", type=int, default=180, metavar="SEC",
                    help="Minimum seconds between movement emails for the same "
                         "device (default 180).")
    ap.add_argument("--usage-report", action="store_true",
                    help="Email a roll-up of every device on the LAN: how much "
                         "data it has used, its signal, and its estimated "
                         "distance from the router, on a timer.")
    ap.add_argument("--usage-every", type=int, default=3600, metavar="SEC",
                    help="Seconds between usage reports (default 3600, hourly).")
    ap.add_argument("--dns-watch", action="store_true",
                    help="Record which domains each device looks up, by "
                         "following dnsmasq's query log. Enables dnsmasq "
                         "logging if it is off (restarts dnsmasq). Query it "
                         "with browsing(x.x.x.x) or browsing().")
    ap.add_argument("--dns-report", action="store_true",
                    help="Also email a lookup summary on a timer.")
    ap.add_argument("--dns-every", type=int, default=3600, metavar="SEC",
                    help="Seconds between dns reports (default 3600).")
    ap.add_argument("--track-devices", action="store_true",
                    help="Keep a permanent registry of every device ever seen "
                         "(MAC, vendor, hostnames, IPs, first seen) and email "
                         "when a new one appears. Query it with devices().")
    ap.add_argument("--track-location", action="store_true",
                    help="Continuously trace each wireless device's location "
                         "within the mesh: which radio it is on and its "
                         "estimated distance from it, sampled on a timer. "
                         "Query it with locate(x.x.x.x) or locate().")
    ap.add_argument("--location-every", type=int, default=8, metavar="SEC",
                    help="Seconds between location samples (default 8). Also "
                         "the forbidden-area sampling rate. One iwinfo call per "
                         "radio, no network traffic.")
    ap.add_argument("--location-csv", metavar="PATH",
                    help="Append every location sample to a CSV.")
    ap.add_argument("--location-quiet", action="store_true",
                    help="Do not print a TRACE line when a device's location "
                         "changes; keep the history and enforcement silent "
                         "except for forbidden-area transitions.")
    ap.add_argument("--anchor", action="append", metavar="SPEC", default=[],
                    help="Pin a radio to a coordinate so the trace reads as a "
                         "position: 'iface=wlan0;name=Lab;x=10;y=4'. Repeatable, "
                         "one per mesh radio. Optional.")
    ap.add_argument("--forbidden-radius", type=float, metavar="METRES",
                    help="Turn on the forbidden area: a wireless device whose "
                         "estimated distance from the mesh falls within this "
                         "many metres loses internet (forwarding dropped, stays "
                         "associated) until it roams back out. Implies "
                         "--track-location.")
    ap.add_argument("--forbidden-rssi", type=float, metavar="DBM",
                    help="Define the forbidden area by signal instead of "
                         "metres: inside when RSSI >= this (e.g. -55). More "
                         "dependable than metres -- no distance model, so no "
                         "wall/multipath error. Overrides --forbidden-radius.")
    ap.add_argument("--forbidden-iface", metavar="NAME",
                    help="Restrict the forbidden area to one radio, so the zone "
                         "is that access point's coverage. Default: any radio.")
    ap.add_argument("--forbidden-applies", choices=("unauthorized", "all"),
                    default="unauthorized",
                    help="unauthorized (default): the authorised/always-open "
                         "list and --forbidden-exempt devices are never cut. "
                         "all: every device is subject to the area.")
    ap.add_argument("--forbidden-exempt", action="append", metavar="IP|MAC",
                    default=[],
                    help="A device (IP or MAC) the forbidden area never cuts, "
                         "independent of the gate. Repeatable.")
    ap.add_argument("--forbidden-margin", type=float, default=0.35, metavar="FRAC",
                    help="Exit hysteresis in metre mode: a cut device is "
                         "restored only past radius*(1+FRAC) (default 0.35), so "
                         "it does not flap at the edge.")
    ap.add_argument("--forbidden-enter", type=int, default=2, metavar="N",
                    help="Consecutive inside samples before internet is cut "
                         "(default 2).")
    ap.add_argument("--forbidden-exit", type=int, default=3, metavar="N",
                    help="Consecutive outside samples before internet is "
                         "restored (default 3).")
    ap.add_argument("--forbidden-cooldown", type=int, default=60, metavar="SEC",
                    help="Minimum seconds between forbidden-area emails for one "
                         "device (default 60). Enforcement itself is immediate.")
    ap.add_argument("--forbidden-dry-run", action="store_true",
                    help="Print the forbidden-area iptables commands instead of "
                         "running them. Read the plan before you trust it.")
    ap.add_argument("--ports-dry-run", action="store_true",
                    help="Print the port-rule iptables commands (block(x, 443), "
                         "allow(x, 80), ...) instead of running them. The rule "
                         "list is still saved, so the plan you read is the one "
                         "a real run would apply.")
    args = ap.parse_args()

    # Over `ssh host "cmd"` stdout is a pipe, not a terminal, so Python block-
    # buffers it and a long-running loop looks frozen. Force line buffering.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass

    # One-shot calibration modes: do the thing, print, exit. These run
    # alongside the service rather than through it -- calibration happens
    # while walking around with the phone, and waiting on an email poll
    # between every step makes that needlessly slow.
    apply_rssi_calibration(args)
    if args.calibrate_status:
        calib_load()
        ref_src, n_src = rssi_apply_fallback()
        print("Reference model%s:"
              % (" (overridden per device where one exists)"
                 if RSSI_PREFER_PER_DEVICE["on"] else
                 " -- used for EVERY device"))
        print("  A = %.1f dBm at 1 m   [%s]" % (RSSI_CAL["ref"], ref_src))
        print("  n = %.2f              [%s]" % (RSSI_CAL["n"], n_src))
        for line in txt_calib_lines():
            print(line)
        if TXT_CALIB["ref"] is None:
            print("  %s: %s" % (TXT_CALIB["path"],
                                TXT_CALIB["error"] or "not loaded"))
            print("  -> distances are generic until a calibration is loaded.")
        print("")
        print("Per-device calibration (%s):"
              % ("in use, it outranks the reference file"
                 if RSSI_PREFER_PER_DEVICE["on"] else
                 "stored, but the reference file above wins"))
        for line in rssi_calib_status():
            print(line)
        return 0
    if args.calibrate_reset:
        calib_load()
        mac = mac_for_ip(args.calibrate_reset)
        if mac and mac in RSSI_CAL["per_mac"]:
            RSSI_CAL["per_mac"].pop(mac)
            calib_save()
            print("Calibration cleared for %s (%s)."
                  % (args.calibrate_reset, mac))
        else:
            print("No calibration stored for %s." % args.calibrate_reset)
        return 0
    if args.calibrate_wizard:
        rc, msg = calibrate_wizard(args.calibrate_wizard,
                                   want=max(2, args.calibrate_points))
        print(msg)
        return rc
    if args.calibrate:
        rc, msg = calibrate_interactive(args.calibrate, args.at)
        print(msg)
        return rc

    threshold = parse_size(args.threshold)

    ok, note = ensure_accounting()
    print("conntrack accounting: %s" % note)
    if not ok:
        print("Without byte accounting there is nothing to measure. Stopping.",
              file=sys.stderr)
        return 1

    nets = lan_networks(args.lan_net)
    if not nets:
        print("No LAN subnet found. Pass --lan-net 192.168.8.0/24", file=sys.stderr)
        return 1

    cfg = None
    if args.email_alert:
        load_credentials()
        user = os.environ.get("STREAMWATCH_EMAIL_USER")
        password = os.environ.get("STREAMWATCH_EMAIL_PASS")
        if not args.email_to:
            print("--email-alert needs --email-to <address>.", file=sys.stderr)
            return 1
        if not user or not password:
            print("No mailbox login found. Put it in %s:" % CREDS_FILE)
            print('  STREAMWATCH_EMAIL_USER="you@gmail.com"')
            print('  STREAMWATCH_EMAIL_PASS="xxxx xxxx xxxx xxxx"')
            print("then: chmod 600 %s" % CREDS_FILE)
            print("(for Gmail, an App Password -- not your normal password)")
            print("Or export them for a one-off run, which overrides the file:")
            print('  export STREAMWATCH_EMAIL_USER="you@gmail.com"')
            print('  export STREAMWATCH_EMAIL_PASS="xxxx xxxx xxxx xxxx"')
            print("If you run this under sudo, use `sudo -E` or the variables vanish.")
            return 1
        cfg = {"server": args.smtp_server, "port": args.smtp_port, "user": user,
               "password": password, "to": args.email_to,
               "direction": args.direction,
               "include_latest": args.include_latest_email,
               "imap_server": args.imap_server,
               "latest_wait": args.latest_wait}
        print("Email alerts ON -> %s  (per-device threshold %s, at most one "
              "email per device every %gs)"
              % (args.email_to, human(threshold), args.alert_repeat))
        if threshold < 100_000:
            print("  NOTE: %s is a low bar -- ordinary browsing passes it in "
                  "seconds, so expect frequent mail." % human(threshold))

    state = None
    if args.threshold_from_email:
        if not (args.email_alert and args.include_latest_email):
            print("--threshold-from-email requires --email-alert and "
                  "--include-latest-email.", file=sys.stderr)
            return 1
        state = {"proposed": None}
        cfg["state"] = state
        print("Threshold-from-email ON: the size named in each inbox line "
              "becomes the next limit (clamped %s - %s)."
              % (human(MIN_THRESHOLD), human(MAX_THRESHOLD)))
        print("  NOTE: the newest message is normally streamwatch's own alert, "
              "so the limit tends to track usage upward each round.")

    # Location tracing + forbidden area share one sampler thread. Configure it
    # now -- before the command watcher starts -- so a runtime forbid(...) can
    # start enforcement even if the tool was launched without --track-location.
    # The zone itself is installed after the gate below, where the authorised
    # list it exempts is already known.
    LOC_TRACKER["cfg"] = cfg
    LOC_TRACKER["nets"] = nets
    LOC_TRACKER["every"] = max(2, args.location_every)
    LOC_TRACKER["csv"] = args.location_csv
    LOC_TRACKER["quiet"] = args.location_quiet
    for spec in args.anchor:
        iface, info = parse_anchor(spec)
        if iface:
            ANCHORS[iface] = info
        else:
            print("  [anchor ignored: %s]" % info)
    FORBIDDEN["iface"] = args.forbidden_iface
    FORBIDDEN["applies"] = args.forbidden_applies
    FORBIDDEN["margin"] = max(0.0, args.forbidden_margin)
    FORBIDDEN["enter_n"] = max(1, args.forbidden_enter)
    FORBIDDEN["exit_n"] = max(1, args.forbidden_exit)
    FORBIDDEN["cooldown"] = max(0, args.forbidden_cooldown)
    FORBIDDEN["dry_run"] = args.forbidden_dry_run
    if args.forbidden_rssi is not None:
        FORBIDDEN["rssi_dbm"] = int(args.forbidden_rssi)
    elif args.forbidden_radius is not None:
        FORBIDDEN["radius_m"] = args.forbidden_radius

    # Default-deny goes up BEFORE the command watcher starts, so there is no
    # window where the LAN is open and commands are already being honoured.
    gate_entries = list(args.always_open)
    if args.always_open_file:
        try:
            with open(args.always_open_file) as f:
                gate_entries += [l for l in f]
        except OSError as e:
            print("Could not read --always-open-file: %s" % e, file=sys.stderr)
            return 1

    # --group-lists seeds the gate's always-open set from allow.txt (minus
    # anything on deny.txt) and enforces deny.txt. It must run before
    # gate_install so the allow list is part of the chain from the first
    # packet, with no open window.
    group_lines = []
    if args.group_lists:
        GROUP["on"] = True
        GROUP["allow"], GROUP["deny"] = args.allow_file, args.deny_file
        group_lines, group_allow_macs = group_install(nets, gate_entries)
        gate_entries += group_allow_macs

    if gate_entries or GROUP["on"]:
        print("  " + gate_install(gate_entries, nets, dry_run=args.gate_dry_run))
        for line in group_lines:
            print("  " + line)
        if GROUP["on"]:
            # gate_install resolved the allow MACs onto GATE["always"]; keep
            # the granted set in step with what actually installed.
            GROUP["granted"] = set(GATE["always"])
            print("  group lists ON: close(ip) deny-lists, open(ip) "
                  "allow-lists; hand edits reload live")
        if not args.accept_commands:
            print("  NOTE: without --accept-commands there is no open(x.x.x.x) "
                  "channel, so nothing can be let through the gate remotely.")

    # Defined unconditionally: the quota enforcer closes devices too, and it
    # runs whether or not the email command channel is enabled.
    blocked = {}              # ip -> mac, so open() can undo after ARP ages out

    if args.accept_commands:
        if not cfg:
            print("--accept-commands requires --email-alert.", file=sys.stderr)
            return 1
        allow_from = args.command_from or [args.email_to]
        if args.include_latest_email:
            cfg["cmd_cfg"] = {"nets": nets, "mode": args.close_mode,
                              "dry_run": args.close_dry_run, "blocked": blocked}
        print("Command channel ON: close(x.x.x.x) / open(x.x.x.x)  [mode: %s]%s"
              % (args.close_mode, "  [DRY RUN]" if args.close_dry_run else ""))
        print("  scanning the last 20 inbox messages every %ds -- position in the "
              "inbox does not matter" % max(10, args.command_poll))
        print("  allowed senders: %s" % ", ".join(allow_from))
        print("  refused automatically: this router, the SSH peer (%s), anything "
              "off-LAN, and streamwatch's own mail" % (ssh_peer() or "none"))
        threading.Thread(target=command_watcher,
                         args=(cfg, nets, max(10, args.command_poll),
                               args.close_dry_run, allow_from, args.close_mode,
                               blocked),
                         daemon=True).start()

    if args.speed_report:
        per_day = 86400 // max(args.speed_every, 1)
        mails = per_day // max(args.speed_email_every, 1)
        print("Speed report ON: probing every %ds%s"
              % (args.speed_every,
                 ", latency only" if args.speed_latency_only else
                 ", downloading %s each time" % human(args.speed_bytes)))
        if not args.speed_latency_only:
            daily = args.speed_bytes * per_day
            print("  COST: %d probes/day = %s of your own bandwidth. Raise "
                  "--speed-every or lower --speed-bytes to cut it."
                  % (per_day, human(daily)))
        if cfg:
            print("  emailing %d report(s)/day to %s" % (mails, args.email_to))
            if mails > 400:
                print("  WARNING: free Gmail accounts stop accepting SMTP at "
                      "roughly 500 messages/day. At this rate sending will "
                      "start failing. Use --speed-email-every %d to batch them "
                      "into one message." % max(2, -(-per_day // 400)))
        else:
            print("  no --email-alert, so results print here only")
        threading.Thread(
            target=speed_watcher,
            args=(cfg, args.speed_every, args.speed_bytes, args.speed_url,
                  args.speed_latency_only, max(1, args.speed_email_every),
                  args.speed_csv, not args.speed_no_geo),
            daemon=True).start()

    apply_rssi_calibration(args, announce=True)
    if args.rssi_track:
        radios = wireless_ifaces()
        print("Movement tracking ON: sampling signal every %ds, trend over "
              "%ds, threshold %.0f dB" % (args.rssi_every, args.rssi_window,
                                          args.rssi_delta))
        print("  radios: %s" % (", ".join(radios) or "NONE FOUND -- iwinfo "
                                "returned nothing, movement cannot be tracked"))
        print("  reports state CHANGES only (approaching / moving away / idle), "
              "at most one per device every %ds" % args.rssi_cooldown)
        print("  wired devices have no signal and are not tracked")
        threading.Thread(
            target=rssi_tracker,
            args=(cfg, args.rssi_every, args.rssi_window, args.rssi_delta,
                  args.rssi_cooldown),
            daemon=True).start()

    quota_load()
    throttle_load()
    calib_load()
    if RSSI_CAL["per_mac"]:
        print("Distance calibration loaded from %s:" % CALIB_FILE)
        for line in rssi_calib_status():
            print(line)
    if args.dns_watch:
        print("DNS watch ON: %s" % dns_enable_logging())
        threading.Thread(target=dns_watcher, daemon=True).start()
        print("  query it by email with browsing(x.x.x.x) or browsing()")
        print("  shows domains looked up, not pages visited; devices using "
              "encrypted DNS will show little or nothing")
        if args.dns_report:
            def _dns_timer():
                while True:
                    time.sleep(args.dns_every)
                    if not DNS_LOG or not cfg:
                        continue
                    try:
                        send_email_alert(
                            cfg["server"], cfg["port"], cfg["user"],
                            cfg["password"], cfg["to"],
                            "[streamwatch] dns lookups - %d device(s)"
                            % len(DNS_LOG),
                            dns_report_body(names=hostname_map()))
                    except Exception as e:
                        print("  [dns report: email FAILED: %s]" % e)
            threading.Thread(target=_dns_timer, daemon=True).start()
            print("  emailing a summary every %s" % human_time(args.dns_every))

    if args.track_devices:
        devices_load()
        known = len(DEVICES)
        first = devices_update(nets)
        print("Device registry ON: %d known%s"
              % (len(DEVICES),
                 ", %d new at startup" % len(first) if known and first
                 else " (first run - everything present counts as known)"
                 if not known else ""))
        rnd = [m for m in DEVICES if DEVICES[m].get("randomised")]
        if rnd:
            print("  %d device(s) use a randomised MAC -- their identity can "
                  "change and break an --always-open entry" % len(rnd))
    if THROTTLES:
        msg = throttle_reapply(gate_ifaces(), wan_iface())
        if msg:
            print(msg)
        for line in throttle_status_lines():
            print(line)
        print("  remove the shaper entirely with: %s" % shaper_teardown())
    if QUOTAS:
        print("Quotas loaded from %s:" % QUOTA_FILE)
        for line in quota_status_lines():
            print(line)
    if args.accept_commands:
        print("  limit(x.x.x.x, 500MB) / limit(x.x.x.x, 2GB, daily) / "
              "unlimit(x.x.x.x) also accepted by email")
        print("  throttle(x.x.x.x, 2mbit) / throttle(x.x.x.x, 5mbit, 1mbit) / "
              "unthrottle(x.x.x.x) -- caps speed, does not cut the device off")

    # Forbidden area is installed here, after the gate, so the authorised
    # (always-open) list it exempts is already populated.
    want_zone = (FORBIDDEN["rssi_dbm"] is not None
                 or FORBIDDEN["radius_m"] is not None)
    if want_zone:
        for item, why in zone_resolve_exempt(args.forbidden_exempt, nets):
            print("  [forbidden-exempt note] %s -- %s" % (item, why))
        print("  " + zone_install(nets))
    elif args.forbidden_exempt:
        # Exemptions named without a zone -- resolve them so a later forbid()
        # honours them.
        zone_resolve_exempt(args.forbidden_exempt, nets)

    if args.track_location or want_zone:
        ensure_location_tracker()
        radios = wireless_ifaces()
        print("Location tracking ON: sampling every %ds%s"
              % (LOC_TRACKER["every"],
                 ", logging to %s" % args.location_csv
                 if args.location_csv else ""))
        print("  radios: %s" % (", ".join(radios) or "NONE FOUND -- iwinfo "
                                "returned nothing; wireless devices cannot be "
                                "located"))
        if ANCHORS:
            print("  anchors: %s"
                  % ", ".join("%s=%s(%.1f,%.1f)"
                              % (i, a["name"], a["x"], a["y"])
                              for i, a in ANCHORS.items()))
        print("  query by email with locate(x.x.x.x) / locate() / zones()")
        print("  distance is modelled from signal and is coarse; this is "
              "location-based access control on a network you operate, not "
              "covert tracking -- tell people where it applies")
        if want_zone:
            for line in zone_status_lines():
                print("  " + line)

    # Port rules go up last so their chain lands at the head of FORWARD,
    # ahead of the gate and the forbidden area -- an allow must be judged
    # before any drop. Re-applied from the file: a restart keeps the policy.
    PORTS["dry_run"] = args.ports_dry_run
    ports_load()
    if PORT_RULES:
        print("Port rules loaded from %s:" % PORT_RULES_FILE)
        for line in port_rules_lines():
            print("  " + line)
        print("  " + ports_apply())
        print("  remove the chain entirely with: %s" % ports_teardown())
    if args.accept_commands:
        print("  block(x.x.x.x, 443) / block(*, 23) / block(x.x.x.x, 6881-6889, udp) "
              "/ allow(x.x.x.x, 80) / unblock(...) / unallow(...) / rules() -- "
              "per-port control, keyed on MAC, a block overrides an allow%s"
              % ("  [DRY RUN]" if args.ports_dry_run else ""))

    if not args.no_detect:
        for w in args.watch_device:
            w = w.strip().lower()
            mac = w if GATE_MAC.match(w) else mac_for_ip(w)
            if mac:
                DETECT_WATCH.add(mac)
            else:
                print("  [watch-device: no MAC known for %s yet -- skipped]" % w)
        threading.Thread(target=outage_watcher,
                         args=(cfg, max(2, args.detect_every), args.detect_fails),
                         daemon=True).start()
        threading.Thread(target=presence_watcher,
                         args=(cfg, max(2, args.detect_every), args.missing_after),
                         daemon=True).start()
        print("Malfunction detection ON: internet checked every %ds (DOWN after %d "
              "misses); %d device(s) watched%s, alert after %s missing"
              % (args.detect_every, args.detect_fails, len(watched_macs()),
                 " + the allow list" if GROUP["on"] else "",
                 human_dur(args.missing_after)))
        print("  history in %s (pulled into the AI CSV by the Recorder)" % HEALTH_LOG)

    meter = Meter(nets)

    if args.usage_report:
        print("Usage report ON: every %s to %s (%d/day)"
              % (human_time(args.usage_every), args.email_to or "console",
                 86400 // max(args.usage_every, 1)))
        print("  lists every device with a lease or an ARP entry, including "
              "idle ones at 0 B")
        threading.Thread(target=usage_reporter,
                         args=(cfg, nets, args.usage_every),
                         daemon=True).start()
    names = hostname_map()
    print("streamwatch  threshold %s on %s traffic, polling every %ds"
          % (human(threshold), args.direction, args.interval))
    print("LAN subnets: %s   (WAN iface %s excluded)"
          % (", ".join(net_to_str(n) for n in nets), wan_iface() or "none"))
    print("conntrack source: %s"
          % (CONNTRACK_PROC if os.path.exists(CONNTRACK_PROC)
             else "conntrack -L (proc file absent)"))
    print("totals count from now, not from boot. Ctrl-C to stop.\n")

    if args.csv and not os.path.exists(args.csv):
        with open(args.csv, "w", newline="") as f:
            csv.writer(f).writerow(
                ["timestamp", "ip", "hostname", "bytes_in", "bytes_out", "bytes_total"])

    cycle = 0
    try:
        while True:
            cycle += 1
            meter.poll()
            if cycle % 10 == 1:
                names = hostname_map()

            # A proposal from the email thread takes effect here, between polls.
            proposed = state.get("proposed") if state else None
            if proposed and proposed != threshold:
                print("  [threshold changed: %s -> %s, read from email]"
                      % (human(threshold), human(proposed)))
                threshold = proposed
                # Resync levels to the new scale, otherwise a smaller threshold
                # makes every device look like it jumped dozens of levels and
                # fires a burst of alerts for growth that already happened.
                for e in meter.dev.values():
                    e["level"] = meter.measured_entry(e, args.direction) // threshold
            if state:
                state["proposed"] = None

            for ip in sorted(meter.dev):
                e = meter.dev[ip]
                total = meter.measured(ip, args.direction)
                level = total // threshold
                if level > e["level"]:
                    e["level"] = level
                    alert(ip, names.get(ip, ""), total, e, threshold,
                          level, cfg, args.alert_repeat)

            # A device appearing is the event a default-deny gate exists to
            # catch. Without this you would not hear about it until the next
            # hourly report -- and a gated device sends no traffic, so it
            # never shows up in the meter at all.
            if args.track_devices:
                for mac in devices_update(nets):
                    rec = DEVICES[mac]
                    ip = (rec.get("ips") or ["?"])[-1]
                    name = (rec.get("hostnames") or ["-"])[-1]
                    gated = GATE["on"] and mac not in GATE["always"]
                    print("NEW    %s  %s (%s) %s  %s%s"
                          % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             mac, rec.get("vendor", "?"), ip, name,
                             "  [BLOCKED by the gate]" if gated else ""))
                    if not cfg:
                        continue
                    try:
                        send_email_alert(
                            cfg["server"], cfg["port"], cfg["user"],
                            cfg["password"], cfg["to"],
                            "[streamwatch] new device: %s (%s)"
                            % (name if name != "-" else mac,
                               rec.get("vendor", "?")),
                            "streamwatch - new device on the network\n\n"
                            "MAC       : %s\n"
                            "Vendor    : %s\n"
                            "IP        : %s\n"
                            "Hostname  : %s\n"
                            "Radio     : %s\n"
                            "Signal    : %s\n"
                            "Gate      : %s\n"
                            "Time      : %s\n\n"
                            "%s"
                            "Send devices() for the full registry.\n"
                            % (mac, rec.get("vendor", "?"), ip, name,
                               rec.get("radio", "wired or unknown"),
                               "%d dBm" % rec["rssi"] if rec.get("rssi")
                               is not None else "n/a (wired)",
                               "BLOCKED -- send open(%s) to allow it" % ip
                               if gated else "allowed",
                               datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                               "This MAC is randomised, so it is not a "
                               "permanent identity --\nthe same device may "
                               "appear again under a different address.\n\n"
                               if rec.get("randomised") else ""))
                    except Exception as e:
                        print("  [new device: email FAILED: %s]" % e)

            # Publish a finished list for the reporting thread. One writer
            # here, one reader there -- the reporter never walks meter.dev
            # while this loop is adding to it.
            usage_snapshot_update(meter, names)

            # After metering, before the table: a device that went over is
            # closed in the same poll that measured it.
            if QUOTAS:
                quota_check(meter, nets, cfg, args.close_mode,
                            args.close_dry_run, blocked)

            # A quota close() inserts ahead of the port chain; an allow must
            # stay in front of every drop, so put the hook back if it moved.
            if PORT_RULES and ports_rehook():
                print("  [ports: chain moved back to the head of FORWARD]")

            # A hand edit of allow.txt / deny.txt takes effect here, without a
            # restart and without the email channel (Group.ListReload).
            if GROUP["on"] and group_files_changed():
                print("  " + group_reconcile(nets))

            # If a firewall reload flushed the gate, put it back -- default-deny
            # must not silently lapse into default-allow while we run.
            if GATE["on"] and gate_reensure():
                print("  [gate] re-applied after a firewall flush")

            if args.table_every and (cycle == 1 or cycle % args.table_every == 0):
                print("\n-- %s --" % datetime.now().strftime("%H:%M:%S"))
                print("%-16s %-18s %10s %10s %10s %10s"
                      % ("IP", "HOSTNAME", "IN", "OUT", "TOTAL", "SIGNAL"))
                rows = sorted(meter.dev.items(),
                              key=lambda kv: -(kv[1]["in"] + kv[1]["out"]))
                for ip, e in rows:
                    print("%-16s %-18s %10s %10s %10s %10s"
                          % (ip, (names.get(ip, "") or "-")[:18],
                             human(e["in"]), human(e["out"]),
                             human(e["in"] + e["out"]),
                             rssi_for_ip(ip) or "wired"))
                print("%d device(s), %d live flows\n"
                      % (len(meter.dev), len(meter.flows)))

            if args.csv:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(args.csv, "a", newline="") as f:
                    w = csv.writer(f)
                    for ip, e in sorted(meter.dev.items()):
                        w.writerow([ts, ip, names.get(ip, ""), e["in"], e["out"],
                                    e["in"] + e["out"]])

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n-- final totals --")
        for ip, e in sorted(meter.dev.items(),
                            key=lambda kv: -(kv[1]["in"] + kv[1]["out"])):
            print("%-16s %-18s in %10s  out %10s  total %10s"
                  % (ip, (names.get(ip, "") or "-")[:18], human(e["in"]),
                     human(e["out"]), human(e["in"] + e["out"])))
        print("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
