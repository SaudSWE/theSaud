#!/usr/bin/env python3
"""
group_lists.py -- manage the StreamWatch authorised-group text files.

Two files, one MAC per line, on the gateway node (SRS Group.Lists):

    allow list  -- devices permitted internet access  (the authorised group)
    deny  list  -- devices refused it entirely, by MAC (Control.BlockDevice)

A device on NEITHER list is unauthorised (BR-1) and is held by the approval
gate until the admin adds it here. A MAC on BOTH lists is denied -- a block
overrides an allow (BR-2).

WHY MAC AND NOT IP
    The request names a device by IP, the way open(ip)/close(ip) do, because
    that is the handle the admin reads off the map. But an IP is a lease: it
    changes between sessions and can be handed to a different device, so a
    list keyed on it would protect the wrong device after a renewal. Every
    entry is therefore resolved to the device's MAC once, when it is added,
    and stored as the MAC (Data.Identity). The IP and name are written after
    a '#' so the file is still readable. A device whose MAC cannot be found
    (not in the ARP table or the lease file) is REJECTED, not guessed at --
    the same refusal close()/open() already make.

FILE FORMAT
    aa:bb:cc:dd:ee:50  # 192.168.8.50 phone  added 2026-10-07T09:12:03
    # blank lines and lines beginning with # are ignored
    Entries are deduplicated by MAC, case-insensitively.

Usage:
    python3 group_lists.py allow add 192.168.8.50
    python3 group_lists.py allow remove 192.168.8.50
    python3 group_lists.py allow list
    python3 group_lists.py deny add aa:bb:cc:dd:ee:60
    python3 group_lists.py classify 192.168.8.50     # allow / deny / hold
"""

import os
import re
import sys
from datetime import datetime

# Small state files on the gateway (CON-2). Override with STREAMWATCH_DIR.
STATE_DIR = os.environ.get("STREAMWATCH_DIR", "/etc/streamwatch")
ALLOW_FILE = os.path.join(STATE_DIR, "allow.txt")
DENY_FILE = os.path.join(STATE_DIR, "deny.txt")

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


# ----------------------------------------------------------- identity

def ip_to_int(ip):
    """Validate a dotted quad. Raises ValueError on anything that is not one,
    so '999.1.1.1' and 'phone' are rejected before they reach a file."""
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(ip)
    n = 0
    for p in parts:
        v = int(p)                       # ValueError on non-digits
        if not 0 <= v <= 255:
            raise ValueError(ip)
        n = (n << 8) | v
    return n


def mac_for_ip(ip):
    """Resolve a LAN IP to its MAC via the ARP table, then the lease file.
    Returns the lower-case MAC, or None if the device cannot be identified."""
    try:
        with open("/proc/net/arp", errors="replace") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[0] == ip \
                        and c[3] != "00:00:00:00:00:00":
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


def resolve(entry, resolver=mac_for_ip):
    """(mac, ip) for an IP or a bare MAC. Raises ValueError if the entry is
    neither a valid IP nor a MAC, or is an IP with no MAC yet known."""
    item = (entry or "").strip()
    if MAC_RE.match(item):
        return item.lower(), None
    ip_to_int(item)                      # ValueError -> "not an IP or MAC"
    mac = resolver(item)
    if not mac:
        raise ValueError(
            "no MAC known for %s -- not in the ARP table or lease file, so "
            "the device cannot be identified" % item)
    return mac.lower(), item


# ----------------------------------------------------------- the list

class GroupList:
    """One MAC-per-line text file, edited atomically and kept root-only."""

    def __init__(self, path):
        self.path = path

    def load(self):
        """-> {mac: comment}. Missing file is an empty list, not an error."""
        out = {}
        try:
            with open(self.path, errors="replace") as f:
                for line in f:
                    body, _, comment = line.partition("#")
                    tok = body.strip()
                    if not tok:
                        continue
                    if MAC_RE.match(tok):
                        out[tok.lower()] = comment.strip()
        except OSError:
            pass
        return out

    def _save(self, entries):
        """Atomic write, then mode 600 -- a config file the admin owns, not
        world-readable. tmp + os.replace so a crash never leaves a half file."""
        d = os.path.dirname(self.path) or "."
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            for mac, comment in entries.items():
                f.write("%-17s  # %s\n" % (mac, comment) if comment
                        else "%s\n" % mac)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def add(self, entry, resolver=mac_for_ip):
        """Add a device. Returns a status string; never raises on a bad
        entry -- it reports the refusal the way the command channel does."""
        try:
            mac, ip = resolve(entry, resolver)
        except ValueError as e:
            return "[add REJECTED] %s" % e
        entries = self.load()
        label = "%s %s" % (ip or "-",
                           datetime.now().strftime("added %Y-%m-%dT%H:%M:%S"))
        if mac in entries:
            return "[add] %s (%s) already in %s" % (entry, mac,
                                                    os.path.basename(self.path))
        entries[mac] = label.strip()
        self._save(entries)
        return "*** %s (%s) ADDED to %s ***" % (entry, mac,
                                                os.path.basename(self.path))

    def remove(self, entry, resolver=mac_for_ip):
        """Remove a device. Resolving a since-departed IP can fail, so fall
        back to treating the entry as a MAC already in the file."""
        try:
            mac, _ = resolve(entry, resolver)
        except ValueError:
            mac = (entry or "").strip().lower()
            if not MAC_RE.match(mac):
                return ("[remove REJECTED] %s is not a MAC and its IP cannot "
                        "be resolved -- name the MAC to remove it" % entry)
        entries = self.load()
        if mac not in entries:
            return "[remove] %s (%s) was not in %s" % (
                entry, mac, os.path.basename(self.path))
        del entries[mac]
        self._save(entries)
        return "*** %s (%s) REMOVED from %s ***" % (
            entry, mac, os.path.basename(self.path))

    def contains(self, entry, resolver=mac_for_ip):
        try:
            mac, _ = resolve(entry, resolver)
        except ValueError:
            mac = (entry or "").strip().lower()
        return mac in self.load()


# ----------------------------------------------------------- decision

def classify(entry, resolver=mac_for_ip,
             allow_path=ALLOW_FILE, deny_path=DENY_FILE):
    """Model A, with BR-2 precedence (deny beats allow):

        on the deny list            -> "deny"   (blocked by MAC, close())
        on the allow list           -> "allow"  (full internet)
        on neither                  -> "hold"   (unauthorised, approval gate)
    """
    try:
        mac, _ = resolve(entry, resolver)
    except ValueError:
        mac = (entry or "").strip().lower()
    if mac in GroupList(deny_path).load():
        return "deny"
    if mac in GroupList(allow_path).load():
        return "allow"
    return "hold"


# ----------------------------------------------------------- cli

def _usage():
    print(__doc__.strip().split("Usage:")[1].strip())
    return 2


def main(argv):
    if not argv:
        return _usage()
    if argv[0] == "classify" and len(argv) == 2:
        print(classify(argv[1]))
        return 0
    if argv[0] not in ("allow", "deny") or len(argv) < 2:
        return _usage()
    gl = GroupList(ALLOW_FILE if argv[0] == "allow" else DENY_FILE)
    op = argv[1]
    if op == "list":
        entries = gl.load()
        if not entries:
            print("(%s is empty)" % gl.path)
        for mac, comment in entries.items():
            print("%-17s  %s" % (mac, comment))
        return 0
    if op in ("add", "remove") and len(argv) == 3:
        print(gl.add(argv[2]) if op == "add" else gl.remove(argv[2]))
        return 0
    if op == "check" and len(argv) == 3:
        print("yes" if gl.contains(argv[2]) else "no")
        return 0
    return _usage()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
