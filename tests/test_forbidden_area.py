#!/usr/bin/env python3
"""Stage-1 tests for the location trace + forbidden area.

Runs anywhere -- no router needed.

    python3 tests/test_forbidden_area.py

Off-router logic tests for the location + forbidden-area additions.

Fakes the iptables/iwinfo layer so the pure decision logic (membership, the
entry/exit state machine, exemptions, runtime commands) can be verified without
a GL.iNet box.
"""
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location(
    "sw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "streamwatch_v12.py"))
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)

PASS = [0]
FAIL = [0]


def check(name, cond):
    if cond:
        PASS[0] += 1
        print("  ok   %s" % name)
    else:
        FAIL[0] += 1
        print("  FAIL %s" % name)


# ---- fake firewall: a stateful set of blocked MACs in SW_ZONE -------------
FW = set()


def fake_zone_ipt(*args):
    a = list(args)
    # find the mac after --mac-source if present
    mac = None
    if "--mac-source" in a:
        mac = a[a.index("--mac-source") + 1].lower()
    op = a[0]
    if op == "-C":
        return (0, "") if mac in FW else (1, "no rule")
    if op == "-I" and mac:
        FW.add(mac)
        return 0, ""
    if op == "-D" and mac:
        if mac in FW:
            FW.discard(mac)
            return 0, ""
        return 1, "not found"
    return 0, ""          # -N, -F, hook checks, etc.


def fake_run(cmd, timeout=5):
    if cmd[:2] == ["which", "iptables"]:
        return "/usr/sbin/iptables\n"
    if cmd[:2] == ["iptables", "-S"]:
        return "".join("-A SW_ZONE -m mac --mac-source %s -j DROP\n" % m
                       for m in FW)
    return ""


sw.zone_ipt = fake_zone_ipt
sw.run = fake_run
sw.gate_ifaces = lambda: ["br-lan"]
sw.wireless_ifaces = lambda: ["wlan0", "wlan1"]
sw.local_addresses = lambda: {"192.168.8.1"}
sw.ssh_peer = lambda: "192.168.8.9"

MACS = {"192.168.8.50": "aa:bb:cc:dd:ee:50",
        "192.168.8.60": "aa:bb:cc:dd:ee:60",
        "192.168.8.9":  "aa:bb:cc:dd:ee:09",
        "192.168.8.1":  "aa:bb:cc:dd:ee:01"}
sw.mac_for_ip = lambda ip: MACS.get(ip)
sw.ip_for_mac = lambda mac: {v: k for k, v in MACS.items()}.get((mac or "").lower())
sw.hostname_map = lambda: {"192.168.8.50": "phone", "192.168.8.60": "laptop"}

NETS = [sw.cidr_to_net("192.168.8.0", 24)]

# Use a simple, predictable distance model: A=-40 at 1 m, n=2 -> clean math.
sw.RSSI_CAL["ref"] = -40.0
sw.RSSI_CAL["n"] = 2.0
sw.RSSI_OVERRIDE["ref"] = -40.0          # force "command line" model, skip files
sw.RSSI_OVERRIDE["n"] = 2.0


def dist_mid(rssi):
    lo, mid, hi = sw.rssi_to_distance(rssi, ref=-40.0, n=2.0)
    return mid


print("rssi_to_distance sanity (A=-40,n=2):")
# -40 dBm -> 1 m, -60 dBm -> 10 m
check("-40 dBm ~ 1 m", abs(dist_mid(-40) - 1.0) < 0.01)
check("-60 dBm ~ 10 m", abs(dist_mid(-60) - 10.0) < 0.01)

print("\nparse_anchor:")
iface, info = sw.parse_anchor("iface=wlan0;name=Lab;x=10;y=4")
check("parses good spec", iface == "wlan0" and info["name"] == "Lab"
      and info["x"] == 10 and info["y"] == 4)
bad_if, why = sw.parse_anchor("name=Lab;x=1;y=2")
check("rejects missing iface", bad_if is None)
bad_if2, why2 = sw.parse_anchor("iface=wlan0;x=1")
check("rejects missing y", bad_if2 is None)

print("\n_zone_membership (metres mode, radius 5 m, margin 0.35):")
sw.FORBIDDEN.update({"on": True, "radius_m": 5.0, "rssi_dbm": None,
                     "iface": None, "margin": 0.35})
# -40dBm=1m inside; -60dBm=10m clearly outside; ~-54dBm≈5m boundary
ins, outc, _ = sw._zone_membership("wlan0", -40, dist_mid(-40))
check("1 m is inside", ins and not outc)
ins, outc, _ = sw._zone_membership("wlan0", -60, dist_mid(-60))
check("10 m is outside-clear", (not ins) and outc)
# a point at 6 m: inside? no (6>5). outside-clear? 6 > 5*1.35=6.75 -> no => dead band
dm6 = 6.0
ins, outc, _ = sw._zone_membership("wlan0", None, dm6)
check("6 m is dead band (neither)", (not ins) and (not outc))

print("\n_zone_membership (rssi mode, >= -55 dBm):")
sw.FORBIDDEN.update({"radius_m": None, "rssi_dbm": -55, "rssi_margin_db": 6})
ins, outc, _ = sw._zone_membership("wlan0", -50, None)
check("-50 dBm inside", ins and not outc)
ins, outc, _ = sw._zone_membership("wlan0", -62, None)
check("-62 dBm outside-clear (<= -61)", (not ins) and outc)
ins, outc, _ = sw._zone_membership("wlan0", -58, None)
check("-58 dBm dead band", (not ins) and (not outc))

print("\n_zone_membership iface scope:")
sw.FORBIDDEN.update({"iface": "wlan1", "rssi_dbm": -55})
ins, outc, _ = sw._zone_membership("wlan0", -50, None)
check("strong signal on wrong radio is outside", (not ins) and outc)
sw.FORBIDDEN["iface"] = None

print("\nzone_is_exempt:")
sw.FORBIDDEN.update({"applies": "unauthorized", "exempt": {}, "exempt_ips": set()})
sw.GATE["always"] = {"aa:bb:cc:dd:ee:60": "192.168.8.60"}   # laptop authorised
sw.GATE["always_ips"] = {"192.168.8.60"}
ex, _ = sw.zone_is_exempt("192.168.8.1", "aa:bb:cc:dd:ee:01", NETS)
check("router exempt", ex)
ex, _ = sw.zone_is_exempt("192.168.8.9", "aa:bb:cc:dd:ee:09", NETS)
check("ssh peer exempt", ex)
ex, _ = sw.zone_is_exempt("192.168.8.60", "aa:bb:cc:dd:ee:60", NETS)
check("authorised device exempt", ex)
ex, _ = sw.zone_is_exempt("192.168.8.50", "aa:bb:cc:dd:ee:50", NETS)
check("ordinary device NOT exempt", not ex)
ex, _ = sw.zone_is_exempt("8.8.8.8", None, NETS)
check("off-LAN exempt (never touched)", ex)

print("\nfull state machine: approach -> cut, leave -> restore (radius 5 m):")
FW.clear()
sw.ZONE_STATE.clear()
sw.FORBIDDEN.update({"on": True, "radius_m": 5.0, "rssi_dbm": None,
                     "iface": None, "applies": "unauthorized",
                     "enter_n": 2, "exit_n": 3, "cooldown": 0, "dry_run": False})
mac = "aa:bb:cc:dd:ee:50"
ip = "192.168.8.50"


def step(rssi, t):
    loc = sw.device_location(mac, {"rssi": rssi, "iface": "wlan0"})
    sw.zone_eval_mac(mac, loc, ip, "phone", NETS, None, t)


# device far away (10 m): no block
step(-60, 1); step(-60, 2); step(-60, 3)
check("far device not blocked", mac not in FW)
# device walks inside (1 m): needs enter_n=2 samples
step(-40, 4)
check("one inside sample: not yet cut", mac not in FW)
step(-40, 5)
check("two inside samples: internet CUT", mac in FW)
check("state marks blocked", sw.ZONE_STATE[mac]["blocked"] is True)
# stays inside: still cut
step(-41, 6)
check("still inside: still cut", mac in FW)
# walks to the boundary dead band (6 m): must NOT restore
step(-200, 7)   # extremely weak? -200 -> huge distance, that's outside-clear
# use a true dead-band sample instead:
sw.ZONE_STATE[mac]["out_streak"] = 0
loc_edge = sw.device_location(mac, {"rssi": -53, "iface": "wlan0"})  # ~4.5m inside-ish
# craft an explicit dead-band distance:
# recompute: at radius 5, dead band is 5..6.75 m
# find rssi for ~6 m: -40-20log10(6)= -40-15.6= -55.6
loc_edge = sw.device_location(mac, {"rssi": -56, "iface": "wlan0"})
sw.zone_eval_mac(mac, loc_edge, ip, "phone", NETS, None, 8)
check("dead-band sample does not restore", mac in FW)
# walks clearly out (10 m): needs exit_n=3 clear samples
step(-60, 9); step(-60, 10)
check("two clear samples: still cut", mac in FW)
step(-60, 11)
check("three clear samples: internet RESTORED", mac not in FW)
check("state cleared blocked", sw.ZONE_STATE[mac]["blocked"] is False)

print("\nauthorised device inside the zone is never cut:")
FW.clear()
sw.ZONE_STATE.clear()
amac = "aa:bb:cc:dd:ee:60"
for t in range(1, 5):
    loc = sw.device_location(amac, {"rssi": -40, "iface": "wlan0"})
    sw.zone_eval_mac(amac, loc, "192.168.8.60", "laptop", NETS, None, t)
check("authorised device not in firewall", amac not in FW)

print("\nforbid_runtime unit detection:")
sw.FORBIDDEN.update({"on": False, "radius_m": None, "rssi_dbm": None})
sw.LOC_TRACKER["nets"] = None    # don't actually start a thread
sw.forbid_runtime("5", "", NETS)
check("forbid(5) -> 5 m radius", sw.FORBIDDEN["radius_m"] == 5.0
      and sw.FORBIDDEN["rssi_dbm"] is None)
sw.FORBIDDEN.update({"on": False, "radius_m": None, "rssi_dbm": None})
sw.forbid_runtime("-55", "", NETS)
check("forbid(-55) -> -55 dBm", sw.FORBIDDEN["rssi_dbm"] == -55
      and sw.FORBIDDEN["radius_m"] is None)
sw.FORBIDDEN.update({"on": False, "radius_m": None, "rssi_dbm": None})
sw.forbid_runtime("8", "dbm", NETS)
check("forbid(8, dbm) -> 8 dBm", sw.FORBIDDEN["rssi_dbm"] == 8)
msg = sw.forbid_runtime("-3", "m", NETS)
check("forbid(-3, m) rejected", "must be positive" in msg)

print("\nunforbid_runtime restores everyone:")
FW.clear(); FW.update({"aa:bb:cc:dd:ee:50", "aa:bb:cc:dd:ee:77"})
sw.FORBIDDEN["on"] = True
sw.ZONE_STATE["aa:bb:cc:dd:ee:50"] = {"inside": True, "blocked": True,
                                      "in_streak": 0, "out_streak": 0,
                                      "since": 0, "last_report": 0}
out = sw.unforbid_runtime()
check("all blocks removed", len(FW) == 0)
check("forbidden turned off", sw.FORBIDDEN["on"] is False)

print("\nreports render without error:")
sw.FORBIDDEN.update({"on": True, "radius_m": 5.0, "rssi_dbm": None})
try:
    _ = "\n".join(sw.zone_status_lines())
    _ = sw.locate_report_body(None, NETS, names=sw.hostname_map())
    _ = sw.locate_report_body("192.168.8.50", NETS, names=sw.hostname_map())
    check("zone_status_lines + locate_report_body render", True)
except Exception as e:
    check("reports render (%r)" % e, False)

print("\ncommand regexes:")
check("forbid(5) matches", bool(sw.FORBID_CMD.search("please forbid(5) now")))
check("forbid(-55) matches", bool(sw.FORBID_CMD.search("forbid(-55)")))
check("unforbid() matches", bool(sw.UNFORBID_CMD.search("unforbid()")))
check("zones() matches", bool(sw.ZONES_CMD.search("zones()")))
check("locate(ip) matches",
      sw.LOCATE_CMD.findall("locate(192.168.8.50)") == ["192.168.8.50"])
check("locate() matches empty", sw.LOCATE_CMD.findall("locate()") == [""])

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
