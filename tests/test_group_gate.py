#!/usr/bin/env python3
"""Logic tests for the --group-lists wiring in streamwatch_v12.py.

The iptables / wifi / device layer is faked, so the decision logic -- startup
seeding, close->deny, open->allow, hand-edit reconcile, BR-2 precedence, and
SSH-peer safety -- is checked without a router.

    python3 tests/test_group_gate.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "sw", os.path.join(HERE, "..", "streamwatch_v12.py"))
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)

PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


# ---- fakes: a gate RETURN set, a hard-blocked set, device identity ----
GATE_RET = set()         # macs with a SW_GATE RETURN (allowed through)
HARD = set()             # macs blocked INPUT+FORWARD (denied)

MACS = {"192.168.8.50": "aa:bb:cc:dd:ee:50",
        "192.168.8.60": "aa:bb:cc:dd:ee:60",
        "192.168.8.9":  "aa:bb:cc:dd:ee:09"}   # 8.9 = ssh peer
I2M = {v: k for k, v in MACS.items()}

sw.mac_for_ip = lambda ip: MACS.get(ip)
sw.ip_for_mac = lambda mac: I2M.get((mac or "").lower())
sw.ssh_peer = lambda: "192.168.8.9"
sw.local_addresses = lambda: {"192.168.8.1"}
sw.wifi_ban_plan = lambda mac, remove=False: ([], "fake")
sw._run_plan = lambda plan: []
NETS = [sw.cidr_to_net("192.168.8.0", 24)]

# gate grant/revoke by mac -> toggle GATE_RET; gate must look "on"
sw.GATE["on"] = True
sw.GATE["dry_run"] = False
sw.GATE["always"] = {}


def fake_grant(mac, label=""):
    GATE_RET.add(mac)
    sw.GATE["always"][mac] = label or mac


def fake_revoke(mac):
    GATE_RET.discard(mac)
    sw.GATE["always"].pop(mac, None)


sw.gate_grant_mac = fake_grant
sw.gate_revoke_mac = fake_revoke
sw.group_block_mac = lambda mac: (HARD.add(mac)
                                  if mac != sw._group_peer_mac() else None)
sw.group_unblock_mac = lambda mac: HARD.discard(mac)


# disconnect/reconnect: fake the firewall effect + refusals that matter
def fake_disconnect(ip, nets, dry_run=False, blocked=None):
    if ip in sw.local_addresses():
        return "[close REFUSED] %s is this router" % ip
    if ip == sw.ssh_peer():
        return "[close REFUSED] %s is the SSH peer" % ip
    mac = sw.mac_for_ip(ip)
    if not mac:
        return "[close REFUSED] no MAC known for %s" % ip
    if not dry_run:
        HARD.add(mac)
        if blocked is not None:
            blocked[ip] = mac
    return "*** %s (%s) DISCONNECTED ***" % (ip, mac)


def fake_reconnect(ip, nets, dry_run=False, blocked=None):
    mac = sw.mac_for_ip(ip)
    if mac and not dry_run:
        HARD.discard(mac)
    return "*** %s REOPENED ***" % ip


sw.disconnect_device = fake_disconnect
sw.reconnect_device = fake_reconnect

TMP = tempfile.mkdtemp()
ALLOW = os.path.join(TMP, "allow.txt")
DENY = os.path.join(TMP, "deny.txt")
sw.GROUP["allow"], sw.GROUP["deny"] = ALLOW, DENY


def write(path, macs):
    with open(path, "w") as f:
        for m in macs:
            f.write(m + "\n")


def reset(allow=(), deny=()):
    GATE_RET.clear()
    HARD.clear()
    sw.GROUP["granted"] = set()
    sw.GROUP["blocked"] = set()
    sw.GROUP["mtimes"] = {}
    sw.GATE["always"] = {}
    write(ALLOW, allow)
    write(DENY, deny)


print("file helpers:")
reset()
check("add writes a MAC", sw.group_file_add(ALLOW, "aa:bb:cc:dd:ee:50", "x") is True)
check("duplicate add is False", sw.group_file_add(ALLOW, "aa:bb:cc:dd:ee:50") is False)
check("load sees it", "aa:bb:cc:dd:ee:50" in sw.group_mac_set(ALLOW))
check("remove works", sw.group_file_remove(ALLOW, "aa:bb:cc:dd:ee:50") is True)
check("remove absent is False", sw.group_file_remove(ALLOW, "aa:bb:cc:dd:ee:50") is False)

print("\nstartup: allow seeds the gate, deny is blocked:")
reset(allow=["aa:bb:cc:dd:ee:50"], deny=["aa:bb:cc:dd:ee:60"])
lines, allow_macs = sw.group_install(NETS, [])
# emulate main(): gate_install would RETURN the allow macs; fake that
for m in allow_macs:
    GATE_RET.add(m)
sw.GROUP["granted"] = set(sw.GATE["always"]) | set(allow_macs)
check("allow mac returned for the gate", allow_macs == ["aa:bb:cc:dd:ee:50"])
check("deny mac hard-blocked at startup", "aa:bb:cc:dd:ee:60" in HARD)
check("deny mac not granted", "aa:bb:cc:dd:ee:60" not in GATE_RET)

print("\nstartup refuses to drop everyone when allow is empty:")
reset(allow=[], deny=[])
sw.ssh_peer = lambda: None            # no peer, no cli always
lines, allow_macs = sw.group_install(NETS, [])
check("warns and installs nothing", allow_macs == []
      and any("WARNING" in l for l in lines))
sw.ssh_peer = lambda: "192.168.8.9"   # restore

print("\nclose(ip) deny-lists and blocks; open(ip) allow-lists and frees:")
reset(allow=["aa:bb:cc:dd:ee:50"], deny=[])
sw.GROUP["granted"] = {"aa:bb:cc:dd:ee:50"}
GATE_RET.add("aa:bb:cc:dd:ee:50")
msg = sw.group_deny("192.168.8.50", NETS, blocked={})
check("close hard-blocks", "aa:bb:cc:dd:ee:50" in HARD)
check("close removed gate pass", "aa:bb:cc:dd:ee:50" not in GATE_RET)
check("close wrote deny.txt", "aa:bb:cc:dd:ee:50" in sw.group_mac_set(DENY))
check("close removed from allow.txt", "aa:bb:cc:dd:ee:50" not in sw.group_mac_set(ALLOW))
msg = sw.group_allow("192.168.8.50", NETS, blocked={})
check("open unblocks", "aa:bb:cc:dd:ee:50" not in HARD)
check("open granted gate pass", "aa:bb:cc:dd:ee:50" in GATE_RET)
check("open wrote allow.txt", "aa:bb:cc:dd:ee:50" in sw.group_mac_set(ALLOW))
check("open removed from deny.txt", "aa:bb:cc:dd:ee:50" not in sw.group_mac_set(DENY))

print("\nnever deny the router or the SSH peer:")
reset(allow=[], deny=[])
check("close(router) refused", "REFUSED" in sw.group_deny("192.168.8.1", NETS, blocked={}))
check("close(peer) refused", "REFUSED" in sw.group_deny("192.168.8.9", NETS, blocked={}))
check("neither got blocked", not HARD)

print("\nhand-edit reload (Group.ListReload) with BR-2 precedence:")
reset(allow=["aa:bb:cc:dd:ee:50"], deny=[])
sw.GROUP["granted"] = {"aa:bb:cc:dd:ee:50"}
GATE_RET.add("aa:bb:cc:dd:ee:50")
sw.group_touch()
# admin hand-edits: add 8.60 to allow, move 8.50 to deny
write(ALLOW, ["aa:bb:cc:dd:ee:50", "aa:bb:cc:dd:ee:60"])
write(DENY, ["aa:bb:cc:dd:ee:50"])
check("files_changed detects it", sw.group_files_changed())
sw.group_reconcile(NETS)
check("newly-allowed 8.60 granted", "aa:bb:cc:dd:ee:60" in GATE_RET)
check("8.50 on both -> denied (BR-2), blocked", "aa:bb:cc:dd:ee:50" in HARD)
check("8.50 lost its gate pass", "aa:bb:cc:dd:ee:50" not in GATE_RET)
check("no change after reconcile", not sw.group_files_changed())
# now the admin frees 8.50 again: remove from deny
write(DENY, [])
sw.group_reconcile(NETS)
check("8.50 unblocked after deny removed", "aa:bb:cc:dd:ee:50" not in HARD)
check("8.50 granted again (back on allow only)", "aa:bb:cc:dd:ee:50" in GATE_RET)

print("\nreconcile never denies the SSH peer even if hand-listed:")
reset(allow=[], deny=["aa:bb:cc:dd:ee:09"])     # someone put the peer on deny
sw.group_touch()
write(DENY, ["aa:bb:cc:dd:ee:09"])
sw.group_reconcile(NETS)
check("peer not hard-blocked", "aa:bb:cc:dd:ee:09" not in HARD)

print("\ngate_reensure rebuilds the chain after a firewall flush:")
# fake iptables: a chain store + FORWARD hook list, driven by gate_ipt/run
CHAIN = []        # SW_GATE rules (strings after the chain name)
HOOK = set()      # ifaces with a FORWARD -> SW_GATE jump


def fake_gate_ipt(*a):
    a = list(a)
    op = a[0]
    if op == "-N":
        return (0, "")
    if op == "-F" and a[1] == sw.GATE_CHAIN:
        CHAIN.clear(); return (0, "")
    if op == "-A" and a[1] == sw.GATE_CHAIN:
        CHAIN.append(" ".join(a[2:])); return (0, "")
    if op == "-C" and a[1] == "FORWARD":
        return (0, "") if a[a.index("-i") + 1] in HOOK else (1, "no")
    if op == "-I" and a[1] == "FORWARD":
        HOOK.add(a[a.index("-i") + 1]); return (0, "")
    return (0, "")


def fake_run(cmd, timeout=5):
    if cmd[:3] == ["iptables", "-S", sw.GATE_CHAIN]:
        return "-N SW_GATE\n" + "".join("-A SW_GATE %s\n" % r for r in CHAIN)
    return ""


sw.gate_ipt = fake_gate_ipt
sw.run = fake_run
sw.GATE.update({"on": True, "dry_run": False, "ifaces": ["br-lan"],
                "always": {"aa:bb:cc:dd:ee:50": "x"}})
sw.GROUP["on"] = False
# install once
HOOK.add("br-lan"); CHAIN[:] = ["-m mac --mac-source aa:bb:cc:dd:ee:50 -j RETURN",
                                "-j DROP"]
check("no-op when chain is intact", sw.gate_reensure() is False)
# simulate a firewall flush: chain and hook gone
CHAIN.clear(); HOOK.clear()
check("detects flush and rebuilds", sw.gate_reensure() is True)
check("RETURN for the allowed mac restored",
      any("aa:bb:cc:dd:ee:50" in r and "RETURN" in r for r in CHAIN))
check("catch-all DROP restored", any(r == "-j DROP" for r in CHAIN))
check("FORWARD hook restored", "br-lan" in HOOK)
check("no-op again once healed", sw.gate_reensure() is False)

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
