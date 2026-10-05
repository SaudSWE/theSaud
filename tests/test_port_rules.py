#!/usr/bin/env python3
"""Stage-1 tests for the per-port block/allow rules (requirement #8).

Runs anywhere -- no router needed. The iptables layer is replaced by a small
stateful fake (chains as ordered lists of rule strings) so the decision logic
can be checked exactly: what rules get built, in what order, what is refused,
what survives a restart, and that an allow is kept at the head of FORWARD.

    python3 tests/test_port_rules.py
"""
import contextlib
import importlib.util
import io
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


# ---------------------------------------------------------- fake iptables
CHAINS = {"FORWARD": [], "INPUT": []}


def fake_ipt(*args):
    a = list(args)
    op, chain = a[0], a[1]
    rest = a[2:]
    if op == "-N":
        if chain in CHAINS:
            return 1, "chain already exists"
        CHAINS[chain] = []
        return 0, ""
    if chain not in CHAINS:
        return 1, "No chain/target/match by that name."
    if op == "-F":
        CHAINS[chain][:] = []
        return 0, ""
    if op == "-A":
        CHAINS[chain].append(" ".join(rest))
        return 0, ""
    if op == "-I":
        pos = 1
        if rest and rest[0].isdigit():
            pos = int(rest[0])
            rest = rest[1:]
        CHAINS[chain].insert(pos - 1, " ".join(rest))
        return 0, ""
    if op == "-C":
        return (0, "") if " ".join(rest) in CHAINS[chain] else (1, "no rule")
    if op == "-D":
        rule = " ".join(rest)
        if rule in CHAINS[chain]:
            CHAINS[chain].remove(rule)
            return 0, ""
        return 1, "not found"
    return 0, ""


def fake_run(cmd, timeout=5):
    if cmd[:2] == ["which", "iptables"]:
        return "/usr/sbin/iptables\n"
    if cmd[:2] == ["iptables", "-S"]:
        chain = cmd[2]
        return ("-P %s ACCEPT\n" % chain
                + "".join("-A %s %s\n" % (chain, r) for r in CHAINS.get(chain, [])))
    return ""


REAL_PORTS_IPT = sw.ports_ipt       # the real one, for the dry-run test below
sw.ports_ipt = fake_ipt
sw.run = fake_run
sw.gate_ifaces = lambda: ["br-lan"]
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

TMP = tempfile.mkdtemp()
sw.PORT_RULES_FILE = os.path.join(TMP, "ports.json")


def reset():
    CHAINS.clear()
    CHAINS.update({"FORWARD": [], "INPUT": []})
    sw.PORT_RULES[:] = []
    sw.PORTS.update({"on": False, "ifaces": [], "dry_run": False})
    try:
        os.remove(sw.PORT_RULES_FILE)
    except OSError:
        pass


print("parse_port_rules:")
P = sw.parse_port_rules
check("single port, both protocols by default",
      P("block(192.168.8.50, 443)") == [("block", "192.168.8.50", 443, 443, "both")])
check("range + udp",
      P("block(192.168.8.50, 6881-6889, udp)") ==
      [("block", "192.168.8.50", 6881, 6889, "udp")])
check("wildcard device", P("block(*, 23)") == [("block", "*", 23, 23, "both")])
check("allow verb", P("allow(192.168.8.50, 80, tcp)") ==
      [("allow", "192.168.8.50", 80, 80, "tcp")])
check("unblock / unallow verbs captured, not 'block' inside 'unblock'",
      [x[0] for x in P("unblock(*, 23) unallow(192.168.8.50, 80)")] ==
      ["unblock", "unallow"])
check("port 0 dropped", P("block(*, 0)") == [])
check("port 70000 dropped", P("block(*, 70000)") == [])
check("backwards range dropped", P("block(*, 90-80)") == [])
check("bad IP dropped", P("block(999.1.1.1, 80)") == [])
check("'any' normalises to both", P("block(*, 53, any)") == [("block", "*", 53, 53, "both")])
check("duplicates collapsed", len(P("block(*, 23) block(*, 23)")) == 1)
check("semicolon separator", P("block(*;23;tcp)") == [("block", "*", 23, 23, "tcp")])
check("rules() regex", bool(sw.RULES_CMD.search("send rules() please")))
check("no false match on prose 'blocked'", P("device BLOCKED (192.168.8.50)") == [])

print("\nrefusals:")
reset()
r = sw.port_rule_cmd("block", "8.8.8.8", 53, 53, "both", NETS)
check("off-LAN refused", "REFUSED" in r and sw.PORT_RULES == [])
r = sw.port_rule_cmd("block", "192.168.8.1", 80, 80, "both", NETS)
check("router refused", "REFUSED" in r)
r = sw.port_rule_cmd("block", "192.168.8.9", 80, 80, "both", NETS)
check("ssh peer refused", "REFUSED" in r)
r = sw.port_rule_cmd("block", "192.168.8.77", 80, 80, "both", NETS)
check("unknown MAC refused", "REFUSED" in r and "no MAC" in r)
check("nothing applied after refusals", "SW_PORTS" not in CHAINS)

print("\nblock builds the right iptables entries:")
reset()
r = sw.port_rule_cmd("block", "192.168.8.50", 443, 443, "both", NETS)
check("announced", r.startswith("*** BLOCK tcp+udp 443 for 192.168.8.50"))
check("undo hint", "unblock(192.168.8.50, 443)" in r)
exp = ["-m mac --mac-source aa:bb:cc:dd:ee:50 -p tcp --dport 443 -j DROP",
       "-m mac --mac-source aa:bb:cc:dd:ee:50 -p udp --dport 443 -j DROP"]
check("tcp + udp DROP by MAC and dport", CHAINS["SW_PORTS"] == exp)
check("hooked at head of FORWARD", CHAINS["FORWARD"] == ["-i br-lan -j SW_PORTS"])
check("persisted", os.path.exists(sw.PORT_RULES_FILE))
r = sw.port_rule_cmd("block", "192.168.8.50", 443, 443, "both", NETS)
check("duplicate skipped", "SKIPPED" in r and len(sw.PORT_RULES) == 1)

r = sw.port_rule_cmd("block", "192.168.8.50", 6881, 6889, "udp", NETS)
check("udp range -> one rule with lo:hi",
      "-m mac --mac-source aa:bb:cc:dd:ee:50 -p udp --dport 6881:6889 -j DROP"
      in CHAINS["SW_PORTS"] and len(CHAINS["SW_PORTS"]) == 3)

r = sw.port_rule_cmd("block", "*", 23, 23, "tcp", NETS)
check("wildcard -> no MAC match", "-p tcp --dport 23 -j DROP" in CHAINS["SW_PORTS"])

print("\nallow is ordered before block and ACCEPTs:")
r = sw.port_rule_cmd("allow", "192.168.8.50", 80, 80, "tcp", NETS)
check("allow announced with ACCEPT caveat", "ACCEPT" in r)
check("allow is first in chain",
      CHAINS["SW_PORTS"][0] ==
      "-m mac --mac-source aa:bb:cc:dd:ee:50 -p tcp --dport 80 -j ACCEPT")
check("blocks follow", all("DROP" in x for x in CHAINS["SW_PORTS"][1:]))
r = sw.port_rule_cmd("block", "192.168.8.50", 80, 80, "both", NETS)
check("block overlapping an allow warns that allows win", "allows win" in r)
check("allow still first after rebuild", CHAINS["SW_PORTS"][0].endswith("-j ACCEPT"))
check("port_allows_for lists the hole",
      sw.port_allows_for("aa:bb:cc:dd:ee:50") == ["tcp 80"])
r = sw.port_rule_cmd("allow", "*", 53, 53, "udp", NETS)
check("wildcard allow listed for any device",
      "udp 53" in sw.port_allows_for("aa:bb:cc:dd:ee:60"))

print("\nunblock / unallow:")
n_before = len(sw.PORT_RULES)
r = sw.port_rule_cmd("unblock", "192.168.8.50", 443, 443, "tcp", NETS)
check("different proto is a different rule -> no such rule",
      "no such rule" in r and len(sw.PORT_RULES) == n_before)
r = sw.port_rule_cmd("unblock", "192.168.8.50", 443, 443, "both", NETS)
check("exact rule removed", "REMOVED" in r and len(sw.PORT_RULES) == n_before - 1)
check("chain rebuilt without it",
      not any("--dport 443 " in x for x in CHAINS["SW_PORTS"]))
r = sw.port_rule_cmd("unallow", "192.168.8.50", 80, 80, "tcp", NETS)
check("unallow removes the hole", "REMOVED" in r and
      sw.port_allows_for("aa:bb:cc:dd:ee:50") == ["udp 53"])

print("\nrestart: rules reload from the file and rebuild the same chain:")
snapshot_rules = [dict(r) for r in sw.PORT_RULES]
snapshot_chain = list(CHAINS["SW_PORTS"])
sw.PORT_RULES[:] = []
CHAINS["SW_PORTS"][:] = []
CHAINS["FORWARD"][:] = []
sw.PORTS.update({"on": False, "ifaces": []})
sw.ports_load()
check("same rules back", [sw._port_rule_key(r) for r in sw.PORT_RULES] ==
      [sw._port_rule_key(r) for r in snapshot_rules])
sw.ports_apply()
check("same chain back", CHAINS["SW_PORTS"] == snapshot_chain)
check("hook back", CHAINS["FORWARD"] == ["-i br-lan -j SW_PORTS"])

print("\nports_load rejects garbage:")
import json
with open(sw.PORT_RULES_FILE, "w") as f:
    json.dump([{"action": "block", "mac": "*", "lo": 23, "hi": 23, "proto": "tcp"},
               {"action": "nuke", "mac": "*", "lo": 1, "hi": 1},
               {"action": "block", "mac": "not-a-mac", "lo": 1, "hi": 1},
               {"action": "block", "mac": "*", "lo": 99, "hi": 1},
               {"action": "block", "mac": "*", "lo": 23, "hi": 23, "proto": "tcp"},
               "junk"], f)
sw.ports_load()
check("one valid, deduped rule survives", len(sw.PORT_RULES) == 1
      and sw.PORT_RULES[0]["mac"] == "*")

print("\nrehook keeps an allow ahead of later drops:")
reset()
sw.port_rule_cmd("allow", "192.168.8.50", 80, 80, "tcp", NETS)
check("initially at front", sw.ports_hook_is_front())
# a close() lands a MAC drop at position 1, in front of our hook
CHAINS["FORWARD"].insert(0, "-m mac --mac-source aa:bb:cc:dd:ee:60 -j DROP")
check("detects it is no longer first", not sw.ports_hook_is_front())
check("rehook moves it", sw.ports_rehook() is True)
check("hook first again, drop second",
      CHAINS["FORWARD"] == ["-i br-lan -j SW_PORTS",
                            "-m mac --mac-source aa:bb:cc:dd:ee:60 -j DROP"])
check("second rehook is a no-op", sw.ports_rehook() is False)
check("exactly one hook, no duplicates", CHAINS["FORWARD"].count("-i br-lan -j SW_PORTS") == 1)

reset()
sw.port_rule_cmd("block", "*", 23, 23, "tcp", NETS)
CHAINS["FORWARD"].insert(0, "-m mac --mac-source aa:bb:cc:dd:ee:60 -j DROP")
check("no allow -> rehook not needed, no-op", sw.ports_rehook() is False)

print("\ntwo LAN interfaces:")
reset()
sw.gate_ifaces = lambda: ["br-lan", "br-guest"]
sw.port_rule_cmd("allow", "*", 53, 53, "udp", NETS)
check("one hook per iface at the head",
      sorted(CHAINS["FORWARD"]) == ["-i br-guest -j SW_PORTS", "-i br-lan -j SW_PORTS"]
      and sw.ports_hook_is_front())
sw.gate_ifaces = lambda: ["br-lan"]

print("\ndry run prints the plan and changes nothing:")
reset()
sw.ports_ipt = REAL_PORTS_IPT       # real function: in dry-run it only prints
sw.PORTS["dry_run"] = True
sw.PORT_RULES.append({"action": "block", "mac": "aa:bb:cc:dd:ee:50",
                      "label": "192.168.8.50", "lo": 443, "hi": 443,
                      "proto": "tcp", "added": 0})
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rep = sw.ports_apply()
out = buf.getvalue()
check("plan shows the DROP",
      "[ports DRY RUN] iptables -A SW_PORTS -m mac --mac-source aa:bb:cc:dd:ee:50 "
      "-p tcp --dport 443 -j DROP" in out)
check("plan shows the hook", "iptables -I FORWARD 1 -i br-lan -j SW_PORTS" in out)
check("report says DRY RUN", "[DRY RUN]" in rep)
check("no real chain created", "SW_PORTS" not in CHAINS)
check("rehook skipped in dry run", sw.ports_rehook() is False)
sw.PORTS["dry_run"] = False
sw.ports_ipt = fake_ipt

print("\nrules() report:")
reset()
sw.port_rule_cmd("block", "192.168.8.50", 443, 443, "tcp", NETS)
sw.port_rule_cmd("allow", "192.168.8.50", 80, 80, "tcp", NETS)
sw.port_rule_cmd("block", "*", 23, 23, "both", NETS)
body = sw.port_rules_body()
lines = [l for l in body.splitlines() if l.startswith(("ALLOW", "BLOCK"))]
check("three rules listed, allow first", len(lines) == 3 and lines[0].startswith("ALLOW"))
check("hostname shown", "192.168.8.50 (phone)" in body)
check("wildcard shown", "* (all devices)" in body)
check("teardown string names the chain", "iptables -X SW_PORTS" in sw.ports_teardown())
empty_body = (sw.PORT_RULES.clear(), sw.port_rules_body())[1]
check("empty report explains how to add", "No port rules" in empty_body)

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
