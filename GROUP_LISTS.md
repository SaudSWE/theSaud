# Group lists → the approval gate (`--group-lists`)

Wires the two MAC text files (`group_lists.py`) into StreamWatch's approval
gate on the **gateway node**, so the files actually control traffic (SRS
`Group.Lists`, `Group.Gate`, `Group.Approve`, `Control.Persist`).

## The three states (Model A, block beats allow — BR-2)

| On which list | Internet | Enforcement |
|---|---|---|
| **allow.txt** (and not deny) | ✅ | gate `RETURN` — traffic forwarded |
| **deny.txt** | ❌ nothing | blocked by MAC (INPUT + FORWARD drop + wifi ban) |
| **neither** | ❌ | held at the approval gate (gets an address + DNS, no internet) |

A MAC on both files is **denied** (BR-2). The **router** and the **SSH peer**
are never denied, even if hand-listed — the gate is FORWARD-only so your SSH
session always survives, and deny-enforcement skips the peer's MAC.

## Running it (on the gateway `main123`, as root)

```sh
python3 streamwatch_v12.py --email-alert --email-to you@example.com \
    --accept-commands --group-lists
# default files: /etc/streamwatch/allow.txt and deny.txt
# override with --allow-file / --deny-file
```

At start it seeds the gate from `allow.txt` (minus anything on `deny.txt`) and
blocks every MAC on `deny.txt`. If the allow list is empty and nothing else is
always-open, it **refuses to install** the gate (it would drop every device,
including yours) and tells you to add your admin device first.

## Managing membership

Two ways, and they stay in sync because the files are the single store:

**By email command** (persists across restart automatically):
- `open(192.168.8.50)` → unblock + **allow-list** the device (internet on)
- `close(192.168.8.50)` → **deny-list** + block the device entirely

**By editing the files** (with `group_lists.py` or by hand) — picked up live,
no restart, no email needed:
```sh
python3 group_lists.py allow add 192.168.8.50     # on the gateway, resolves MAC
python3 group_lists.py deny  add 192.168.8.60
```
StreamWatch notices the file change on its next poll and reconciles: grants
newly-allowed devices, blocks newly-denied ones, frees ones you removed from
deny. Every change is logged to the console.

## Testing on the gateway

1. **Start** with `--group-lists` and one known device (your laptop) in
   `allow.txt`. Confirm the laptop has internet and a brand-new phone (on
   neither list) gets an IP but **no internet**.
2. `open(phone-ip)` by email → within a poll the phone gets internet, and its
   MAC appears in `allow.txt`.
3. `close(phone-ip)` → phone loses internet entirely, MAC moves to `deny.txt`.
4. **Hand-edit test:** `python3 group_lists.py deny add <laptop-ip>` on the
   gateway, wait one poll → the laptop is cut, and the console prints
   `[group] reload: block aa:bb:...`. Remove it again → restored.
5. **Restart** StreamWatch → the allow/deny decisions are re-applied from the
   files (`Control.Persist`, ROB-3).
6. **Lockout safety:** try `close(<the gateway's own IP>)` and
   `close(<your SSH client IP>)` — both are refused.

Off-router, the logic is covered by `tests/test_group_gate.py` (28 checks:
startup seeding, close/open, hand-edit reload, BR-2 precedence, peer safety)
and `tests/test_group_lists.py` (the file manager, 26 checks).

## Notes / limits
- Enforcement lives on the **gateway** (CON-7), which is where the real DHCP
  leases and firewall are — not on the companion Pi.
- MAC-based, so a cloned MAC defeats it; it enforces a policy on cooperating
  devices, it is not a defence against a forged MAC.
- iptables rules don't survive a reboot; the gate prints its teardown command.
  The allow/deny **files** do survive, and are re-applied when StreamWatch
  starts.
- Direct file edits over SSH are attributed only to the root login, not to a
  named user (a known `Control.Log` / SEC-5 gap tracked in the SRS).
