# Per-port block / allow rules (requirement #8)

Added to `streamwatch_v12.py`. `close()`/`open()` and the gate decide whether a
*device* may use the internet at all; the forbidden area decides it by
location. These rules add the missing granularity: **this device, but not this
port.**

---

## Commands (by email, needs `--email-alert --accept-commands`)

| command | effect |
|---|---|
| `block(192.168.8.50, 443)` | the device can't reach port 443 anywhere (tcp and udp) |
| `block(192.168.8.50, 6881-6889, udp)` | a port range, one protocol |
| `block(*, 23)` | every device loses port 23 (Telnet) |
| `allow(192.168.8.50, 80)` | the device may use port 80 even if it is otherwise shut |
| `allow(*, 53)` | every device keeps DNS, whatever else is blocked |
| `unblock(...)` / `unallow(...)` | remove a rule — same shape as the rule you added |
| `rules()` | email the current rule list |

Protocol is optional: `tcp`, `udp`, or `both` (the default; `any` also works).
Ports must be 1–65535 and a range must run low→high; anything else is dropped
rather than guessed at, like a malformed `limit()`.

**Refused automatically** (same refusals as `close()`): the router itself, the
SSH peer administering it, any address off the LAN, and a device with no known
MAC.

---

## Exactly what a rule means

* **Destination port, device as source.** `block(x, 443)` = *x may not reach
  port 443 on any far-end host*. The far-end port is the one that names a
  service.
* **Keyed on MAC.** A device that gets a new DHCP lease is still covered.
* **Forwarded traffic only.** Ports on the router itself (its SSH, its web UI)
  are not touched.
* **Allows win.** The chain is `allow` rules first (ACCEPT), then `block` rules
  (DROP). An allow is judged before the gate, the forbidden area, a
  forward-mode `close()` and every block, for that device and port. It cannot
  help a device that a full-mode `close()` has deauthenticated — there is no
  link for any port to travel over. The tool tells you when a block you add
  overlaps an allow, and when a device the forbidden area cuts still has an
  allow hole.
* **Persisted.** Rules live in `/root/.streamwatch_ports.json` and are
  re-applied at startup. The live chain is rebuilt from that list on every
  change, so the two cannot drift apart.

### The `rules()` email

```
streamwatch - port rules

Generated: 2026-10-05 12:10:03
Rules    : 4  (applied)

ALLOW  192.168.8.50 (phone)             tcp 80             added 2026-10-05 12:10
BLOCK  * (all devices)                  tcp+udp 23         added 2026-10-05 12:08
BLOCK  192.168.8.50 (phone)             tcp 443            added 2026-10-05 12:04
BLOCK  192.168.8.60 (laptop)            udp 6881-6889      added 2026-10-05 12:06

Allow rules are checked first; a matching allow beats any block, ...
```

---

## How it is built (for the curious)

One iptables chain, `SW_PORTS`, hooked at the head of `FORWARD` on each LAN
interface:

```
SW_PORTS:  ACCEPT  --mac-source <mac>  -p tcp --dport 80      <- allow(x, 80)
           ACCEPT                      -p udp --dport 53      <- allow(*, 53)
           DROP    --mac-source <mac>  -p tcp --dport 443     <- block(x, 443)
           DROP    --mac-source <mac>  -p udp --dport 443
           DROP                        -p tcp --dport 23      <- block(*, 23)
           (fall through: nothing here applies)
```

`close()`, the gate and the forbidden area all insert at the head of `FORWARD`
too, so after any of them fires the port chain could end up *behind* a drop —
and an allow only works in front of every drop. The poll loop and the command
thread therefore check the head of `FORWARD` and move the chain back when
needed (only while an allow exists; a block drops wherever it sits).

Remove everything with the teardown command printed at startup, or
`iptables -F SW_PORTS; iptables -X SW_PORTS` after deleting the jumps.

---

## Testing — three stages

### Stage 1 — logic tests, no router (run anywhere)

```sh
python3 tests/test_port_rules.py
python3 tests/test_forbidden_area.py
```

The iptables layer is replaced by a stateful fake. The suite checks the rules
that get built and their order, every refusal, duplicate handling, exact
removal, reload after a restart, that garbage in the rules file is rejected,
that an allow is moved back to the head of `FORWARD` after a later `close()`,
two-interface hooking, the dry-run plan, and the `rules()` report.

### Stage 2 — dry run on the router (nothing changes)

```sh
python3 streamwatch_v12.py --email-alert --email-to you@example.com \
    --accept-commands --ports-dry-run
```

Email `block(phone-ip, 443)`. The script prints the iptables commands it
*would* run and saves the rule, but touches nothing. Read the plan; when it
matches what you expect, restart without `--ports-dry-run` and the saved rule
is applied for real.

### Stage 3 — live, with a phone and a laptop

| step | you do | you should see |
|---|---|---|
| 1 | on the phone open https://example.com | loads |
| 2 | email `block(phone-ip, 443)` | within ~15 s HTTPS sites stop loading on the phone |
| 3 | on the phone open http://neverssl.com | still loads — port 80 is not blocked |
| 4 | on the laptop open https://example.com | still loads — rule is per device |
| 5 | email `rules()` | the email lists the block |
| 6 | email `unblock(phone-ip, 443)` | HTTPS works again on the phone |
| 7 | start with `--always-open laptop-ip` (phone now gated), email `allow(phone-ip, 80)` | phone loads http://neverssl.com and nothing else |

On the router, `iptables -L SW_PORTS -n -v` shows the live rules; the `pkts`
column on a block rule climbs each time it drops something.

Step 7 uses the gate rather than `close()` on purpose: a full-mode `close()`
deauthenticates the phone, and no allow can help a device with no link. With
`--close-mode forward` the same allow-through-`close()` test works.
