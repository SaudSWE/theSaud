# Continuous location tracing + forbidden area

Added to `streamwatch_v12.py`. Both features build on the per-device Wi-Fi
signal the tool already samples (`iwinfo ... assoclist`), so they need no new
hardware and no network traffic.

This is **location-based access control on a network you operate** — the same
idea as corporate Wi-Fi geofencing. It is coarse by physics (see *Limitations*)
and MAC-based, so it enforces a policy on cooperating devices; it is not covert
tracking and is not a defence against a forged MAC. Where people are subject to
it, tell them.

---

## 1. Continuous location trace

Every few seconds, for each **associated** wireless device, the tool records:

* which mesh radio it is on (`wlan0`, `wlan1`, …),
* its estimated distance from that radio (a **range**, from the path-loss
  model), and
* optionally a coarse `(x, y)` if you pin radios to positions with `--anchor`.

A rolling history is kept per device and can be mailed back on demand.

```sh
# Trace continuously; print a line only when a device's location changes.
python3 streamwatch_v12.py --track-location --location-every 8

# Log every sample to CSV as well, and pin two radios to coordinates.
python3 streamwatch_v12.py --track-location --location-csv /root/loc.csv \
    --anchor "iface=wlan0;name=Front;x=0;y=0" \
    --anchor "iface=wlan1;name=Lab;x=12;y=4"
```

Query by email (needs `--email-alert --accept-commands`):

| command              | effect                                            |
|----------------------|---------------------------------------------------|
| `locate(192.168.8.50)` | current location of one device                  |
| `locate()`           | current location of every associated device       |

---

## 2. Forbidden area

A proximity zone around the mesh (or one radio). A device **confirmed inside**
it loses internet; a device **confirmed back outside** gets it back.
Enforcement drops the device's **forwarded** traffic by MAC — no internet, no
cross-subnet — while leaving it associated to the radio, which is exactly what
lets the tool see it leave and restore access.

```sh
# Cut internet for any device estimated within 5 m of the mesh, restore outside.
python3 streamwatch_v12.py --email-alert --email-to you@example.com \
    --accept-commands --forbidden-radius 5

# More dependable boundary: define it by signal, not metres (no wall error).
python3 streamwatch_v12.py ... --forbidden-rssi -55

# Scope the area to one access point, and apply it to everyone.
python3 streamwatch_v12.py ... --forbidden-rssi -55 \
    --forbidden-iface wlan1 --forbidden-applies all
```

Key options:

| option                         | meaning                                               |
|--------------------------------|-------------------------------------------------------|
| `--forbidden-radius METRES`    | inside when the distance estimate ≤ this              |
| `--forbidden-rssi DBM`         | inside when signal ≥ this (preferred; overrides radius)|
| `--forbidden-iface NAME`       | restrict the zone to one radio's coverage             |
| `--forbidden-applies`          | `unauthorized` (default, authorised list exempt) / `all` |
| `--forbidden-exempt IP|MAC`    | a device the area never cuts (repeatable)             |
| `--forbidden-margin FRAC`      | exit hysteresis in metre mode (default 0.35)          |
| `--forbidden-enter N`          | inside samples before cutting (default 2)             |
| `--forbidden-exit N`           | outside samples before restoring (default 3)          |
| `--forbidden-cooldown SEC`     | min seconds between emails per device (default 60)    |
| `--forbidden-dry-run`          | print the iptables plan instead of running it         |

Runtime control by email:

| command        | effect                                                        |
|----------------|---------------------------------------------------------------|
| `forbid(5)`    | set a 5 m radius and turn the area on                          |
| `forbid(-55)`  | set a −55 dBm signal threshold (negative ⇒ dBm, positive ⇒ m)  |
| `unforbid()`   | turn the area off and restore everyone it had cut             |
| `zones()`      | email the current rule and who is inside / cut                 |

**Who is never cut:** the router, the SSH peer administering it, off-LAN hosts,
anything on `--forbidden-exempt`, and (unless `--forbidden-applies all`) the
authorised / `--always-open` list. This is whiteboard item 6 — *authorised
group exempt, everyone else is subject to the area.*

### Why entry/exit is confirmed over several samples

RSSI swings several dB at rest and distance is a wide range, not a point.
Toggling internet on every boundary crossing would flap the connection. Entry
needs `--forbidden-enter` consecutive inside samples; exit needs
`--forbidden-exit` samples clear of the radius **by a margin**; between the two
is a dead band the device holds in. Same philosophy as the movement tracker.

---

## Limitations (read before relying on the boundary)

* Distance is **modelled from signal, not measured**. A 6 dB swing is ~2.5× in
  distance; one wall costs ~15 dB, so a device just behind a wall reads as far
  away. Calibrate (`calibrate(x.x.x.x)`) or use `--forbidden-rssi` where the
  edge must be dependable.
* True `(x, y)` needs trilateration from ≥3 simultaneous anchors; a station
  associates to one radio at a time, so the trace is *radio + distance* (plus an
  anchor label if configured), not GPS.
* Wired devices have no signal, so they cannot be located or enforced.
* MAC-based, so a cloned MAC defeats it. iptables rules do not survive a reboot;
  `zones()` / startup print the exact teardown command.

---

## Requirement coverage (whiteboard)

This change delivers **5, 7, 11** and reinforces **6**. Full map of what the
script now covers:

| # | Requirement                         | Status | Where |
|---|-------------------------------------|--------|-------|
| 1 | All IP – MAC – port                 | met    | conntrack (IP+ports), ARP/leases/registry (MAC) |
| 2 | Traffic / consumption / speed       | met    | `Meter`, `--speed-report` |
| 3 | Date – time                         | met    | timestamps in every report/CSV |
| 4 | Browsing site address history       | met    | `--dns-watch`, `browsing()` |
| 5 | Location by dB signal + coordinates | **met**| this change: trace + `--anchor` |
| 6 | Authorised group vs. target         | met    | `--always-open` gate; forbidden-area exemption |
| 7 | Device tracing                      | **met**| movement tracker + continuous trace |
| 8 | Control: bandwidth / block / allow  | partial| `throttle()` ✓, `close()`/`open()`/gate ✓ **by IP/MAC, not port** |
| 9 | Detect malfunction / no internet    | partial| speed probe flags a dead/degraded link; connected-device detection |
| 10| IoT sensor on/off switch            | not met| `close()`/`open()` toggles any device's connectivity, but no sensor telemetry |
| 11| Forbidden area                      | **met**| this change |
| 12| Attack admin …                      | not done | offensive capability — out of scope |

---

## Security note on credentials

The mailbox login is intentionally **blank in source** (`EMBEDDED_EMAIL_USER` /
`EMBEDDED_EMAIL_PASS`). Supply it at runtime via environment variables or
`/root/.streamwatch_env` (chmod 600), both already read by `load_credentials()`.
If you ran an earlier build with a password hard-coded, treat it as compromised
and rotate it (Gmail: revoke the App Password).
