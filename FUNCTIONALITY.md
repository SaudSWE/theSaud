# StreamWatch — Functionality Reference

Every function the system has, what it does, how to use it, and where it runs.
To check each one yourself, follow **`TESTING.md`** — the test IDs (e.g. `G3`)
match the sections below.

Where things run:

| Box | Address | Runs |
|-----|---------|------|
| Gateway **main123** (GL-MT3000, OpenWrt) | 192.168.8.1 | `streamwatch_v12.py` (procd service `streamwatch`), `group_lists.py` |
| Nodes **acf**, **456** | 192.168.8.2 / .3 | Wi-Fi only; read by the recorder over SSH |
| Raspberry Pi | 192.168.8.162 | `mesh_tracker.py`, `mesh_recorder.py` (service `mesh-recorder`), all analysis tools, `report-mailer.timer` |

StreamWatch's options are set in `/etc/streamwatch/streamwatch.conf` on the
gateway (`SW_EMAIL_TO`, `SW_THRESHOLD`, `SW_EXTRA`), then
`/etc/init.d/streamwatch restart`. The flags below go in `SW_EXTRA`.

---

## The nine functions

The system's functions, what delivers each one, and where it's described.
"Pi only" means the code or configuration lives on the Pi or the routers and
is **not in this repository** — push it to get it documented and tested in full.

| # | Function | Delivered by | In repo | Reference | Tests |
|---|----------|--------------|---------|-----------|-------|
| 1 | **Device approval** — internet only for approved devices | gateway gate + allow/deny lists | yes | G3, G4, L | G3, G4, G4b, G4c, L1, L2 |
| 2 | **Data monitoring** — per-device usage, 500 MB alerts, data caps | metering + `SW_THRESHOLD="500M"`, `limit()`, `throttle()`, device report | yes | G1, G6, G9, A1 | G1, G6a, G6b, G9, A1 |
| 3 | **Email remote control** — close, open, limit, throttle, block, devices, browsing, locate, zones, calibrate | gateway email command channel | yes | G2 (table) | G2, G3, G5, G6a, G6b, G10, G11, G13, G14, G15 |
| 4 | **Location tracking** — live positions, map, events, steering | `mesh_tracker.py` + live map (Pi only); gateway location and forbidden area; recorder events | partly | F4, G12–G15, R | M1–M4, G12–G15 |
| 5 | **Recording** — everything into a daily CSV | `mesh_recorder.py` (`mesh-recorder` unit: Pi only) | yes | R | R1–R4 |
| 6 | **Nightly report** — per-device daily summary email | `report_mailer.py` on a nightly schedule (schedule: Pi only) | partly | F6, A7 | N1, A7, S3 |
| 7 | **Mesh network** — three routers, one network, seamless roaming | 802.11s on the GL-MT3000s (router config) + tracker steering | config | F7 | W1–W3 |
| 8 | **Remote access** — router terminal and map from anywhere, behind Google sign-in | ngrok + Google login on the Pi (Pi only) | no | F8 | X1–X3 |
| 9 | **Safety and upkeep** — safe deploys with rollback, Pi firewall, automated tests | tests in `tests/` (yes); deploy/rollback and firewall (Pi only) | partly | F9, S, T | U1–U2, S1–S2, T |

### F4. Location tracking (tracker and map on the Pi)
From the system description in the recorder's data dictionary:
- `mesh_tracker.py` estimates each device's position from Wi-Fi signal at the
  router it's connected to (`d = 10^((A − RSSI)/(10 n))`, per-station A and n
  from calibration) plus a particle filter — expect metres of error.
- **Events:** ARRIVED, LEFT, HANDOVER (moved to another router), STEER,
  APPROACHING, LEAVING, IDLE — recorded as `tracker_event` rows; positions as
  `device_position` rows every ~10 s.
- **Steering:** phones are sticky, so when the signal drops below −70 dBm the
  tracker briefly disconnects the phone so it rejoins the closest router.
- **Live map:** served by the Pi on port 8090.
- The gateway also traces location itself (G14) and enforces the forbidden area (G15).

### F6. Nightly report
`report_mailer.py` builds the per-device summary (device report + Eagle-Eye
scan) and emails it; `--hours 24` makes it a daily summary. The repo's timer
runs it every 5 min — a nightly run needs `OnCalendar=daily` (or a set time) in
the installed timer on the Pi.

### F7. Mesh network
Three GL-MT3000 routers on OpenWrt 24.10 in an 802.11s mesh: main123 (L1,
gateway: internet, DHCP, firewall), acf (L2) and 456 (L3) as mesh nodes —
one network name everywhere. Roaming is helped by the tracker's steering.
Configured on the routers; the recorder logs mesh health as `mesh_link` rows.

### F8. Remote access
The live map (Pi, port 8090) is published through **ngrok behind Google
login**, so it can be opened from anywhere by approved Google accounts. The
router terminal is published the same way. Configuration lives on the Pi.

### F9. Safety and upkeep
- **Automated tests:** 14 suites in `tests/`, stdlib only.
- **Self-healing gateway:** StreamWatch restarts on boot and respawns if it
  exits; the gate re-applies itself after a firewall reload; detection is
  immune to boot-time clock corrections.
- **Safe deploys with rollback** and the **Pi firewall:** configured on the Pi,
  not in this repository.

---

## G — Gateway: `streamwatch_v12.py`

### G1. Traffic metering and threshold alerts
Measures every LAN device's data through the gateway (conntrack) and emails
when a device's running total crosses the threshold.
- `--threshold 500M` (K/M/G), `--direction in|out|total`, `--interval 10`
- `--email-alert --email-to ADDR`, `--smtp-server`, `--smtp-port`
- `--alert-repeat 600` — quiet period per device after an alert
- `--table-every N` — print the usage table every N polls; `--csv PATH` — log totals
- `--lan-net 192.168.8.0/24` — override LAN detection
- Email subject: `[streamwatch] <ip> (<name>) data usage crossed <size>`

### G2. Email command channel
Polls the inbox and runs commands found in an email's first line. Only senders
on the allowed list are obeyed; old or refused commands are logged, not run.
- `--accept-commands` (needs `--email-alert`), `--command-from ADDR`
  (repeatable; default `--email-to`), `--command-poll 15`
- `--include-latest-email`, `--threshold-from-email`, `--latest-wait`, `--imap-server`

| Command | Effect |
|---------|--------|
| `close(ip)` | Cut the device (deny-lists it under `--group-lists`) |
| `open(ip)` | Restore / approve the device (allow-lists it under `--group-lists`) |
| `limit(ip, 500MB[, daily\|weekly\|monthly])` | Data quota; blocks when used up |
| `unlimit(ip)` | Remove the quota |
| `throttle(ip, 2mbit[, 1mbit])` | Speed cap (download[, upload]) |
| `unthrottle(ip)` | Remove the cap |
| `block(ip\|*, port[-port][, tcp\|udp])` | Block a port for a device or everyone |
| `allow(ip\|*, port…)` / `unblock(…)` / `unallow(…)` | Allow / remove port rules |
| `rules()` | Email back the port rules |
| `devices()` | Email back the device registry |
| `browsing([ip])` | Email back the domains looked up |
| `locate([ip])` | Email back where devices are |
| `zones()` | Email back the forbidden-area status |
| `forbid(5)` / `forbid(-55)` | Turn on the forbidden area (metres / dBm) |
| `unforbid()` | Turn it off, restore everyone it cut |
| `calibrate(ip[, metres])` | Record a distance calibration point |

### G3. Close / open a device
- `--close-mode full` (firewall drop + deauth + re-association ban) or `forward`
  (routed traffic only; stays connected). `--close-dry-run` prints instead of acting.

### G4. Approval gate (default-deny)
Every device is blocked from the internet unless approved.
- **Group lists** (`--group-lists`): `/etc/streamwatch/allow.txt` = internet,
  `/etc/streamwatch/deny.txt` = fully blocked, on neither = **held**. Deny beats
  allow. Lists are keyed on MAC, reload live, persist across reboot, and the
  gate self-heals after a firewall reload. `--allow-file`, `--deny-file`.
- **Always-open** (`--always-open IP`, `--always-open-file PATH`): devices that
  can never be closed.
- `--gate-dry-run` prints the plan. `/etc/init.d/streamwatch gate_down` removes
  the gate (opens the LAN) on purpose — stopping the service does not.

### G5. Per-port rules
`block(...)`, `allow(...)`, `unblock(...)`, `unallow(...)`, `rules()` by email.
Block always beats allow. Saved and re-applied after restart. `--ports-dry-run`.

### G6. Data quotas and speed throttling
`limit` / `unlimit` (blocks the device when its quota is used, resets per period)
and `throttle` / `unthrottle` (tc HTB caps) by email.

### G7. Malfunction detection (on by default)
- **Internet outage:** checks 1.1.1.1:443 and 8.8.8.8:53 every `--detect-every 10`
  s; DOWN after `--detect-fails 3` misses, dated from the first miss. Email on
  recovery with cut time, restore time, duration (retried if sending fails).
- **Device not connected:** allow-listed devices (and `--watch-device`) unseen
  for `--missing-after 300` s → alert; "device back" when seen again.
- Immune to the router's clock being corrected at boot. `--no-detect` turns it off.
- Logged to `/root/.streamwatch_health.log` → `malfunction` rows in the AI CSV.

### G8. Speed report
`--speed-report` measures the link on a timer and emails it. `--speed-every`,
`--speed-bytes`, `--speed-url`, `--speed-latency-only` (cheap), `--speed-email-every`,
`--speed-csv`, `--speed-no-geo`.

### G9. Usage report
`--usage-report` emails a roll-up of every device (data, signal, distance) every
`--usage-every 3600` s.

### G10. Browsing (DNS) watch
`--dns-watch` follows dnsmasq's query log per device (turns logging on).
`browsing([ip])` by email; `--dns-report` / `--dns-every` email a summary.

### G11. Device registry
`--track-devices` keeps every device ever seen (MAC, vendor, names, IPs, first
seen) and emails `[streamwatch] new device: …`. Query with `devices()`.

### G12. Signal movement alerts
`--rssi-track` emails when a device starts approaching, moving away, or goes
idle. `--rssi-every 5`, `--rssi-window 60`, `--rssi-delta 5`, `--rssi-cooldown 180`.

### G13. Distance calibration
Turns signal (dBm) into a distance range with a path-loss model.
- `--calibrate IP --at METRES` (one point), `--calibrate-wizard IP`
  (`--calibrate-points 3`, guided), `--calibrate-status`, `--calibrate-reset IP`
- `--rssi-ref` (A, dBm at 1 m), `--rssi-exponent` (n), `--prefer-per-device`,
  `--rssi-calib-file /root/rssi_calibration.txt` (re-read when it changes)
- Stored in `/root/.streamwatch_calibration.json`; `calibrate(ip)` by email.

### G14. Location tracing
`--track-location` samples each device's radio and estimated distance every
`--location-every 8` s. `--anchor 'iface=wlan0;name=Lab;x=10;y=4'` pins radios to
coordinates. `--location-csv`, `--location-quiet`. Query with `locate([ip])`.

### G15. Forbidden area
Cuts internet for a device inside the zone; restores it when it leaves.
- `--forbidden-rssi -55` (signal, recommended) or `--forbidden-radius METRES`
- `--forbidden-iface`, `--forbidden-applies unauthorized|all`, `--forbidden-exempt`,
  `--forbidden-margin 0.35`, `--forbidden-enter 2`, `--forbidden-exit 3`,
  `--forbidden-cooldown 60`, `--forbidden-dry-run`
- `forbid(…)`, `unforbid()`, `zones()` by email.

---

## L — Lists admin: `group_lists.py` (gateway)

| Command | Effect |
|---------|--------|
| `group_lists.py allow add <ip\|mac>` | Add to the allow list (IP resolved to MAC; unknown devices refused) |
| `group_lists.py allow remove <ip\|mac>` | Remove |
| `group_lists.py allow list` | Show |
| `group_lists.py deny add\|remove\|list …` | Same for the deny list |
| `group_lists.py allow check <ip\|mac>` | `yes` / `no` |
| `group_lists.py classify <ip\|mac>` | `allow` / `deny` / `hold` |

---

## R — Recorder: `mesh_recorder.py` (Pi)

Pulls every node over SSH and writes **one AI CSV per day** to
`~/mesh_records/records_YYYY-MM-DD.csv` (finished days gzipped). 54 columns,
24 record types; every row has `timestamp`, `date`, `time`, `epoch`.

| Subcommand | Effect |
|------------|--------|
| `mesh_recorder.py` (or `run`) | Record continuously (the `mesh-recorder` service) |
| `dictionary` | Write `DATA_DICTIONARY.md` + `data_dictionary.csv` |
| `note "text"` | Add a `change_log` row (e.g. "moved 456") |
| `export --from "…" --to "…" [--types a,b] [-o file]` | Slice of the records |
| `import-history` | Convert the tracker's past logs into records |

Flags: `--out`, `--interval`, `--health`, `--no-dns` (skip browsing),
`--all-logs` (keep kernel info lines), `--lan-prefix`, `--verbose`.

**Record types:** `station_config`, `device_position`, `tracker_event`,
`wifi_station`, `mesh_link`, `device_traffic`, `flow_end`, `flow_active`,
`router_health`, `internet_latency`, `router_log`, `dns_query`, `dhcp_lease`,
`sw_usage`, `sw_quota`, `sw_throttle`, `malfunction`, `email`,
`internet_access`, `device_inventory`, `open_port`, `calibration_point`,
`change_log`, `recorder`. Full definitions in `~/mesh_records/DATA_DICTIONARY.md`.

**Tracker** (`mesh_tracker.py`, Pi) produces `device_position` and
`tracker_event` (ARRIVED, LEFT, HANDOVER, STEER, APPROACHING, LEAVING, IDLE).
It is **not in this repository** — it lives only on the Pi.

---

## A — Analysis & model (Pi, offline, read the AI CSV)

### A1. `device_report.py` — per-device report
Online time and sessions (incl. the APs' own connect/disconnect events), data,
peak rate, browsing, biggest/large flows, access state, nodes, not-connected
count, `new_device`, `flap_burst`. Sorted longest-online first.
`[device]`, `--hours 24`, `--csv FILE` (feature table), `--flap-seconds 120`,
`--all-devices`, `--dir`.

### A2. `history.py` — activity timeline
Meaningful events in time order. `[device…]`, `--browsing`, `--all`, `--dir`.

### A3. `eagle_eye.py` — Eagle-Eye (EE1) cross-device model
Reads the feature table; robust median/MAD scores, high side only; `!! ANOMALY`
with reasons. **Threat rules:** 2+ fast in/outs within 10 min, or a new device
logging in and out fast → `!! THREAT`. `[features.csv]`, `--threshold 4`, `--json`.
(Formerly `anomaly_model.py`.)

### A4. `trend_model.py` — each device vs its own history
Daily features per device; flags the latest day when it breaks the device's
own normal (`!! ABNORMAL for this device`). `--min-days 3`, `--threshold`, `--json`.

### A5. `threats.py` — fast log in/out and unknown entrances
`!! POTENTIAL THREAT` for flapping (`--min-flaps 2`) or a device held at the
gate; recent arrivals noted (`--hours 24`). `--json`.
*Overlaps Eagle-Eye's threat rules — see `handoff.md`.*

### A6. `ask.py` — offline terminal
Interactive (`ask.py`) or one command (`ask.py online`). Commands: `help`,
`online`, `data`, `browsing`, `device`, `anomalies`, `flagged`, `trend`,
`threats`, `history`, `email [all]`, `window <hours|all>`, `reload`, `quit`.
A device is any part of an IP, MAC or name.

### A7. `report_mailer.py` — emailed reports
Builds the device report + Eagle-Eye scan and emails it.
`--dry-run`, `--only-flagged`, `--to`, `--threshold`, `--hours 24`, `--env`
(creds file `~/.streamwatch_env`: `EMAIL_USER`, `EMAIL_PASS`, `EMAIL_TO`).
Scheduled by `systemd/report-mailer.timer` (repo default: every 5 min, every run).

---

## S — Services

| Unit | Box | Purpose |
|------|-----|---------|
| `openwrt/streamwatch.init` → `/etc/init.d/streamwatch` | gateway | starts on boot, respawns; `gate_down` action |
| `openwrt/streamwatch.conf` → `/etc/streamwatch/streamwatch.conf` | gateway | email, threshold, extra flags |
| `mesh-recorder` (systemd) | Pi | the recorder (unit file lives on the Pi) |
| `mesh-tracker` (systemd) | Pi | the tracker (unit file lives on the Pi) |
| `systemd/report-mailer.service` + `.timer` | Pi | scheduled report email |
| NTP (router: Google time servers; Pi syncs from router) | both | correct timestamps after reboot |

## T — Automated tests
14 suites in `tests/` (stdlib only):
`for t in tests/test_*.py; do python3 $t; done`
