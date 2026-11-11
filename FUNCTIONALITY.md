# StreamWatch — Functionality Reference

Every function the system has, what it does, how to use it, and where it runs.
To check each one yourself, follow **`TESTING.md`** — the test IDs (e.g. `G3`)
match the sections below.

Where things run:

| Box | Address | Runs |
|-----|---------|------|
| Gateway **main123** (GL-MT3000, OpenWrt) | 192.168.8.1 | `streamwatch_v12.py` (procd service `streamwatch`), `group_lists.py` |
| Nodes **acf**, **456** | 192.168.8.2 / .3 | Wi-Fi only; read by the recorder over SSH |
| Raspberry Pi | 192.168.8.162 | tracker + map, recorder, nightly report, ngrok portal, ttyd, firewall (deployed from `~/streamwatch-live`); analysis tools in `~/theSaud` |

StreamWatch's options are set in `/etc/streamwatch/streamwatch.conf` on the
gateway (`SW_EMAIL_TO`, `SW_THRESHOLD`, `SW_EXTRA`), then
`/etc/init.d/streamwatch restart`. The flags below go in `SW_EXTRA`.

---

## The nine functions

**Where the code lives.** The deployed system runs from the private repository
**`SaudSWE/Manarat-Cyber`** (checked out on the Pi at `~/streamwatch-live`).
This repository (`theSaud`) holds earlier copies of the gateway and recorder
plus offline analysis tools (section A) that are **not deployed**. Facts about
the tracker, map, nightly report, remote access, deploys and firewall were
verified on the Pi on 2026-11-11 (deployed commit `24b293a`). Sections G, L and
R below are written from this repository's copies, which can differ slightly
from the deployed ones.

| # | Function | Delivered by | Code lives in | Reference | Tests |
|---|----------|--------------|---------------|-----------|-------|
| 1 | **Device approval** — internet only for approved devices | gateway gate + allow/deny lists | Manarat-Cyber (copy here) | G3, G4, L | G3, G4, G4b, G4c, L1, L2 |
| 2 | **Data monitoring** — per-device usage, 500 MB alerts, data caps | gateway metering, `SW_THRESHOLD="500M"`, `limit()`, `throttle()` | Manarat-Cyber (copy here) | G1, G6, G9 | G1, G6a, G6b, G9 |
| 3 | **Email remote control** — close, open, limit, throttle, block, devices, browsing, locate, zones, calibrate | gateway email command channel | Manarat-Cyber (copy here) | G2 (table) | G2, G3, G5, G6a, G6b, G10, G11, G13, G14 |
| 4 | **Location tracking** — live positions, map, events, steering | `mesh_tracker.py` + live map; gateway location tracing; recorder | Manarat-Cyber | F4, G12–G14, R | M1–M4, G12–G14 |
| 5 | **Recording** — everything into a daily CSV | `mesh_recorder.py` (`mesh-recorder.service`) | Manarat-Cyber (copy here) | R | R1–R4 |
| 6 | **Nightly report** — per-device daily summary email | `nightly_report.py` (`streamwatch-report.timer`, 00:15) | Manarat-Cyber | F6 | N1, N2 |
| 7 | **Mesh network** — three routers, one network, roaming | 802.11s on the three GL-MT3000s + tracker steering | router config | F7 | W1–W3 |
| 8 | **Remote access** — router terminal and map from anywhere, behind Google sign-in | ngrok + Google sign-in, ttyd | Pi config | F8 | X1–X3 |
| 9 | **Safety and upkeep** — safe deploys with rollback, Pi firewall, automated tests | `deploy.sh`, `deploy-router.sh`, nftables, tests | Manarat-Cyber | F9, S, T | U1–U3, S1–S2, T |

### F4. Location tracking (tracker and map)
- **Position:** `mesh_tracker.py` (service `mesh-tracker`) polls every 2 s and
  estimates each device's distance from the router it's connected to with
  `d = 10^((A − RSSI)/(10 n))`, then smooths it with a 300-particle filter.
  Expect metres of error.
- **Calibration:** per-router A and n are fitted from points marked on the map
  and stored in `~/mesh_calibration.json` on the Pi, with indoor fingerprints
  and surveyed router positions.
- **States:** NEW, SETTLING, IDLE, APPROACHING Lx, LEAVING Lx, GONE.
- **Events:** ARRIVED, HANDOVER (moved to another router, after 2 polls), LEFT
  (unseen 30 s), STEER. Saved in `~/mesh_tracker/tracker_events.csv` and
  recorded as `tracker_event` rows; positions as `device_position` rows.
- **Steering:** when a phone's signal is below −75 dBm, or it is further than its
  router's zone radius plus 2 m, for 3 polls in a row, the tracker disconnects it
  from that router and bans it there for 8 s, so it rejoins a closer one
  (20 s cooldown). It skips devices heard by two or more routers, devices marked
  indoor, the phone being calibrated, and cases where no other router is at
  least 3 dB stronger. It never kicks the Pi.
- **Live map:** `http://192.168.8.162:8090/mesh_map.html` on the LAN (plus
  `phone.html`); from outside, through the remote-access portal (F8).
- The gateway also traces location itself (G14); `locate()` emails it.

### F6. Nightly report
- `nightly_report.py` runs at **00:15** every night (`streamwatch-report.timer`,
  catches up if the Pi was off) and covers the previous day.
- Per device: zones, traffic, alerts, an anomaly section, new or blocked
  devices, and the router's failed-SSH-login count.
- Optionally one plain-English sentence per device from a small local model
  (Ollama, on the Pi only); a sentence is used only if every number in it
  matches the facts, otherwise a template sentence is used.
- Sent through the router's Gmail account to the alert address. Full copies are
  kept in `~/mesh_records/reports/report_<date>.json` and `.txt`.
- Switched on in `~/.streamwatch_report.env` (`SW_REPORT=1`, `SW_REPORT_QWEN=1`).
- (`report_mailer.py` in this repository is a separate, older mailer; its timer
  is disabled on the Pi.)

### F7. Mesh network
Three GL-MT3000 routers on OpenWrt 24.10 in an 802.11s mesh: main123 (L1,
gateway: internet, DHCP, firewall), acf (L2) and 456 (L3), one network name
everywhere. Roaming is **assisted by steering**: a phone stuck on a far router
is disconnected and banned there for 8 s, so it drops Wi-Fi for about 1–3 s and
rejoins the nearest router. Whether the routers also use 802.11r has not been
checked. The recorder logs mesh health as `mesh_link` rows.

### F8. Remote access
- `ngrok.service` on the Pi publishes **one portal address behind Google
  sign-in**; only the alert account (`manaratcyber@gmail.com`) is let in.
- The portal's root opens a **terminal on the router**: ttyd on the Pi,
  listening only on `127.0.0.1:7681`, running `ssh root@192.168.8.1`.
- `/map` on the same address opens the **live map**.
- Config: `~/ngrok-portal.yml` (endpoints and Google sign-in policy) and
  `~/.config/ngrok/ngrok.yml` (account token).

### F9. Safety and upkeep
- **Pi deploys (`deploy/deploy.sh`):** refuses an unclean tree or a branch other
  than `main`; pulls; runs the tests; restarts the tracker and recorder and
  watches them for 130 s (stable PIDs, running from the deployed folder, map
  answers 200, tracker state and records growing, no Traceback). On success it
  records the commit in `~/.streamwatch-deployed`; on failure it rolls back to
  the last good commit and re-checks, and as a last resort falls back to the
  original copies in the home folder. Log: `~/streamwatch-deploy.log`.
- **Router deploys (`deploy/deploy-router.sh`):** stages and verifies the files
  on main123, runs the tests, then arms a **dead man's switch** (restores the
  previous version after 300 s unless the deploy is confirmed) and a **boot
  guard** (restores at boot if a deploy was left pending). It restarts
  StreamWatch, checks health for 90 s (stable PID, file checksum, startup
  banner, no Traceback, gate hooks intact, Pi still online), then confirms or
  rolls back. A rollback never opens the gate.
- **Pi firewall:** nftables table `streamwatch_fw` accepts SSH (22) and the map
  (8090) only from the LAN (192.168.8.0/24) and loopback, and drops them from
  anywhere else.
- **Automated tests:** deploys run a compile check, the toolkit tests and the
  recorder test (the router deploy adds the alert-email test); CI also runs the
  nightly-report test. This repository has 14 suites of its own.
- **Known gaps:** the tracker tests (`test_tracker_*.py`) aren't run by deploys
  or CI; VNC (5900) and RDP (3389) listen on all interfaces with no firewall
  rule; `~/mesh_calibration.json` is not in git.
- **Self-healing gateway:** StreamWatch starts on boot and respawns if it exits;
  the gate re-applies itself after a firewall reload; outage detection is immune
  to boot-time clock corrections.

**Not part of the system:** the forbidden area (cutting internet inside a zone)
is not one of the system's functions, so it isn't documented or tested here.

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
| `zones()` | Email back the zone status |
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

## A — Analysis & model (this repository only, offline, read the AI CSV)

These tools exist only in `theSaud`; they are **not deployed** and aren't one of
the nine functions. Run them by hand from `~/theSaud` on the Pi.

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
Its timer (`systemd/report-mailer.timer`, every 5 min) is **disabled** on the Pi;
the nightly report (F6) is the deployed one.

---

## S — Services

| Unit | Box | Purpose |
|------|-----|---------|
| `openwrt/streamwatch.init` → `/etc/init.d/streamwatch` | gateway | starts on boot, respawns; `gate_down` action |
| `openwrt/streamwatch.conf` → `/etc/streamwatch/streamwatch.conf` | gateway | email, threshold, extra flags |
| `mesh-tracker.service` | Pi | the tracker and live map (port 8090) |
| `mesh-recorder.service` | Pi | the recorder (starts after the tracker) |
| `streamwatch-report.timer` + `.service` | Pi | nightly report at 00:15 |
| `ngrok.service` | Pi | remote-access portal behind Google sign-in |
| `ttyd.service` | Pi | router terminal for the portal (loopback only) |
| `ollama.service` | Pi | local model for the nightly report's sentences (loopback only) |
| `nftables.service` | Pi | the Pi firewall (`streamwatch_fw`) |
| `/etc/init.d/sw-rollback` + watchdog | gateway | router deploy safety net (boot guard, dead man's switch) |
| `systemd/report-mailer.service` + `.timer` | Pi | older mailer from this repository; **disabled** on the Pi |
| NTP (router: Google time servers; Pi syncs from router) | both | correct timestamps after reboot |

The Pi units come from `deploy/` in Manarat-Cyber.

## T — Automated tests
14 suites in `tests/` (stdlib only):
`for t in tests/test_*.py; do python3 $t; done`
