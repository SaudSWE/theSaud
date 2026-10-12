# StreamWatch Mesh Protection — Handoff

Branch: `claude/location-tracking-forbidden-zones-ersaxf` · Last updated: 2026-10-12
Tests: **388 passing** across 12 suites (pure stdlib, run with `python3 tests/test_*.py`).

---

## 1) Goal

A household network monitoring and control system on a 3-node 802.11s GL‑MT3000
OpenWrt mesh (gateway **main123** = 192.168.8.1; nodes **acf** = .2, **456** = .3)
plus a Raspberry Pi companion host (**192.168.8.162**) running the tracker and
the recorder. Scope is set by the project whiteboard (12 items) and the SRS
(authoritative). The current phase: build an **offline, on-server classical‑ML
model** over the recorder's data that reports per‑device‑IP relationships
(data usage, browsing, file transfer, log‑in sessions, time online, speed
impact, location↔usage, fast log‑in/out, downloads affecting the system) and
flags abnormal devices — with everything kept local (no cloud, PRV).

Board coverage and the AI‑model framework are tracked in **`REQUIREMENTS.md`**.

---

## 2) Current State

Components (all committed and pushed):

- **`streamwatch_v12.py`** — gateway daemon: default‑deny allow/deny gate,
  per‑port block/allow, quotas/throttle, email command channel, and item‑9
  malfunction detection (internet outage history + missing‑device alerts),
  now immune to the router's clock being stepped at boot.
- **`mesh_recorder.py`** — Pi recorder: one unified AI CSV (54 columns, 24
  record types) + generated `DATA_DICTIONARY.md`/`.csv`. Captures internet
  access (GRANTED/BLOCKED/HELD), browsing (dns_query, loopback excluded),
  emails, malfunctions with cut/restored date‑time, date/time columns.
- **`group_lists.py`** — admin CLI for the allow/deny text files (keyed on MAC).
- **Feature + model + interface layer (this phase):**
  - **`device_report.py`** — per‑device feature report; `--csv` writes the
    feature table. Drops infra/non‑devices, caps rate glitches.
  - **`history.py`** — time‑ordered activity log of meaningful events.
  - **`eagle_eye.py`** — offline robust (median/MAD) anomaly detector
    (cross‑device), high‑side only, names the reasons. Pure stdlib;
    `fit()/score()` is a drop‑in slot for scikit‑learn later.
  - **`trend_model.py`** — per‑device‑over‑time: scores each device's latest
    day against its OWN history, so a device is flagged for deviating from
    itself (not for differing from peers). In `ask.py` as `trend`.
  - **`report_mailer.py`** + `systemd/report-mailer.{service,timer}` —
    scheduled build + email of the reports.
  - **`ask.py`** — offline command terminal to query/command the model.
- Docs: `REQUIREMENTS.md`, `GROUP_LISTS.md`, `PORT_RULES.md`,
  `LOCATION_FORBIDDEN_AREA.md`, and this file.

Board status: items **1–9 done**, **11 (forbidden area)** coded (needs a zone
configured + tracker running), **Adblocker** is the user's other team,
**10 (IoT)** and **12 (Attack)** are TBD / not built.

---

## 3) Active Status (what is running vs on‑demand)

**Running continuously on the hardware:**
- Pi: **`mesh-recorder`** systemd service — confirmed **active** (writing the CSV).
- Pi: **`report-mailer.timer`** — installed and enabled; now **every 15 min**
  with **`--only-flagged`** (emails only when the model flags a device).
- Gateway: **StreamWatch** (procd service) — **needs verification**: a recent
  `pgrep` returned nothing, i.e. it may be **down**. See Next Steps.

**On‑demand (run by hand / scriptable), not services:**
- `device_report.py`, `history.py`, `eagle_eye.py`, `ask.py`.
- The anomaly model only scores when invoked (by you or by the mailer); it is
  not a background process.

Run the terminal: `cd ~/theSaud && python3 ask.py` (or `python3 ask.py online`).

---

## 4) Changes Made (this phase, newest first)

- `ask.py` — offline terminal to the model (commands + keyword phrasing, device
  resolution, one‑shot mode). 24 tests.
- `report-mailer` safe defaults — `--only-flagged`, every 15 min (was minutely).
- `report_mailer.py` + systemd units — scheduled build+email of the reports,
  creds from an env file, `--dry-run`/`--only-flagged`/`--to`. 16 tests.
- `eagle_eye.py` — high‑side‑only scoring (a quiet device is not an anomaly).
- `eagle_eye.py` — first classical‑ML model: robust median/MAD anomaly
  detector, log‑scaled heavy‑tailed features, explainable reasons. 20 tests.
- `device_report.py` — filter infra/non‑devices (loopback, .0/.255, node
  self‑traffic, null/multicast MACs, zero‑signal), normalize comma‑MAC, cap
  absurd per‑sample rates; keep randomized phone MACs and the Pi.
- `device_report.py` + `history.py` — skip stray header/junk rows (a
  clock‑jump artifact) instead of crashing.
- `device_report.py` — the per‑device feature report + `--csv` feature table;
  `REQUIREMENTS.md` (board coverage + AI‑model framework).
- `history.py` — readable activity history, collapses the hourly port
  inventory and the tracker's distance jitter. 27 tests.
- `mesh_recorder.py` — drop the router's own loopback DNS lookups and kernel
  info/debug boot chatter from the CSV (`--all-logs` restores).

Earlier in the session: item‑9 malfunction detection + outage email retry +
clock‑jump immunity; browsing capture; date/time/access/email columns.

**Operational fixes done on the live hardware:** router clock was ~18.5 h slow
(no RTC; booted stale) → pointed NTP at Google time servers, Pi syncs from the
router; both now agree and survive reboot. Pi had jumped to a different saved
Wi‑Fi after a gateway reboot → rejoined the mesh (set mesh autoconnect priority
if not yet done).

---

## 5) Failed Attempts / Dead Ends

- **Email every minute** (as first requested) — would send ~1440/day and get
  the free Gmail account suspended, which also kills StreamWatch's own alerts
  (same account). Replaced with every‑15‑min + `--only-flagged`.
- **Cross‑device anomaly detection at n=4** — unreliable: it flagged the Pi
  just for being the always‑on server, and (before the fix) flagged a *quiet*
  device at −38σ. Fixed the quiet‑device bug (high‑side only); the small‑sample
  weakness remains inherent — see Next Steps (per‑device‑over‑time).
- **MAD=0 masking** — with several *identical* devices MAD collapses and a lone
  outlier is masked (~3.6σ, under 4). Handled with a mean‑abs‑dev fallback;
  real (non‑identical) devices clear the threshold fine.
- **`python3 ask.py` from `~`** — fails; the scripts live in `~/theSaud`. Use
  `cd ~/theSaud` or the full path, or add an `alias ask=`.
- **scp to OpenWrt** — no sftp‑server on the router; deploy with
  `cat file | ssh root@192.168.8.1 'cat > /root/file'`.
- **Restarting the log service alone** cut dnsmasq off from syslog (no DNS rows)
  → must restart dnsmasq after the log service (already in the recorder).
- **A true conversational AI** over the data — not available: the team chose
  classical ML (no LLM), so `ask.py` is a command interpreter, not a chat bot.

---

## 6) Next Steps

**Must‑do (operational):**
1. **Verify StreamWatch on the gateway is up** (it may be down):
   `ssh root@192.168.8.1 '/etc/init.d/streamwatch restart; sleep 3; pgrep -af streamwatch_v12 || echo NOT RUNNING'`
   then `logread | grep -i streamwatch | tail -20` to see why it stopped.
2. **Rotate the Gmail app password** (it was in old source and in chat); update
   `/root/.streamwatch_env` on the gateway and `~/.streamwatch_env` on the Pi.
3. **Confirm the Pi won't leave the mesh on reboot** — set the mesh Wi‑Fi to
   autoconnect with priority, and disable autoconnect on the other saved SSID.

**Model roadmap (all classical, all local):**
4. ~~Per‑device‑over‑time model~~ **DONE** — `trend_model.py` (and `ask.py
   trend`): each device vs its own daily history. Next for it: fold in the
   three features below as daily inputs, and wire a `trend` flag into the
   mailer alongside the cross‑device scan.
5. **The three remaining framework features** (in `REQUIREMENTS.md`): internet
   **speed impact** (bin time, attribute high‑latency minutes to the top talker),
   **location↔usage** (per‑node byte split), and **download‑affects‑system**
   (big inbound flow + a new `open_port` → overlaps board #12 Attack).
6. **Rotating‑MAC stitching** — one iPhone shows up as several identities
   (private MAC). Stitch by vendor + timing, or document turning off "Private
   Wi‑Fi Address" per device.
7. Optional: upgrade `eagle_eye.py` to scikit‑learn IsolationForest behind
   the existing `fit()/score()` interface (only if sklearn is installed).

**How to pick back up:** `cd ~/theSaud && git pull`, then
`python3 ask.py` (interactive) or `python3 device_report.py --csv ~/features.csv && python3 eagle_eye.py ~/features.csv`.
