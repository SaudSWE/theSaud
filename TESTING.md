# StreamWatch — Hands-on Test Plan

A checklist for testing every function yourself on the real system. Test IDs
match `FUNCTIONALITY.md`. For each test: do the **Steps**, compare with
**Expect**, tick **Pass** or **Fail**, and note anything odd.

`GW$` = run on the gateway (`ssh root@192.168.8.1`). `PI$` = run on the Pi
(section A from `~/theSaud`). `CSV` = `~/mesh_records/records_$(date +%F).csv` on the Pi.

## Tests by function

| # | Function | Tests |
|---|----------|-------|
| 1 | Device approval | G3, G4, G4b, G4c, L1, L2 |
| 2 | Data monitoring | G1, G6a, G6b, G9 |
| 3 | Email remote control | G2, G3, G5, G6a, G6b, G10, G11, G13, G14 |
| 4 | Location tracking | M1–M4, G12, G13, G14 |
| 5 | Recording | R1–R4 |
| 6 | Nightly report | N1, N2 |
| 7 | Mesh network | W1–W3 |
| 8 | Remote access | X1–X3 |
| 9 | Safety and upkeep | U1–U3, S1, S2, T |

The deployed system runs from **Manarat-Cyber** (`~/streamwatch-live` on the
Pi). Section A tests tools that exist only in this repository (`~/theSaud`).
The forbidden area is not part of the system and is not tested.

---

## 0. Before you start

- [ ] **Make sure the deployed code is current.** Changes go into Manarat-Cyber
  and are deployed only with its scripts:
  `PI$ ~/streamwatch-live/streamwatch/deploy/deploy.sh` (Pi services) and
  `PI$ ~/streamwatch-live/streamwatch/deploy/deploy-router.sh` (router).
  **Don't** copy `streamwatch_v12.py` from `~/theSaud` to the router — it's an
  older copy and would replace the deployed one.
- [ ] **Keep yourself connected.** Your laptop and the Pi must be on the allow
  list before any gate test: `GW$ python3 /root/group_lists.py allow list`.
  If you ever lock yourself out: `GW$ /etc/init.d/streamwatch gate_down`.
- [ ] **Have a spare test phone** (Wi-Fi, Private Wi-Fi Address set to *Fixed*
  for this network) and note its IP: `GW$ cat /tmp/dhcp.leases`.
- [ ] **Open the alert inbox** (the `SW_EMAIL_TO` address) to watch emails arrive.
- [ ] **Watch the gateway log** in a second window:
  `GW$ logread -f | grep python3`.
- [ ] Features that need extra flags: add them to `SW_EXTRA` in
  `/etc/streamwatch/streamwatch.conf`, `GW$ /etc/init.d/streamwatch restart`,
  test, then remove noisy ones (speed/usage reports) afterwards.

Test phone IP used below: `PHONE=192.168.8.X` (replace with yours).

---

## G — Gateway (`streamwatch_v12.py`)

### G0. Service is running
- Steps: `GW$ pgrep -af streamwatch_v12`
- Expect: one `python3 /root/streamwatch_v12.py --email-alert …` line.
- [ ] Pass [ ] Fail — notes:

### G1. Traffic threshold alert
- Steps: set `SW_THRESHOLD="50M"`, restart. On the test phone stream video for a few minutes.
- Expect: email `[streamwatch] <PHONE> (...) data usage crossed 50.0 MB`; an `email` row with category `sent` in the CSV.
- After: restore your normal threshold.
- [ ] Pass [ ] Fail — notes:

### G2. Email commands are obeyed only from the allowed sender
- Steps: from the allowed address, send an email whose first line is `rules()`. Then send the same from a different address.
- Expect: the first gets a `[streamwatch] port rules - N` reply. The second is ignored and appears in the CSV as an `email` row with category `refused`.
- [ ] Pass [ ] Fail — notes:

### G3. close / open a device
- Steps: email `close(PHONE)`. Try browsing on the phone. Then email `open(PHONE)`.
- Expect: after `close`, the phone has no internet (with `--group-lists` its MAC is now in `deny.txt`). After `open`, internet returns and it's in `allow.txt`.
- [ ] Pass [ ] Fail — notes:

### G4. Approval gate (allow / deny / held)
- Steps:
  1. `GW$ python3 /root/group_lists.py allow remove PHONE` and `… deny remove PHONE` → `GW$ python3 /root/group_lists.py classify PHONE`
  2. `… allow add PHONE` → classify again, browse on the phone
  3. `… deny add PHONE` (still on allow) → classify, browse
  4. `… deny remove PHONE`
- Expect: 1 → `hold`, phone has Wi-Fi but no internet. 2 → `allow`, internet works within seconds (no restart). 3 → `deny`, blocked (deny beats allow). 4 → `allow` again. Each change gives an `internet_access` row (HELD / GRANTED / BLOCKED) in the CSV.
- [ ] Pass [ ] Fail — notes:

### G4b. Gate survives restart and firewall reload
- Steps: `GW$ /etc/init.d/streamwatch restart`, then `GW$ /etc/init.d/firewall reload`, wait 30 s, then `GW$ iptables -S | grep SW_GATE | head`.
- Expect: SW_GATE rules present; allowed devices still online, held devices still blocked.
- [ ] Pass [ ] Fail — notes:

### G4c. Inspect the live gate rules
- Steps: `GW$ iptables -S SW_GATE` and `GW$ iptables -S FORWARD | grep SW_GATE`
- Expect: one `-j RETURN` line per allow-listed MAC, then a final `-j DROP`; FORWARD sends LAN traffic into `SW_GATE`.
- (Don't start a second StreamWatch just to use `--gate-dry-run` on the live gateway — that flag is for previewing before you first turn the gate on.)
- [ ] Pass [ ] Fail — notes:

### G5. Per-port rules
- Steps: email `block(PHONE, 443)`; open an https site on the phone. Email `rules()`. Email `unblock(PHONE, 443)`.
- Expect: https fails while blocked; the `rules()` reply lists the block; https works after unblock. Also try `allow(PHONE, 443)` together with `block(PHONE, 443)` → block wins.
- [ ] Pass [ ] Fail — notes:

### G6a. Data quota
- Steps: email `limit(PHONE, 30MB)`; stream on the phone. Then `unlimit(PHONE)`.
- Expect: the phone is blocked once it passes 30 MB (`sw_quota` row, state BLOCKED); internet returns after `unlimit`.
- [ ] Pass [ ] Fail — notes:

### G6b. Speed throttle
- Steps: run a speed test on the phone; email `throttle(PHONE, 1mbit)`; speed test again; `unthrottle(PHONE)`.
- Expect: about 1 Mbit/s while throttled; back to normal after (`sw_throttle` rows).
- [ ] Pass [ ] Fail — notes:

### G7a. Internet outage history
- Steps: unplug main123's WAN cable for 60 s, plug back in, wait 30 s.
  `PI$ grep ',malfunction,' CSV | tail -2`
- Expect: a `DOWN` row (`cut_date`/`cut_time` = when you unplugged) and an `UP` row (cut + `restored_date`/`restored_time`, `duration_s` ≈ 60). Email `[streamwatch] internet was DOWN for …`.
- [ ] Pass [ ] Fail — notes:

### G7b. Device not connected / back
- Steps: the phone must be on the allow list. Turn its Wi-Fi off for 6 min, then on.
- Expect: after ~5 min, `MISSING` row + email `device not connected`; on return, `BACK` row with the real duration + email `device back`.
- [ ] Pass [ ] Fail — notes:

### G8. Speed report
- Steps: add `--speed-report --speed-latency-only --speed-every 60`, restart, wait 2 min.
- Expect: email `[streamwatch] speed …` with latency. Remove the flags after.
- [ ] Pass [ ] Fail — notes:

### G9. Usage report
- Steps: add `--usage-report --usage-every 120`, restart, wait 3 min.
- Expect: email `[streamwatch] usage report - N device(s)` with data, signal and distance per device. Remove after.
- [ ] Pass [ ] Fail — notes:

### G10. Browsing watch
- Steps: add `--dns-watch`, restart. Visit a few sites on the phone. Email `browsing(PHONE)`.
- Expect: reply `[streamwatch] dns lookups - PHONE` listing those domains.
- [ ] Pass [ ] Fail — notes:

### G11. Device registry / new device
- Steps: add `--track-devices`, restart. Connect a device that has never joined before. Email `devices()`.
- Expect: email `[streamwatch] new device: …`; the `devices()` reply `[streamwatch] device registry - N known` includes it.
- [ ] Pass [ ] Fail — notes:

### G12. Signal movement alerts
- Steps: add `--rssi-track`, restart. Walk the phone slowly toward main123, wait, then away.
- Expect: emails for approaching / moving away / idle (at most one per `--rssi-cooldown`).
- [ ] Pass [ ] Fail — notes:

### G13. Distance calibration
- Steps: `GW$ python3 /root/streamwatch_v12.py --calibrate-status`. Then stand the phone 1 m from main123 and run `GW$ python3 /root/streamwatch_v12.py --calibrate PHONE --at 1`. Run `--calibrate-status` again.
- Expect: status prints the model in force; after calibrating, a per-device entry for the phone. (Optional: `--calibrate-wizard PHONE`; `--calibrate-reset PHONE` to undo.)
- [ ] Pass [ ] Fail — notes:

### G14. Location tracing
- Steps: add `--track-location`, restart. Move the phone between nodes. Email `locate(PHONE)`.
- Expect: TRACE lines in the log as it moves; reply `[streamwatch] location - …` with radio and distance range.
- [ ] Pass [ ] Fail — notes:

---

## L — Lists admin (`group_lists.py`)

### L1. Add / list / check / remove
- Steps: `GW$ python3 /root/group_lists.py allow add PHONE` → `allow list` → `allow check PHONE` → `allow remove PHONE` → `allow check PHONE`
- Expect: added line shows the MAC with `# <ip> added <time>`; check prints `yes` then `no`.
- [ ] Pass [ ] Fail — notes:

### L2. Unknown device is refused
- Steps: `GW$ python3 /root/group_lists.py allow add 192.168.8.250` (an IP nobody holds).
- Expect: refused (no MAC found); the file is unchanged.
- [ ] Pass [ ] Fail — notes:

---

## R — Recorder (`mesh_recorder.py`)

### R1. Recorder is running and writing
- Steps: `PI$ systemctl is-active mesh-recorder`; `PI$ tail -1 CSV`, wait a minute, `tail -1 CSV` again.
- Expect: `active`; the last line's time moves forward.
- [ ] Pass [ ] Fail — notes:

### R2. Every record type and the date/time columns
- Steps: `PI$ cut -d, -f5 CSV | sort | uniq -c | sort -rn` and `PI$ head -1 CSV | tr ',' '\n' | head -4`
- Expect: many record types listed; the first columns are `timestamp, date, time, epoch`.
- [ ] Pass [ ] Fail — notes:

### R3. Browsing capture (and the router's own lookups excluded)
- Steps: visit a site on the phone, wait 1 min. `PI$ grep ',dns_query,' CSV | tail -5` and `PI$ grep ',dns_query,' CSV | grep -c ',127.0.0.1,'`
- Expect: rows with the phone's IP and the domain; new rows from `127.0.0.1` stop appearing.
- [ ] Pass [ ] Fail — notes:

### R4. Data dictionary, note, export
- Steps: `PI$ python3 mesh_recorder.py dictionary`; `PI$ python3 mesh_recorder.py note "test note"`; `PI$ python3 mesh_recorder.py export --from "$(date +%F) 00:00" --to "$(date +%F) 23:59" --types malfunction -o /tmp/m.csv`
- Expect: `wrote …/DATA_DICTIONARY.md and data_dictionary.csv`; `noted in …` and a `change_log` row; `/tmp/m.csv` contains only malfunction rows.
- [ ] Pass [ ] Fail — notes:

---

## A — Analysis & model (Pi)

These tools exist only in this repository and aren't deployed. Run them from
`~/theSaud` (`git pull` there first).

### A1. Device report
- Steps: `PI$ python3 device_report.py`, then `python3 device_report.py PHONE`, then `python3 device_report.py --hours 24 --csv ~/features.csv`
- Expect: one block per real device (no 127.0.0.1, routers or 00:00… entries), longest-online first; the filter shows just the phone; `feature table written to …`.
- [ ] Pass [ ] Fail — notes:

### A2. Activity history
- Steps: `PI$ python3 history.py | tail -20`; `python3 history.py PHONE`
- Expect: time-ordered events (internet access, malfunctions, emails, ARRIVED/LEFT); no repeated open_port lines; filtering shows only the phone.
- [ ] Pass [ ] Fail — notes:

### A3. Eagle-Eye scan and threat rule
- Steps: `PI$ python3 eagle_eye.py ~/features.csv`. Then toggle the phone's Wi-Fi off/on 3 times within 5 minutes, rebuild features (`device_report.py --hours 1 --csv ~/features.csv`) and scan again.
- Expect: `Eagle-Eye (EE1) scan of N device(s)…`; after the toggling the phone shows `!! THREAT` with `sudden log-ins: … fast in/out within 10 min`.
- [ ] Pass [ ] Fail — notes:

### A4. Per-device trend
- Steps: `PI$ python3 trend_model.py` (use `--min-days 2` if you have little history).
- Expect: each device scored against its own past days; or the "needs more days" message if history is short.
- [ ] Pass [ ] Fail — notes:

### A5. Threats (flapping / unknown entrance)
- Steps: `PI$ python3 threats.py`. Then connect a device that's on neither list (it's held) and run again.
- Expect: the held device appears as `!! POTENTIAL THREAT` — `unknown entrance`.
- [ ] Pass [ ] Fail — notes:

### A6. Offline terminal
- Steps: `PI$ python3 ask.py`, then type: `help`, `online`, `data iphone`, `browsing PHONE`, `anomalies`, `trend`, `threats`, `window all`, `quit`
- Expect: each command answers from your data; `quit` exits.
- [ ] Pass [ ] Fail — notes:

### A7. Report mailer
- Steps: `PI$ python3 report_mailer.py --dry-run | head -40`, then `PI$ python3 report_mailer.py`
- Expect: the dry run prints the report without sending; the real run prints `report emailed to …` and the email arrives.
- [ ] Pass [ ] Fail — notes:

---

## S — Services, boot and clock

### S1. Gateway reboot
- Steps: `GW$ reboot`. After ~2 min: `GW$ pgrep -af streamwatch_v12; date` and `PI$ date`.
- Expect: StreamWatch running without you starting it; router and Pi show the same correct time; allowed devices online, held devices still held.
- [ ] Pass [ ] Fail — notes:

### S2. Pi reboot
- Steps: `PI$ sudo reboot`. After it's back: `PI$ systemctl is-active mesh-tracker mesh-recorder ngrok ttyd nftables`, `PI$ timedatectl | grep synchronized`, `PI$ systemctl list-timers streamwatch-report.timer`, and confirm the Pi rejoined the **mesh** Wi-Fi (`ip -br addr` shows 192.168.8.x). If you set up the always-on Claude bridge: `systemctl --user is-active claude-remote`.
- Expect: every unit `active`; `yes`; the report timer listed for 00:15; a 192.168.8.x address.
- [ ] Pass [ ] Fail — notes:

### S3. Only the intended mailers are scheduled
- Steps: `PI$ systemctl list-timers --all | grep -E 'streamwatch-report|report-mailer'`
- Expect: `streamwatch-report.timer` scheduled for 00:15; `report-mailer.timer` (the older mailer from this repository) not scheduled.
- [ ] Pass [ ] Fail — notes:

---

## M — Location tracking: tracker, map, events, steering (function 4)

### M1. Live positions on the map
- Steps: on the LAN, open `http://192.168.8.162:8090/mesh_map.html`. Carry the test phone from L1 to L2 to L3, pausing ~30 s at each.
- Expect: every device appears near its router; the phone's marker follows you (the tracker polls every 2 s and smooths, so allow a few seconds).
- [ ] Pass [ ] Fail — notes:

### M2. Positions are recorded
- Steps: `PI$ grep ',device_position,' CSV | grep PHONE | tail -3`
- Expect: recent rows with the station (L1/L2/L3), distance and movement state, changing as the phone moves.
- [ ] Pass [ ] Fail — notes:

### M3. Tracker events
- Steps: turn the phone's Wi-Fi off for a minute, then on; then walk it from L1 to L2. `PI$ tail -20 ~/mesh_tracker/tracker_events.csv` and `PI$ grep ',tracker_event,' CSV | tail -8`
- Expect: LEFT (after 30 s unseen) then ARRIVED for the Wi-Fi toggle; HANDOVER for the walk.
- [ ] Pass [ ] Fail — notes:

### M4. Steering a sticky phone
- Steps: with the phone connected to L1, walk to the far side near L3 without turning Wi-Fi off; wait there a minute.
- Expect: after 3 polls in a row below −75 dBm (or beyond L1's zone radius + 2 m), a `STEER` event; the phone drops Wi-Fi for about 1–3 s and rejoins L3 (`HANDOVER`). It won't steer if two routers already hear the phone, or if no other router is at least 3 dB stronger.
- [ ] Pass [ ] Fail — notes:

---

## N — Nightly report (function 6)

### N1. Scheduled and switched on
- Steps: `PI$ systemctl list-timers streamwatch-report.timer` and `PI$ grep SW_REPORT ~/.streamwatch_report.env`
- Expect: next run at 00:15; `SW_REPORT=1` (and `SW_REPORT_QWEN=1` if you want the model's one-line summaries).
- [ ] Pass [ ] Fail — notes:

### N2. Report arrives and matches the data
- Steps: run it now: `PI$ sudo systemctl start streamwatch-report.service`, then `PI$ journalctl -u streamwatch-report -n 5 --no-pager` and `PI$ ls -t ~/mesh_records/reports/ | head -2`. Check the inbox.
- Expect: the journal says it was sent; a `report_<date>.json` and `.txt` saved; one email with a per-device summary of the previous day. Pick one device and check its traffic figure against the saved `.txt`.
- [ ] Pass [ ] Fail — notes:

---

## W — Mesh network (function 7)

### W1. All three routers are meshed
- Steps: on each router, find the mesh interface with `iw dev`, then `iw dev <mesh-if> station dump | grep -c Station`. Also `PI$ grep ',mesh_link,' CSV | tail -6`.
- Expect: each router sees the other two (count 2); `mesh_link` rows show the peers with a healthy signal.
- [ ] Pass [ ] Fail — notes:

### W2. One network everywhere
- Steps: on the test phone, look at the Wi-Fi list at L1, L2 and L3.
- Expect: the same single network name at each location.
- [ ] Pass [ ] Fail — notes:

### W3. Roaming
- Steps: start a video call or stream on the phone at L1, walk slowly to L2 then L3.
- Expect: the call continues; a short stall (about 1–3 s) is normal when the tracker steers the phone; `tracker_event` shows HANDOVER (and maybe STEER) rows.
- [ ] Pass [ ] Fail — notes:

---

## X — Remote access (function 8)

### X1. Map from outside the house
- Steps: turn the phone's Wi-Fi off (mobile data only). Open your ngrok portal address with `/map` at the end.
- Expect: Google sign-in first; signed in as `manaratcyber@gmail.com`, the live map loads.
- [ ] Pass [ ] Fail — notes:

### X2. Strangers are refused
- Steps: open the portal address in a private/incognito window and sign in with any other Google account (or don't sign in).
- Expect: refused (403); neither the map nor the terminal loads.
- [ ] Pass [ ] Fail — notes:

### X3. Router terminal from outside
- Steps: on mobile data, open the portal address itself (no `/map`), sign in as `manaratcyber@gmail.com`, and run `uptime`.
- Expect: a working terminal on the router. On the Pi, `ss -ltn | grep 7681` shows ttyd listening only on `127.0.0.1`.
- [ ] Pass [ ] Fail — notes:

---

## U — Safety and upkeep (function 9)

### U1. Pi firewall
- Steps: `PI$ sudo nft list table inet streamwatch_fw`. From another device on the LAN: `nc -zv 192.168.8.162 22` and `nc -zv 192.168.8.162 8090`. Then `PI$ sudo ss -ltnp | grep -E ':5900|:3389'`.
- Expect: the table accepts 22 and 8090 only from 192.168.8.0/24 and loopback; both answer from the LAN. **Known issue:** VNC (5900) and RDP (3389) currently listen on all interfaces with no firewall rule, so this check fails until they're firewalled or turned off.
- [ ] Pass [ ] Fail — notes:

### U2. Pi deploy is gated and recorded
- Steps: `PI$ ~/streamwatch-live/streamwatch/deploy/deploy.sh`, then `PI$ cat ~/.streamwatch-deployed`, `PI$ git -C ~/streamwatch-live rev-parse HEAD` and `PI$ tail -20 ~/streamwatch-deploy.log`.
- Expect: "up to date" (or a deploy ending `OK: … deployed and healthy`); the recorded commit equals HEAD; the log shows "tests passed" and a health check before every "OK".
- Optional rollback drill: push a commit to Manarat-Cyber that fails a test, run `deploy.sh` → it stops at the tests and restarts nothing; then revert that commit.
- [ ] Pass [ ] Fail — notes:

### U3. Router deploy safety net is disarmed after a good deploy
- Steps: `PI$ ~/streamwatch-live/streamwatch/deploy/deploy-router.sh` (no-op if nothing changed), then `GW$ ls /root/.sw-deploy/` and `GW$ /etc/init.d/sw-rollback enabled && echo armed || echo disarmed`.
- Expect: no `pending` file; `disarmed`. After a real deploy the output ends `deployed, healthy and confirmed (dead man's switch disarmed)`.
- [ ] Pass [ ] Fail — notes:

---

## T — Automated tests (optional, run them yourself)

- Steps: `PI$ for t in tests/test_*.py; do python3 $t | tail -1; done`
- Expect: every suite ends `N passed, 0 failed`.
- [ ] Pass [ ] Fail — notes:

---

## Results summary

| # | Function | Tests | Passed | Failed | Notes |
|---|----------|-------|--------|--------|-------|
| 1 | Device approval | G3, G4, G4b, G4c, L1, L2 | | | |
| 2 | Data monitoring | G1, G6a, G6b, G9 | | | |
| 3 | Email remote control | G2, G3, G5, G6a, G6b, G10, G11, G13, G14 | | | |
| 4 | Location tracking | M1–M4, G12, G13, G14 | | | |
| 5 | Recording | R1–R4 | | | |
| 6 | Nightly report | N1, N2 | | | |
| 7 | Mesh network | W1–W3 | | | |
| 8 | Remote access | X1–X3 | | | |
| 9 | Safety and upkeep | U1–U3, S1, S2, T | | | |
| — | Other | G0, G7a, G7b, G8, S3; repo-only tools A1–A7 | | | |

Total: 51 tests (some count toward more than one function).

Tested by: ________  Date: ________
