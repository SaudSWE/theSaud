# StreamWatch / Manarat Mesh: context for Claude Code

Claude Code loads this file at the start of every session in this folder. It is
the current picture of the project: what is deployed, where the code lives, the
rules, and what is still open. Last updated: 2026-11-12.

**This repository is public.** Never write passwords, app passwords, tokens,
OAuth secrets, email addresses, or the remote-access (ngrok) URL into any file
here.

---

## 1. Where things live (read before touching anything)

| Repo | What it is | Rule |
|---|---|---|
| `SaudSWE/Manarat-Cyber` (private) | **The deployed system.** Gateway daemon, tracker, recorder, nightly report, map, deploy scripts. | Edit in `~/Manarat-Cyber` only, **never** in `~/streamwatch-live` (that is the deploy checkout). Ship only with `deploy/deploy.sh` (Pi) and `deploy/deploy-router.sh` (router): tests, health checks, automatic rollback. Its own `CLAUDE.md` governs work there. |
| `SaudSWE/theSaud` (public, this repo) | Docs, plus the offline analysis/ML tools (`device_report`, `history`, `eagle_eye`, `trend_model`, `threats`, `ask`, `report_mailer`). | **Nothing here is deployed.** `streamwatch_v12.py` here is an **older copy**: never copy it onto the router. |

- theSaud working branch: `claude/location-tracking-forbidden-zones-ersaxf`.
  `main` is behind it (PR #1 was merged; later commits are not on `main` yet).
- New features for the live system go into **Manarat-Cyber** and ship through its
  deploy scripts. theSaud is for docs and analysis tools.

## 2. Hardware

| Name | Address | Role |
|---|---|---|
| main123 (L1) | 192.168.8.1 | Gateway, GL-MT3000, OpenWrt 24.10. Runs StreamWatch (procd `/etc/init.d/streamwatch`) |
| acf (L2) | 192.168.8.2 | Mesh node (802.11s) |
| 456 (L3) | 192.168.8.3 | Mesh node (802.11s) |
| Raspberry Pi | 192.168.8.162 | Companion server: tracker, recorder, nightly report, map, remote access, Claude Code |

## 3. The nine functions

Full descriptions: `FUNCTIONALITY.md`. Hands-on test steps: `TESTING.md` (51 tests).

1. **Device approval.** Default-deny gate (iptables `SW_GATE`); allow/deny lists keyed by MAC; unknown devices are held.
2. **Data monitoring.** Per-device usage, browsing (domain names only), traffic alerts.
3. **Email remote control.** close, open, limit, throttle, block, devices, browsing, locate, zones, calibrate.
4. **Location tracking.** Wi-Fi signal tracker, live map, arrive/leave events, steering.
5. **Recording.** One unified CSV per day on the Pi (`~/mesh_records`, 54 columns, 24 record types).
6. **Nightly report.** Emailed at 00:15. A local model (Ollama) adds one number-checked sentence per device.
7. **Mesh network.** Three GL-MT3000 nodes over 802.11s.
8. **Remote access.** Router terminal (ttyd) and the map, reachable from anywhere behind Google sign-in (ngrok OAuth policy, one allowed account).
9. **Safety and upkeep.** Safe deploys with rollback (dead man's switch + boot guard on the router), Pi firewall (nftables `streamwatch_fw`), automated tests.

Also live: **malfunction detection.** Internet outage history with cut/restore
times, and "device not connected / back" alerts. Emails retry (30 s to 10 min),
and timing uses monotonic time, so a boot-time clock step can't cause false alerts.

## 4. What runs where

**Pi (systemd):** `mesh-tracker`, `mesh-recorder`, `streamwatch-report.timer`
(00:15), `ngrok`, `ttyd`, `ollama`, `nftables`. User service `claude-remote`
keeps Claude Code Remote Control always on. It runs in tmux session `claude-rc`,
`--spawn=same-dir`, in `~/theSaud`. Linger is enabled, and it survives a reboot.
theSaud's `report-mailer.timer` is **disabled**.

**Gateway:** StreamWatch, with the `SW_GATE` and `SW_PORTS` chains, dnsmasq query
logging and conntrack.

**Time:** the router has no RTC. Its NTP points to the Google time servers, and
the Pi syncs from the router (`timesyncd`, `NTP=192.168.8.1`, Google as fallback).

**Pi Wi-Fi:** pinned to the mesh SSID by autoconnect priority. It once jumped to
another saved network after a gateway reboot.

## 5. Rules (standing decisions by the owner)

- **The owner tests functions themselves.** Write docs and checklists. Don't run
  test sweeps against the live system unless asked.
- **Forbidden-area tracking is NOT part of the system.** Keep it out of docs, test
  plans and new code. The dormant code in this repo is pending a remove/keep
  decision.
- **Scope of monitoring:** consenting household devices on this network only.
  Never build detection or tracking of devices that aren't on the network (for
  example passers-by's phones or probe requests). Any monitor-mode sensor keeps
  allow-listed MACs only.
- **Metadata only:** domain names, flow sizes, ports and timing. Never page or file
  contents.
- **Identity is the MAC.** The IP is only a lease and a label.
- **Changes on the Pi or routers need the owner's approval.** Helper sessions are
  read-only by default.
- **No email floods.** Never email every minute: Gmail would suspend the account,
  and StreamWatch's own alerts use the same account.
- **Router config backups contain Wi-Fi and Gmail passwords.** Keep them
  encrypted, on the Pi, out of git.
- Don't open pull requests or push to `main` unless the owner asks.

## 6. Status (2026-11-12)

- Malfunction detection is verified live: outage DOWN/UP rows, email delivered
  after a retry, and missing/back device alerts.
- Clock-skew problem fixed (the router booted about 18.5 h slow). Router and Pi
  agree, and both survive a reboot.
- Always-on Claude bridge on the Pi passed a reboot test.
- theSaud: 14 test suites, **438 checks, all passing**
  (`for t in tests/test_*.py; do python3 "$t"; done`).
- Docs are organized around the nine functions: `FUNCTIONALITY.md`, `TESTING.md`,
  `README.md`, `ARCHITECTURE.md`, `handoff.md`, `REQUIREMENTS.md`.
- **45-feature review** (from the product PDF): 10 done, 14 partly there, 21 not
  there. See `FEATURES_CHECKLIST.md`.

## 7. Known issues

- The Pi's remote-desktop ports (VNC 5900, RDP 3389) are reachable from the whole
  LAN. They should be closed or firewalled. `TESTING.md` U1 fails until then.
- `~/mesh_calibration.json` (tracker calibration) is not in git and not backed up.
- Tracker tests (`test_tracker_*`) aren't run by the deploy gate or CI.
- Data caps and throttles are keyed by **IP** (`QUOTAS[ip]`, `THROTTLES[ip]`), so
  they can land on the wrong device after a DHCP change. They should key by MAC.
- Email commands verify only the From address, which can be forged
  (checklist #06).
- The Gmail app password was exposed earlier. **Rotation is pending** (owner
  action, on both router and Pi env files).
- The trend and threat tools exist only in theSaud, not in the deployed repo.
  `threats.py` and `eagle_eye.py` overlap; merge or pick one.
- The Pi's `~/theSaud` has uncommitted local edits (`ask.py`, `device_report.py`,
  `eagle_eye.py`, `tests/test_device_report.py`). Don't `git pull` blindly. Stash
  first, or fetch single files with `git checkout origin/<branch> -- <file>`.
- `german_credit_data_biased_training.csv` in this repo is unrelated to the
  project.

## 8. Waiting on the owner

1. The `zones` email command: keep or drop? (In theSaud's copy it reports
   forbidden-area status.)
2. Remove the dormant forbidden-area code and `LOCATION_FORBIDDEN_AREA.md`?
3. Approve the corrected product description (drops the forbidden zone; qualifies
   the DHCP, location-accuracy, browsing and mesh claims; adds fault alerts).
4. Move the docs into Manarat-Cyber?
5. Which partly-there features to build. Suggested order:
   **#32** config backups (including calibration) → **#06** email sender
   verification (DKIM/SPF + optional PIN) → **#13** turn on the speed report →
   **#12/#42** move the trend tools into Manarat-Cyber → **#43** pre-deploy
   validator + tracker tests in the gate → **#19** LAN isolation for held devices,
   together with closing VNC/RDP.
6. Bring theSaud's `main` up to date with the branch.

## 9. Working in this repo

- Pure Python standard library: no pip installs, no GPU.
- Tests: `for t in tests/test_*.py; do python3 "$t"; done`.
- Analysis tools read `~/mesh_records` on the Pi: `python3 ask.py`,
  `python3 device_report.py`, `python3 trend_model.py`, `python3 threats.py`.
- When behavior changes, update `FUNCTIONALITY.md`, `TESTING.md` and `handoff.md`
  in the same commit.
