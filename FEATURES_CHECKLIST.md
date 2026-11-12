# Feature checklist (45 features from the product PDF)

Each feature is checked against what the system actually does. Reviewed
2026-11-12, against the deployed `Manarat-Cyber` code (as verified on the Pi) and
the tools in this repo.

**Legend:** ✅ in the running system · 🟡 partly there · ❌ not there

**Totals: ✅ 10 · 🟡 14 · ❌ 21.** Section 1 is essentially delivered: 8 ✅, 5 🟡,
and only #14 missing. Most of 15–45 are partial or not started. The PDF itself
calls those proposals.

## Section 1: Original features (01–14)

| # | Feature | Status | What exists |
|---|---|---|---|
| 01 | Intruder detection and prevention | ✅ | Default-deny gate holds every unknown device; deny list; failed router logins counted in the nightly report |
| 02 | Bandwidth management | ✅ | Per-device download/upload limits and data caps (set by hand; stored by IP) |
| 03 | Device location tracking | ✅ | Indoors: Wi-Fi tracker and live map, accurate to a few metres. Outdoors: the phone page sends GPS (still to confirm) |
| 04 | Unified network access | 🟡 | One network, one password everywhere. No per-user usernames (that needs WPA-Enterprise/RADIUS) |
| 05 | Remote router reconfiguration | ✅ | Router terminal through the Google-protected link; email commands; remote deploys |
| 06 | Email-based control | 🟡 | All commands work, but "verifying the sender" only checks the From address, which can be forged |
| 07 | No client software | ✅ | Everything runs on the network; the phone map is just a web page |
| 08 | Low cost | ✅ | One Raspberry Pi and three standard routers |
| 09 | Daily network reports | ✅ | Nightly email at 00:15: per device, anomalies, new/blocked devices |
| 10 | On-device offline AI | 🟡 | A local model adds one checked sentence per device. It doesn't diagnose errors or suggest remedies |
| 11 | Fault detection | ✅ | Internet outages with cut/restore times; "device not connected" alerts (confirm in the deployed copy: TESTING.md G7a/G7b) |
| 12 | Historical analysis | 🟡 | Everything is recorded daily. The trend tools exist only in this repo (not deployed); the nightly report covers just the previous day |
| 13 | Network speed analysis | 🟡 | A speed and latency report is built but off by default (`--speed-report`) |
| 14 | Employee efficiency reporting | ❌ | Per-device usage only, no work metrics (the PDF itself warns against equating the two) |

## Section 2: Derived features (15–40)

| # | Feature | Status | What exists |
|---|---|---|---|
| 15 | Self-healing network | 🟡 | Services restart themselves, the gate re-applies itself, and deploys roll back. Network faults aren't repaired |
| 16 | Predictive fault detection | ❌ | — |
| 17 | Intelligent bandwidth distribution | ❌ | Manual limits only |
| 18 | Time-based access control | ❌ | Caps reset daily/weekly/monthly, but there are no access schedules |
| 19 | Unauthorized device quarantine | 🟡 | New devices are held until approved, but that only cuts their internet access. They can still reach devices on the LAN (for example the Pi's open remote-desktop ports) |
| 20 | Secure guest network | ❌ | The routers support one; not set up |
| 21 | Automatic ISP failover | ❌ | The routers support it, but there is one internet line and it isn't set up |
| 22 | User experience monitoring | ❌ | Latency checks only |
| 23 | High-usage app identification | 🟡 | Biggest connections by service and port, plus top sites per device. Not true app identification |
| 24 | Automatic network mapping | 🟡 | The live map shows routers, devices and mesh links; no switches or full topology |
| 25 | Bottleneck detection | ❌ | — |
| 26 | Learning from previous incidents | ❌ | — |
| 27 | Arabic natural-language control | ❌ | `ask.py` takes English keywords and exists only in this repo |
| 28 | Arabic AI explanatory reports | ❌ | The report's AI sentence is in English and doesn't suggest fixes |
| 29 | Multi-branch comparison | ❌ | Single site |
| 30 | Network health score | ❌ | — |
| 31 | Offline monitoring | ✅ | Gate, monitoring, recording and the local AI keep running during an outage; alerts go out when the internet returns |
| 32 | Automatic configuration backups | 🟡 | Deploys keep the previous code version. Router settings, the allow/deny lists and the calibration file aren't backed up |
| 33 | Safe configuration rollback | ✅ | For code deploys: health checks, automatic rollback, dead man's switch. Not for hand-made router changes |
| 34 | Cost optimization recommendations | ❌ | — |
| 35 | Malicious website protection | ❌ | Port rules only; no domain blocking (the ad-blocker belongs to another team) |
| 36 | Security risk scoring | ❌ | This repo's threat flags exist but aren't deployed; no vulnerability scoring |
| 37 | Centralized branch management | ❌ | Single site |
| 38 | Verification of sensitive commands | ❌ | Email commands run immediately, with no second approval |
| 39 | Departmental usage reports | ❌ | Per device only |
| 40 | Automated root-cause diagnosis | ❌ | Tells "internet down" apart from "device missing", but nothing finer |

## Section 3: AI features (41–45)

| # | Feature | Status | What exists |
|---|---|---|---|
| 41 | Virtual AI network engineer | 🟡 | Claude Code on the Pi already does this: it works in Arabic, diagnoses problems, writes reports, and every change needs the owner's approval. But it's cloud AI, not the local model |
| 42 | Behavioral fingerprinting | 🟡 | The nightly report has an anomaly section. The per-device "compared with its own history" model exists only in this repo |
| 43 | Pre-deployment validation | 🟡 | Deploys run tests and checksums first; no policy-conflict checking |
| 44 | Unknown device classification | 🟡 | Vendor from the hardware address plus hostnames, no AI classification. Phones' random addresses defeat the vendor lookup |
| 45 | Measuring improvement value | ❌ | — |

---

## The 14 partly-there features: how to finish each

Anything built goes into **`Manarat-Cyber`** (the deployed repo) and ships through
`deploy.sh` / `deploy-router.sh`, with their tests and rollback.

### Quick to finish

| # | Feature | Missing | To finish |
|---|---|---|---|
| 13 | Speed analysis | Built but switched off | Add `--speed-report --speed-latency-only` to the router's config (latency only, almost no data use). Run a full download test hourly. Add a speed trend to the nightly report |
| 32 | Config backups | Router settings, allow/deny lists, port rules, caps and the calibration file aren't backed up | A nightly job on the Pi that pulls each router's built-in backup (`sysupgrade -b`), StreamWatch's state files and `mesh_calibration.json`. It keeps 30 days and comes with a restore script. **The backups contain Wi-Fi and Gmail passwords: encrypted on the Pi, never in git** |
| 06 | Email sender verification | Only the From address is checked, and it can be forged | Accept a command only when Gmail's sender-authentication check (DKIM/SPF) passes for the owner's address. Optionally also require a short PIN in the command |
| 41 | AI network engineer | It works (Claude Code on the Pi), but it's cloud AI with no playbook | A playbook in the repo: system layout, safe commands, deploy rules (this file's sibling `CLAUDE.md` is the start). A fully local version needs a far bigger model than the Pi can run |
| 12 / 42 | Historical analysis + behavioral fingerprinting | The trend model and threat rules exist only in this repo | Move them into `Manarat-Cyber` with their tests. Add a "this week vs last week" section and per-device "unusual for this device" flags to the nightly report |
| 43 | Pre-deployment validation | Tests and checksums only; no "would this lock us out?" check | A validator that runs before every deploy and every email command. It refuses any change that would remove the Pi or the owner's laptop from the allow list, block DNS/DHCP for everyone, or cut SSH from the Pi. Also add the tracker tests to the deploy gate |

### Medium

| # | Feature | Missing | To finish |
|---|---|---|---|
| 19 | Quarantine | Held devices lose internet but can still reach the LAN | First, the Pi's firewall drops traffic from devices that aren't on the allow list (this also closes the VNC/RDP hole). Then put unapproved devices on an isolated network on the routers |
| 23 | App identification | Ports and site names, not "YouTube used 3 GB" | Match each connection to the site name it was looked up as, then map sites to apps with a small table (googlevideo.com → YouTube, nflxvideo.net → Netflix). Report the top apps per device. Traffic over encrypted DNS stays "unknown" |
| 24 | Network mapping | Positions, not topology | A topology tab on the existing map: gateway → mesh nodes → devices, wired vs Wi-Fi, link strength, all from data already collected. Unmanaged switches can't be discovered |
| 44 | Device classification | Vendor and hostname only | A rules-based classifier using hostname patterns, the DHCP fingerprint, the random-address bit (almost always a phone or laptop), ports seen (printers 631/9100, cameras 554) and traffic shape (cameras upload constantly) |
| 10 | Offline AI | Narrates only | Give the local model the detectors' findings. It explains each one and picks a remedy from a fixed list of safe actions. Keep the number checking |
| 15 | Self-healing | Services heal, the network doesn't | A short whitelist of safe automatic actions, each rate-limited, logged and emailed (for example, restart the internet connection once if it has been down 5 minutes). Nothing beyond the whitelist |

### Large

| # | Feature | Missing | To finish |
|---|---|---|---|
| 04 | Unified login | One shared password, no per-user accounts | WPA-Enterprise with a login server on the Pi, so each person gets their own revocable login, and identity follows the person (this also fixes the random-address problem). IoT devices that can't do this stay on a separate password network |

### Suggested order

1. **#32 backups.** The calibration file and router settings are one dead SD card away from being lost.
2. **#06 sender verification.** Today a forged email could send commands to the router.
3. **#13 speed analysis.** Practically a config change.
4. **#12/#42**, then **#43.** The code mostly exists already.
5. **#19**, together with closing VNC/RDP.
