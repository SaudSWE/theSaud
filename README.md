# StreamWatch Mesh Protection System

Offline network monitoring, control, and anomaly detection for a home 802.11s
Wi-Fi mesh. Runs entirely on your own hardware — no cloud, no data leaves the
network. **415 tests, pure Python standard library.**

---

## 1) Goal

Give a household one place to see and control its network: who is on it, what
each device is doing (data, browsing, file transfer, where it is, how long it
has been online), and to **act** on that — allow or block a device, cap or
throttle it, cut internet in a forbidden zone — plus an **offline, on-server
classical-ML layer** that flags abnormal devices and potential threats. Scope
comes from the project whiteboard (12 items) and the SRS; the design keeps all
data local (consented household monitoring, domain-level metadata only).

## 2) Current State

Three layers, all built and tested:

**Collect & control (on the mesh hardware)**
- `streamwatch_v12.py` — gateway daemon: default-deny allow/deny **gate**,
  per-port block/allow, quotas/throttle, email command channel, and
  **malfunction detection** (internet outage history + missing-device alerts),
  immune to the router's clock being stepped at boot.
- `mesh_recorder.py` — Raspberry Pi recorder: one unified **AI CSV** (54
  columns, 24 record types) with a generated `DATA_DICTIONARY.md`.
- `group_lists.py` — admin CLI for the allow/deny text files (keyed on MAC).

**Analyze & model (offline, on the server — all stdlib)**
- `device_report.py` — per-device feature report + `--csv` feature table.
- `history.py` — time-ordered activity log of meaningful events.
- `anomaly_model.py` — cross-device robust (median/MAD) anomaly detector.
- `trend_model.py` — per-device-over-time: each device vs **its own** history.
- `threats.py` — flags **fast log in/out** and **unknown entrances**.

**Use**
- `ask.py` — offline terminal: `online`, `data`, `browsing`, `anomalies`,
  `trend`, `threats`, `history`, `email`, …
- `report_mailer.py` + `systemd/` — scheduled build + email of the reports.

Whiteboard coverage: items **1–9 done**, **11 (forbidden area)** coded,
**Adblocker** is a separate team, **10 (IoT)** and **12 (Attack)** TBD. Full
traceability in `REQUIREMENTS.md`; design in `ARCHITECTURE.md`.

## 3) Active Status

| Component | Where | Runs | State |
|-----------|-------|------|-------|
| `mesh-recorder` | Pi | always (systemd) | **active** |
| `report-mailer.timer` | Pi | every 15 min, `--only-flagged` | enabled |
| StreamWatch (gate + detection) | gateway | always (procd) | **active** (PID 4074) |
| `device_report` / `history` / `anomaly_model` / `trend_model` / `threats` / `ask` | Pi | on demand | run by hand or by the mailer |

The models are **not** background services — they score when invoked (by you
or by the mailer).

## 4) Changes Made (newest first)

- `threats.py` — fast log in/out + unknown-entrance flagging (in `ask.py` as `threats`).
- `trend_model.py` — per-device-over-time anomaly model (`ask.py trend`).
- `ask.py` — offline terminal to query/command the model.
- `report_mailer.py` + systemd units — scheduled, emailed reports (safe defaults).
- `anomaly_model.py` — first classical-ML model; high-side-only scoring.
- `device_report.py` — per-device feature report; infra/glitch filtering.
- `history.py` — readable activity history.
- `mesh_recorder.py` — drop the router's own DNS/boot-log noise from the CSV.
- Earlier: item-9 malfunction detection, outage-email retry, clock-jump
  immunity, browsing capture, date/time/access/email columns, the group gate,
  per-port rules, forbidden-area enforcement.

## 5) Failed Attempts / Lessons

- **Email every minute** → would suspend the Gmail account (~1440/day); replaced
  with every-15-min + `--only-flagged`.
- **Cross-device anomaly detection at n=4** → flags the Pi for being the server;
  fixed quiet-device false flags (high-side only); the fix is `trend_model.py`.
- **MAD=0 masking** → identical history hides an outlier; handled with a
  mean-abs-dev fallback and a flat-baseline override in the trend model.
- **`scp` to OpenWrt** → no sftp-server; deploy with `cat f | ssh root@… 'cat > /root/f'`.
- **Restarting only the log service** cut dnsmasq from syslog → restart dnsmasq after.
- **A conversational AI** over the data isn't available (classical ML, no LLM);
  `ask.py` is a command interpreter, not a chat bot.

## 6) Next Steps

**Operational (on the hardware):** rotate the Gmail app password; pin the Pi to
the mesh Wi-Fi so it doesn't jump networks on reboot.

**Model roadmap (all classical, all local):** the three remaining framework
features — internet **speed impact**, **location↔usage** split, and
**download-that-affects-the-system** (overlaps the Attack item); **rotating-MAC
stitching** (one phone shows up as several private MACs); optional **scikit-learn
IsolationForest** behind the existing `fit()/score()` interface.

---

## Quickstart

```sh
git clone https://github.com/SaudSWE/theSaud.git && cd theSaud
python3 -m pytest -q           # or: for t in tests/test_*.py; do python3 $t; done

# analysis (reads ~/mesh_records on the Pi)
python3 device_report.py                 # per-device report
python3 anomaly_model.py ~/features.csv  # cross-device anomalies
python3 trend_model.py                   # each device vs its own history
python3 threats.py                       # fast log in/out + unknown entrances
python3 ask.py                           # interactive offline terminal
```

Deploy to the hardware with `git pull` on the Pi, and
`cat streamwatch_v12.py | ssh root@192.168.8.1 'cat > /root/streamwatch_v12.py'`
for the gateway (OpenWrt has no `scp`). See `handoff.md` for the full operator
guide and `ARCHITECTURE.md` for how the pieces fit.
