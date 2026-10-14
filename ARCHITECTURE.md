# StreamWatch — Architecture

How the system is built: the nodes, the data flow, and the layers. Organized
by the same six sections, viewed through the architecture.

---

## 1) Goal (architecturally)

A **three-tier, offline** pipeline: **collect** on the mesh → **record** to one
flat file on a companion host → **analyze/model/serve** on that host. Each tier
is replaceable and testable in isolation; nothing depends on the cloud; the only
outbound traffic is optional email alerts and internet-reachability probes.

## 2) Current State — the system in one picture

```
                         INTERNET
                            │  (WAN)
                    ┌───────┴────────┐
                    │   main123      │  gateway / GL-MT3000 / OpenWrt 24.10
                    │  192.168.8.1   │  ── streamwatch_v12.py (procd service) ──
                    │   L1           │   • allow/deny GATE (default-deny, MAC)
                    └──┬────────┬────┘   • per-port block/allow, quota, throttle
             802.11s   │        │        • email command channel (SMTP/IMAP)
             mesh ┌────┴──┐  ┌──┴────┐    • malfunction detect (outage/missing)
                  │ acf   │  │ 456   │    • writes: dnsmasq query log, conntrack,
                  │ .2 L2 │  │ .3 L3 │             /root/.streamwatch_{emails,health}.log,
                  └───┬───┘  └───┬───┘             /etc/streamwatch/{allow,deny}.txt
                      │          │
                 Wi-Fi clients (phones, laptops, IoT)
                      │
                 ┌────┴─────────────────────────────┐
                 │  Raspberry Pi  192.168.8.162      │  companion host (systemd)
                 │  ── mesh_tracker.py ──► positions │
                 │  ── mesh_recorder.py ─────────────┼─► ~/mesh_records/
                 │       pulls from all nodes over   │     records_YYYY-MM-DD.csv(.gz)
                 │       SSH, one unified AI CSV      │     DATA_DICTIONARY.md
                 └───────────────┬───────────────────┘
                                 │  (same CSV, read-only)
          ┌──────────────────────┼───────────────────────────┐
          ▼                      ▼                            ▼
   device_report.py        anomaly_model.py             history.py
   (features + --csv)      trend_model.py               threats.py
          │                 (classical ML, offline)            │
          └──────────┬───────────────┬─────────────────────────┘
                     ▼               ▼
                  ask.py        report_mailer.py ──► email (SMTP)
              (offline terminal)  (systemd timer, --only-flagged)
```

**Tier A — Collect & control** (`streamwatch_v12.py` on the gateway,
`mesh_tracker.py` on the Pi). Enforces policy at the gateway with iptables
(chains `SW_GATE`/`SW_ZONE`/`SW_PORTS`), identifies devices by **MAC**
(Data.Identity), and emits raw signals: dnsmasq query logs, conntrack byte
counts, radio assoc lists, `ip neigh`, and its own email/health JSON logs.

**Tier B — Record** (`mesh_recorder.py` on the Pi). SSH-pulls each node and
normalizes everything into **one unified CSV**: 54 columns, 24 `record_type`s
(device_position, dns_query, device_traffic, flow_end, internet_access,
malfunction, email, open_port, …). One row per observation; a generated data
dictionary documents every column.

**Tier C — Analyze / model / serve** (the rest, pure stdlib, read-only on the
CSV). A feature layer, two models, a threat rule, a terminal, and a mailer.

## 3) Active Status — what is a process vs a function call

- **Long-running processes:** `streamwatch_v12.py` (gateway, procd),
  `mesh_tracker.py` + `mesh-recorder` + `report-mailer.timer` (Pi, systemd).
- **On-demand libraries/CLIs:** `device_report`, `history`, `anomaly_model`,
  `trend_model`, `threats`, `ask`. Each is importable (functions return data)
  and runnable (a thin `main()`); the models hold no state between runs.
- **The one shared artifact** every Tier-C tool reads is the CSV directory;
  they never talk to each other, only to the file. This is deliberate: the
  pipeline is a file, so any tool can be added, replaced, or run alone.

## 4) Changes Made — key design decisions

- **One flat CSV, not a database.** Append-only, self-describing, greppable,
  survives restarts; finished days are gzipped. Trade-off: readers must skip
  stray/legacy rows (they do — `epoch_of()` guards).
- **Identity is the MAC, never the IP.** IP is a lease; keying on it would
  mix devices. Tools resolve IP→MAC and show the IP as a label only.
- **Metadata only (PRV-4).** Browsing = domains, flows = sizes/ports/timing —
  never page or file contents.
- **Robust statistics (median/MAD), not mean/stdev.** The outliers we hunt must
  not define "normal". Heavy-tailed features are log-scaled; scoring is
  high-side only (excess, not quiet).
- **Two complementary models.** `anomaly_model` (device vs peers) and
  `trend_model` (device vs its own history) share one `fit()/score()` contract,
  so scikit-learn can drop in later without touching callers.
- **Block overrides allow (BR-2); default-deny gate (BR-1).** Enforced in
  `streamwatch_v12.py` and mirrored in every consumer.
- **Offline by construction.** No tool makes an outbound call except
  `report_mailer` (SMTP) and the reachability probe; everything else is local.

## 5) Failed Attempts — architectural dead ends

- **Per-minute emailing** — not a cadence a free mail account survives; the
  mailer is built for any interval and defaults to 15 min + only-on-flag.
- **Cross-device-only anomaly detection** — structurally can't tell "unusual"
  from "the one server among phones" at small N; required adding the
  per-device-over-time model as a second, independent scorer.
- **Trusting per-sample rate (`rate_in_kbps`)** — counter resets produced
  3.4 Gbps artifacts; readers cap at a sane ceiling, and true speed-impact will
  be computed from byte deltas over real intervals (a planned Tier-C addition).
- **`scp`/sftp to OpenWrt** — unavailable; deploys stream over `ssh 'cat >'`.

## 6) Next Steps — where new code attaches

- **New analysis** = a new Tier-C script that reads the CSV and (optionally)
  writes features; it needs no change to A or B. The three remaining framework
  features (speed impact, per-node usage, download-affects-system) land here.
- **New daily inputs to the model** = extend `trend_model.build_daily()` and the
  shared `FEATURES` list; both models pick them up.
- **Model upgrade** = implement `fit()/score()` with scikit-learn behind the
  same interface; `ask.py`, `report_mailer.py` and the CLIs are unaffected.
- **Rotating-MAC stitching** = a resolver that collapses private MACs into one
  identity, applied in `device_report.key_of()` so the whole tier benefits.
- **Operational** = the gateway and Pi run deployed copies; `git pull` on the
  Pi and the `ssh 'cat >'` deploy on the gateway are the only "release" steps.

See `README.md` for the overview, `REQUIREMENTS.md` for board/feature
traceability, and `handoff.md` for the operator runbook.
