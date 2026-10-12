# StreamWatch — scope & AI-model framework

Two things live here:

1. **Board coverage** — every item on the project whiteboard, what implements
   it, and where it lands in the recorder's AI CSV.
2. **AI-model framework** — the per-device relationships the server-side model
   is meant to learn, mapped to the data that feeds them, with the gaps called
   out honestly.

The authoritative requirements are the SRS; this file is the traceability
view from the board and the data.

---

## 1. Board coverage

| # | Board item | Implemented by | Record type(s) / columns | Status |
|---|------------|----------------|--------------------------|--------|
| 1 | All IP – MAC – Port | device identity + port scan | `device_inventory`, `dhcp_lease`, `open_port`; `device_ip`/`device_mac`/`dst_port` | done |
| 2 | Traffic / data transfer (consumption + speed) | conntrack accounting + speed probe | `device_traffic`, `flow_end`, `flow_active`, `sw_usage`, `internet_latency` | done |
| 3 | Date – Time | on every row | `timestamp`, `date`, `time`, `epoch` | done |
| 4 | Browsing site-address history | dnsmasq query logging | `dns_query` (`domain`) | done |
| 5 | Location by dB signal + coordinates | mesh tracker | `device_position` (`rssi_dbm`,`lat`,`lon`,`dist_m`), `station_config` | done (tracker running) |
| 6 | Group (authorized) | allow/deny lists + default-deny gate | `internet_access` (GRANTED/BLOCKED/HELD) | done |
| 7 | Device tracing | position every 10 s + events | `device_position`, `tracker_event` | done |
| 8 | Control / limitation (bandwidth, block/allow ip-port) | quotas, throttle, port rules | `sw_quota`, `sw_throttle`, `open_port` | done — **Adblocker is a separate team** |
| 9 | Malfunction (no-internet history, device not connected) | outage + presence monitors | `malfunction` | done |
| 10 | IoT (sensor) on/off switch | — | — | **not built (TBD)** |
| 11 | Forbidden area | tracker zone + gate cuts internet | `tracker_event` (forbidden), `internet_access` | coded; needs zone configured |
| 12 | Attack | — | — | **not built (TBD)** |

---

## 2. AI-model framework — per-device (per-IP) relationships

The model reasons about **devices**, keyed on **MAC** (the stable identity); the
IP is shown but is only a lease and must not be the key. Everything is
**metadata** — domains, flow sizes, ports, timing, signal — never page or file
contents (PRV-4), within the consented household scope (BR-7).

| Relationship asked for | Built from | Status | Where |
|------------------------|------------|--------|-------|
| Data usage (incl. internet access) | `device_traffic`, `sw_usage`, `internet_access` | ready | `device_report.py` |
| Browsing data | `dns_query` | ready | `device_report.py` |
| File transfer | `flow_end`/`flow_active` size + service/port (inferred, no contents) | inferred | `device_report.py` (biggest / large flows) |
| Log in / log out (join & leave network) | `tracker_event` ARRIVED/LEFT, Wi-Fi assoc, `dhcp_lease` | ready | `device_report.py` (sessions) |
| Longest online interval (sort by date/time) | sessionized presence | ready | `device_report.py` (sorted longest-first) |
| Fast log in / log out (flapping) | short/repeated sessions | ready | `device_report.py` (`fast_flaps`) |
| Internet-speed impact | `internet_latency` time-joined with each device's rate/bytes | **next** | — |
| Location ↔ usage (bytes per node) | `device_position` + `device_traffic` time-join | **next** | nodes listed; per-node split pending |
| Download that affects the system | big inbound flow + a NEW `open_port` appearing after | **next** | overlaps board #12 (Attack); needs host-level signal |

### Design rules for the model
- **Key on MAC, not IP.** A lease rotates and can move to another device.
- **Randomized MACs.** One phone can appear as several identities until
  "Private Wi-Fi Address" is turned off for the network.
- **Metadata only.** Domains and flow sizes/ports, never contents.
- **Consent.** Household devices, with the household's knowledge.

### The model: classical ML, offline, on the server
Chosen approach: **classical ML, run locally** — no cloud API, no data leaving
the network (PRV). First model shipped: a robust anomaly detector.

- `device_report.py` — one section per device (online time, data, browsing,
  file transfer, sessions/flaps, location, access), sorted longest-online
  first; `--csv` writes a per-device feature table for the model.
- `history.py` — the time-ordered activity log of meaningful events.
- `anomaly_model.py` — reads the feature table, learns each feature's median
  and MAD across devices (robust: the outliers don't skew the baseline),
  log-scales heavy-tailed features, and scores every device by its most
  extreme robust z-score; past `--threshold` it is flagged, with the features
  that drove the flag named (explainable, not a black box). Pure stdlib — no
  pip, no GPU, runs on the Pi, fully offline. fit()/score() is a drop-in slot:
  swap in scikit-learn's IsolationForest later without changing the contract.

Pipeline:
```
python3 device_report.py --csv ~/features.csv   # build the feature table
python3 anomaly_model.py ~/features.csv          # flag the odd device(s)
```

- `trend_model.py` — **per-device-over-time**: one feature row per device per
  day, scores each device's latest day against ITS OWN prior days (robust
  median/MAD, high side only), so a device is flagged when it deviates from
  itself — not for merely differing from the others. A flat baseline broken
  upward (e.g. a first-ever block) is flagged too. Needs `--min-days`+1 days of
  history per device; reuses anomaly_model's math. Also in `ask.py` as `trend`.

Model roadmap (all classical, all local):
- DONE: score a device against its OWN history over time (`trend_model.py`).
- once the three "next" features land (speed impact, per-node usage, download
  that affects the system), they become model inputs too;
- optional upgrade to scikit-learn (IsolationForest / clustering) if installed,
  behind the same fit()/score() interface.

### The three "next" items, concretely
1. **Speed impact** — bin time (e.g. 1 min), take latency per bin from
   `internet_latency`, attribute each high-latency bin to the top data user in
   that bin; per device, count "high-latency minutes where it was the top
   talker".
2. **Location ↔ usage** — for each `device_traffic` interval, join the device's
   nearest `device_position` to split bytes per node (L1/L2/L3).
3. **Download affects system** — flag a large inbound `flow_end` followed within
   a short window by a NEW `open_port` on the network; this is the Attack (#12)
   surface and should also pull a host-level integrity signal, not flow size
   alone.
