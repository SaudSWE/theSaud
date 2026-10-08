#!/usr/bin/env python3
"""Item 9 -- malfunction detection: internet outages (with history) and
devices that should be present going missing. No router needed.

    python3 tests/test_detect.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", file))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sw = load("sw", "streamwatch_v12.py")
mr = load("mr", "mesh_recorder.py")
PASS, FAIL = [0], [0]


def check(name, cond):
    (PASS if cond else FAIL)[0] += 1
    print("  %s %s" % ("ok  " if cond else "FAIL", name))


print("outage detection (3 misses = DOWN, dated from the first miss):")
m = sw.OutageMonitor(fail_n=3)
check("up -> nothing", m.step(100, True) is None)
check("1st miss -> nothing yet", m.step(110, False) is None)
check("2nd miss -> nothing yet", m.step(120, False) is None)
ev = m.step(130, False)
check("3rd miss -> internet_down", ev and ev["kind"] == "internet_down")
check("dated from first failed probe", ev["t"] == 110 and ev["confirmed_at"] == 130)
check("further misses -> no repeat alert", m.step(140, False) is None)
ev = m.step(560, True)
check("back -> internet_up", ev and ev["kind"] == "internet_up")
check("outage length = 450 s", ev["duration_s"] == 450 and ev["down_since"] == 110)
check("steady up -> nothing", m.step(570, True) is None)

print("\none or two blips are not an outage:")
m = sw.OutageMonitor(fail_n=3)
check("miss, miss, ok -> no event",
      [m.step(1, False), m.step(2, False), m.step(3, True)] == [None, None, None])
check("counter reset after recovery", m.step(4, False) is None and m.step(5, False) is None)

print("\ndevice not connected:")
p = sw.PresenceMonitor(missing_after=300)
A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
check("both present -> nothing", p.step(0, {A, B}, {A, B}) == [])
check("A gone 200 s -> still within grace", p.step(200, {A, B}, {B}) == [])
ev = p.step(300, {A, B}, {B})
check("A gone 300 s -> device_missing", len(ev) == 1 and ev[0]["kind"] == "device_missing"
      and ev[0]["mac"] == A and ev[0]["last_seen"] == 0)
check("no repeat while still missing", p.step(400, {A, B}, {B}) == [])
ev = p.step(900, {A, B}, {A, B})
check("A back -> device_back with how long", ev[0]["kind"] == "device_back"
      and ev[0]["duration_s"] == 900)
check("newly watched device gets a grace period", p.step(901, {A, B, "cc"}, {A, B}) == [])
p.step(1300, {A, B, "cc"}, {A, B})
check("removing a missing device from the list forgets it",
      p.step(1301, {A, B}, {A, B}) == [] and "cc" not in p.missing)

print("\nhealth log:")
sw.HEALTH_LOG = os.path.join(tempfile.mkdtemp(), "health.log")
sw.health_log("internet_down", t=110, detail="no answer")
sw.health_log("internet_up", t=560, duration_s=450, detail="down from a to b")
lines = [json.loads(x) for x in open(sw.HEALTH_LOG)]
check("two JSON events with their own times",
      [(x["kind"], x["t"]) for x in lines] == [("internet_down", 110), ("internet_up", 560)])
check("human duration", sw.human_dur(450) == "7 min 30 s" and sw.human_dur(3725) == "1 h 2 min")
sw.wifi_rssi_map = lambda ttl=5: {"aa:bb:cc:dd:ee:09": {}}
sw.run = lambda cmd, timeout=5: (
    "192.168.8.5 dev br-lan lladdr aa:bb:cc:dd:ee:05 REACHABLE\n"
    "192.168.8.6 dev br-lan lladdr aa:bb:cc:dd:ee:06 STALE\n")
check("radio + REACHABLE counted, STALE not",
      sw.present_macs() == {"aa:bb:cc:dd:ee:09", "aa:bb:cc:dd:ee:05"})

print("\nAI CSV malfunction rows:")
dump = "## SYS\nUPTIME 1\n## HEALTH\n" + "\n".join(json.dumps(x) for x in [
    {"t": 1791382000, "kind": "internet_down", "detail": "no answer", "down_since": 1791382000},
    {"t": 1791382450, "kind": "internet_up", "duration_s": 450, "detail": "down from x to y",
     "down_since": 1791382000, "restored": 1791382450},
    {"t": 1791382600, "kind": "device_missing", "mac": "d6:95:79:3b:1c:4a",
     "ip": "192.168.8.135", "name": "iPhone", "detail": "not seen since z"},
]) + "\n## END\n"
d = mr.parse_router(dump)
r = mr.Recorder(types.SimpleNamespace(out=tempfile.mkdtemp(), lan_prefix="192.168.8."))
rows = r.health_rows(d)
check("one malfunction row per event", [x["record_type"] for x in rows] == ["malfunction"] * 3)
check("states DOWN / UP / MISSING", [x["state"] for x in rows] == ["DOWN", "UP", "MISSING"])
check("outage row carries the duration", rows[1]["duration_s"] == 450)
check("rows dated by the event, with date/time", rows[0]["epoch"] == 1791382000
      and rows[0]["date"] and rows[0]["time"])
check("device columns on device rows", rows[2]["device_mac"] == "d6:95:79:3b:1c:4a"
      and rows[2]["device_name"] == "iPhone")
import time as _t
cut = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(1791382000))
back = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(1791382450))
check("cut row: cut date/time, no restored yet",
      (rows[0]["cut_date"] + " " + rows[0]["cut_time"]) == cut and rows[0]["restored_date"] == "")
check("restored row: cut AND restored date/time on one row",
      (rows[1]["cut_date"] + " " + rows[1]["cut_time"]) == cut
      and (rows[1]["restored_date"] + " " + rows[1]["restored_time"]) == back)
check("device rows leave the outage columns empty", rows[2]["cut_date"] == "")
check("polled again -> no duplicates", r.health_rows(d) == [])
check("dictionary has the cut/restored columns",
      all(c in mr.FIELDS for c in ("cut_date", "cut_time", "restored_date", "restored_time")))
check("dictionary documents malfunction",
      "malfunction" in dict((x[0], x[1]) for x in mr.RECORD_TYPES))

print("\nalert email retried, not lost, when the first send fails:")


class FakeSMTP:
    fails, tries = 0, 0

    def __init__(self, *a, **k):
        FakeSMTP.tries += 1
        if FakeSMTP.tries <= FakeSMTP.fails:
            raise OSError("Connection unexpectedly closed: timed out")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        pass

    def login(self, u, p):
        pass

    def send_message(self, m):
        pass


class SyncThread:
    def __init__(self, target, daemon=None):
        self.target = target

    def start(self):
        self.target()


real_smtp, real_thread, real_sleep = sys.modules.get("smtplib"), sw.threading.Thread, sw.time.sleep
sys.modules["smtplib"] = types.SimpleNamespace(SMTP=FakeSMTP)
sw.threading.Thread = SyncThread
slept = []
sw.time.sleep = slept.append
cfg = {"server": "smtp.x", "port": 587, "user": "sw@x", "password": "p", "to": "admin@x"}
try:
    sw.EMAIL_LOG = os.path.join(tempfile.mkdtemp(), "emails.log")
    FakeSMTP.fails, FakeSMTP.tries = 2, 0
    sw._detect_mail(cfg, "[streamwatch] internet was DOWN for 1 min 0 s",
                    "streamwatch - internet outage\n")
    log = [json.loads(x) for x in open(sw.EMAIL_LOG)]
    check("two timeouts, then sent", [x["dir"] for x in log] == ["failed", "failed", "sent"])
    check("waits follow the retry schedule", slept == list(sw.DETECT_MAIL_RETRY[:2]))
    check("failed rows say a retry is coming",
          "retrying in 30 s" in log[0]["detail"] and "retrying in 60 s" in log[1]["detail"])
    sw.EMAIL_LOG = os.path.join(tempfile.mkdtemp(), "emails.log")
    FakeSMTP.fails, FakeSMTP.tries, slept[:] = 99, 0, []
    sw._detect_mail(cfg, "s", "b")
    log = [json.loads(x) for x in open(sw.EMAIL_LOG)]
    check("gives up after the schedule (1 + %d tries)" % len(sw.DETECT_MAIL_RETRY),
          len(log) == 1 + len(sw.DETECT_MAIL_RETRY) and all(x["dir"] == "failed" for x in log)
          and "retrying" not in log[-1]["detail"])
    sw.EMAIL_LOG = os.path.join(tempfile.mkdtemp(), "emails.log")
    FakeSMTP.fails, FakeSMTP.tries, slept[:] = 99, 0, []
    sw.send_email_alert("smtp.x", 587, "sw@x", "p", "admin@x", "s", "b")
    check("other alerts keep one attempt (no retry_waits)",
          FakeSMTP.tries == 1 and slept == [])
finally:
    sw.time.sleep, sw.threading.Thread = real_sleep, real_thread
    if real_smtp is None:
        sys.modules.pop("smtplib", None)
    else:
        sys.modules["smtplib"] = real_smtp

print("\n%d passed, %d failed" % (PASS[0], FAIL[0]))
sys.exit(1 if FAIL[0] else 0)
