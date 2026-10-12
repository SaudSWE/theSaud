#!/usr/bin/env python3
"""An offline terminal to the StreamWatch model and data.

Type a command (or a plain phrase with a keyword) and it answers from the
local AI CSV -- no internet, no cloud, no LLM. It is a COMMAND shell, not a
chat bot: it matches keywords and device names, it does not understand free
conversation. Classical and deterministic, which is the point.

  ask.py                      open the interactive terminal
  ask.py anomalies            run one command and exit (scriptable)
  ask.py "data iphone"        quoting lets a command take arguments
  ask.py --hours 6 flagged    judge only the last 6 h (default 24; 0 = all time)

COMMANDS (plain phrasing with these words works too):
  help                        this list
  online [device]             who was online and for how long (longest first)
  data [device]               data usage, biggest first
  browsing <device>           the sites a device looked up
  device <device>             everything on one device
  anomalies [threshold]       Eagle-Eye's cross-device scan: who stands out, and why
  flagged [threshold]         only the devices Eagle-Eye flags
  trend [threshold]           per-device vs its OWN history: who's abnormal today
  threats                     fast log in/out + unknown entrances, flagged
  history [device]            recent activity events
  email [all]                 TASK: build the report and email it now
                              (default only if a device is flagged; 'all' = always)
  window <hours|all>          look at the last N hours (default 24) or all time
  reload                      re-read the data from disk
  quit                        leave

A <device> is any part of an IP, MAC or name (e.g. 135, iphone, 88:a2).
"""
import contextlib
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import device_report          # noqa: E402
import eagle_eye          # noqa: E402
import history                # noqa: E402

DEFAULT_DIR = os.path.expanduser("~/mesh_records")
HOURS = 24                 # default window; 0 = all time


class Context:
    def __init__(self, folder, hours=HOURS):
        self.folder = folder
        self.hours = hours
        self.reload()

    def reload(self):
        self.rows = device_report.load(self.folder)
        self.agg = device_report.aggregate(self.rows, since=device_report.since_hours(self.hours))
        self.stations = device_report.collect_station_ips(self.rows)
        self.devices = device_report.select(self.agg, self.stations)


def capture(func, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        func(*a, **k)
    return buf.getvalue().rstrip()


def find_device(ctx, token):
    t = token.lower()
    for d in ctx.devices:
        if t in d["mac"].lower() or t in (d["ip"] or "").lower() or t in (d["name"] or "").lower():
            return d
    return None


def fmt_dur(sec):
    return device_report.human_dur(sec)


def cmd_online(ctx, who):
    ds = ctx.devices                      # already sorted longest-online first
    if who:
        d = find_device(ctx, who)
        if not d:
            return "no device matches %r" % who
        return "%s (%s) was online %s over %d session(s); longest %s; %d fast in/out." % (
            d["name"] or d["mac"], d["ip"], fmt_dur(d["online_s"]), d["sessions"],
            fmt_dur(d["longest_session_s"]), d["fast_flaps"])
    out = ["Time online, longest first:"]
    for d in ds:
        out.append("  %-16s %-15s %-14s %d session(s)" %
                   (d["name"] or d["mac"], d["ip"] or "", fmt_dur(d["online_s"]), d["sessions"]))
    return "\n".join(out) if ds else "no devices yet."


def cmd_data(ctx, who):
    if who:
        d = find_device(ctx, who)
        if not d:
            return "no device matches %r" % who
        return "%s (%s): %s down, %s up, %s total; peak %.0f kbps." % (
            d["name"] or d["mac"], d["ip"], device_report.human(d["bytes_in"]),
            device_report.human(d["bytes_out"]), device_report.human(d["bytes_total"]),
            d["peak_rate_kbps"])
    ds = sorted(ctx.devices, key=lambda d: d["bytes_total"], reverse=True)
    out = ["Data usage, biggest first:"]
    for d in ds:
        out.append("  %-16s %-15s %s" %
                   (d["name"] or d["mac"], d["ip"] or "", device_report.human(d["bytes_total"])))
    return "\n".join(out) if ds else "no devices yet."


def cmd_browsing(ctx, who):
    if not who:
        return "which device? e.g. 'browsing 192.168.8.135'"
    d = find_device(ctx, who)
    if not d:
        return "no device matches %r" % who
    hist = capture(history.main, ["--dir", ctx.folder, "--browsing", who])
    sites = [l for l in hist.splitlines() if " dns_query " in l][-15:]
    head = "%s (%s): %d lookups, %d distinct sites." % (
        d["name"] or d["mac"], d["ip"], d["dns_queries"], d["distinct_domains"])
    return head + ("\n" + "\n".join(sites) if sites else "")


def cmd_device(ctx, who):
    if not who:
        return "which device? e.g. 'device iphone'"
    if not find_device(ctx, who):
        return "no device matches %r" % who
    return capture(device_report.report, ctx.devices, [who])


def cmd_scan(ctx, arg, flagged_only=False):
    try:
        th = float(arg) if arg else eagle_eye.THRESHOLD
    except ValueError:
        th = eagle_eye.THRESHOLD
    ranked, _ = eagle_eye.rank(ctx.devices, threshold=th)
    if flagged_only:
        ranked = [d for d in ranked if d["anomaly"]]
        if not ranked:
            return "nothing flagged at %.1f sigma -- all devices look normal." % th
    out = ["%s scan (%s, threshold %.1f sigma):" % (eagle_eye.NAME, device_report.window_label(ctx.hours), th)]
    for d in ranked:
        mark = "  !! THREAT" if d["threats"] else "  !! FLAGGED" if d["anomaly"] else ""
        out.append("  %-16s %-15s score %5.2f%s" %
                   (d["name"] or d["mac"], d["ip"] or d["mac"], d["score"], mark))
        for t in d["threats"]:
            out.append("        ! %s" % t)
        for col, z in d["reasons"][:3]:
            out.append("        - %s high (%.1f sigma)" % (col, z))
    return "\n".join(out) if len(out) > 1 else "no devices to score."


def cmd_threats(ctx, arg):
    import threats
    return capture(threats.main, ["--dir", ctx.folder])


def cmd_trend(ctx, arg):
    import trend_model
    try:
        th = float(arg) if arg else eagle_eye.THRESHOLD
    except ValueError:
        th = eagle_eye.THRESHOLD
    return capture(trend_model.main, ["--dir", ctx.folder, "--threshold", str(th)])


def cmd_history(ctx, who, n=25):
    evs = history.events(ctx.rows, match=[who] if who else ())
    if not evs:
        return "no activity events%s." % (" for %r" % who if who else "")
    return "\n".join(history.format_event(e) for e in evs[-n:])


def cmd_email(ctx, arg):
    import report_mailer
    only_flagged = not (arg and arg.lower() in ("all", "always", "force"))
    args = ["--dir", ctx.folder, "--hours", str(ctx.hours)] + (["--only-flagged"] if only_flagged else [])
    return capture(report_mailer.main, args)


HELP = __doc__.strip()


def handle(line, ctx):
    line = line.strip()
    if not line:
        return ""
    parts = line.split()
    word = parts[0].lower()
    rest = " ".join(parts[1:]).strip()
    low = line.lower()

    # a device token anywhere in the phrase, for natural phrasing
    dev_tok = ""
    for p in parts[1:]:
        if find_device(ctx, p):
            dev_tok = p
            break

    if word in ("help", "?", "commands"):
        return HELP
    if word in ("quit", "exit", "q", "bye"):
        return None
    if word in ("window", "last", "since"):
        if rest.lower() in ("all", "0", "ever"):
            ctx.hours = 0
        else:
            try:
                ctx.hours = float(rest.lower().rstrip("h"))
            except ValueError:
                return "usage: window <hours>  or  window all   (now: %s)" % device_report.window_label(ctx.hours)
        ctx.reload()
        return "window: %s -- %d device(s)" % (device_report.window_label(ctx.hours), len(ctx.devices))
    if word in ("reload", "refresh"):
        ctx.reload()
        return "reloaded: %d device(s) from %s" % (len(ctx.devices), ctx.folder)
    if ("threat" in low or "intrud" in low or "entrance" in low or "log in" in low
            or "login" in low or "log out" in low or word in ("threats", "logins", "entrances")):
        return cmd_threats(ctx, rest)
    if word == "trend" or "trend" in low or "over time" in low or "its own" in low:
        return cmd_trend(ctx, rest)
    if "anomal" in low or word in ("scan", "model"):
        return cmd_scan(ctx, rest)
    if "flag" in low:
        return cmd_scan(ctx, rest, flagged_only=True)
    if "brows" in low or "site" in low or "visit" in low:
        return cmd_browsing(ctx, dev_tok or rest)
    if "email" in low or "send" in low or (word == "report" and "mail" in low):
        return cmd_email(ctx, rest)
    if "history" in low or "activity" in low or word == "log":
        return cmd_history(ctx, dev_tok)
    if word in ("online", "connected", "who") or "how long" in low or "online" in low:
        return cmd_online(ctx, dev_tok)
    if word in ("data", "usage") or "usage" in low or "consum" in low or "data" in low:
        return cmd_data(ctx, dev_tok)
    if word in ("device", "show", "detail", "report") or dev_tok:
        return cmd_device(ctx, dev_tok or rest)
    return "not sure what you mean. type 'help' for commands."


def main(argv):
    folder, hours = DEFAULT_DIR, HOURS
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--dir" and i + 1 < len(argv):
            folder = argv[i + 1]; i += 2; continue
        if argv[i] == "--hours" and i + 1 < len(argv):
            hours = float(argv[i + 1]); i += 2; continue
        rest.append(argv[i]); i += 1
    if not os.path.isdir(folder):
        print("no records folder: %s" % folder); return 1
    ctx = Context(folder, hours)

    if rest:                               # one-shot mode
        out = handle(" ".join(rest), ctx)
        if out:
            print(out)
        return 0

    print("StreamWatch offline terminal -- %d device(s), %s. Type 'help', 'quit' to leave."
          % (len(ctx.devices), device_report.window_label(ctx.hours)))
    while True:
        try:
            line = input("ask> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        out = handle(line, ctx)
        if out is None:
            break
        if out:
            print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
