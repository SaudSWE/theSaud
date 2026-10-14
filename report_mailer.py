#!/usr/bin/env python3
"""Build the per-device reports and email them -- the scheduled job.

Run on the companion host (the Pi), by a timer. Each run it:
  1. builds the per-device report (device_report.py) -- the device-IP
     relationships: data usage, browsing, file transfer, log-in sessions,
     how long each device was online (sorted longest first), location, fast
     log-in/out, and writes the feature table;
  2. runs Eagle-Eye (EE1), the anomaly model (eagle_eye.py) over that table;
  3. emails both, as one message, to the admin.

It is OFFLINE except for the one outbound email (SMTP to your mail server),
and it only reads data already on the server (PRV).

CREDENTIALS come from an env file (default ~/.streamwatch_env), KEY=VALUE:
    EMAIL_USER=you@gmail.com
    EMAIL_PASS=app-password-here
    EMAIL_TO=you@gmail.com
    SMTP_SERVER=smtp.gmail.com        # optional (this is the default)
    SMTP_PORT=587                     # optional

    python3 report_mailer.py --dry-run           # build + print, do NOT send
    python3 report_mailer.py                      # build + send once
    python3 report_mailer.py --only-flagged       # send ONLY if a device is flagged
    python3 report_mailer.py --to someone@x --threshold 4
    python3 report_mailer.py --hours 6            # judge the last 6 h (default 24; 0 = all time)

CADENCE: a timer calls this; see systemd/report-mailer.timer. ONE EMAIL A
MINUTE IS ~1440/DAY and most mail providers suspend a free account for that.
Prefer a longer interval, or --only-flagged so mail is sent only when there is
something to see.
"""
import contextlib
import io
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import device_report          # noqa: E402
import eagle_eye          # noqa: E402

DEFAULT_DIR = os.path.expanduser("~/mesh_records")
DEFAULT_ENV = os.path.expanduser("~/.streamwatch_env")

HOURS = 24                 # judge recent behaviour, not all-time totals

def load_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


def recorder_active():
    try:
        out = subprocess.run(["systemctl", "is-active", "mesh-recorder"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5).stdout.decode().strip()
        return out == "active"
    except (OSError, subprocess.SubprocessError):
        return None          # unknown (not systemd / not permitted)


def build_report(folder=DEFAULT_DIR, threshold=eagle_eye.THRESHOLD,
                 features_path=None, hours=HOURS):
    """(full text, number of devices flagged). Pure: builds the feature table
    and captures the two tools' output -- no email, no network."""
    features_path = features_path or os.path.join(folder, ".report_features.csv")
    dev_buf = io.StringIO()
    with contextlib.redirect_stdout(dev_buf):
        device_report.main(["--dir", folder, "--csv", features_path, "--hours", str(hours)])
    an_buf = io.StringIO()
    with contextlib.redirect_stdout(an_buf):
        eagle_eye.main([features_path, "--threshold", str(threshold)])
    anomaly_txt = an_buf.getvalue()

    flagged = 0
    for line in anomaly_txt.splitlines():
        if "flagged of" in line:          # "N flagged of M device(s)."
            try:
                flagged = int(line.split("flagged of")[0].split()[-1])
            except (ValueError, IndexError):
                pass

    rec = recorder_active()
    header = [
        "StreamWatch device report",
        "Built: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "Recorder: %s" % ({True: "active", False: "NOT ACTIVE", None: "unknown"}[rec]),
        "=" * 72, "",
    ]
    body = "\n".join(header) + dev_buf.getvalue() + "\n\n" + anomaly_txt
    return body, flagged


def send_email(subject, body, env, retries=(10, 30)):
    import smtplib
    from email.message import EmailMessage
    user, pw = env.get("EMAIL_USER"), env.get("EMAIL_PASS")
    to = env.get("EMAIL_TO") or user
    server = env.get("SMTP_SERVER", "smtp.gmail.com")
    port = int(env.get("SMTP_PORT", "587"))
    if not (user and pw and to):
        raise RuntimeError("missing EMAIL_USER / EMAIL_PASS / EMAIL_TO in the env file")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, user, to
    msg.set_content(body)
    waits = list(retries)
    while True:
        try:
            with smtplib.SMTP(server, port, timeout=15) as s:
                s.starttls()
                s.login(user, pw)
                s.send_message(msg)
            return to
        except Exception:
            if not waits:
                raise
            time.sleep(waits.pop(0))


def main(argv):
    folder, env_path, threshold = DEFAULT_DIR, DEFAULT_ENV, eagle_eye.THRESHOLD
    to_override, only_flagged, dry, hours = None, False, False, HOURS
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.strip()); return 0
        elif a == "--dir":
            i += 1; folder = argv[i] if i < len(argv) else folder
        elif a == "--env":
            i += 1; env_path = argv[i] if i < len(argv) else env_path
        elif a == "--to":
            i += 1; to_override = argv[i] if i < len(argv) else None
        elif a == "--threshold":
            i += 1; threshold = float(argv[i]) if i < len(argv) else threshold
        elif a == "--hours":
            i += 1; hours = float(argv[i]) if i < len(argv) else hours
        elif a == "--only-flagged":
            only_flagged = True
        elif a == "--dry-run":
            dry = True
        i += 1

    if not os.path.isdir(folder):
        print("no records folder: %s" % folder); return 1
    body, flagged = build_report(folder, threshold, hours=hours)

    if only_flagged and flagged == 0:
        print("no device flagged; nothing sent (--only-flagged)")
        return 0

    subject = "[streamwatch] device report%s - %s" % (
        " - %d FLAGGED" % flagged if flagged else "",
        time.strftime("%Y-%m-%d %H:%M"))

    if dry:
        print("SUBJECT: %s\n" % subject)
        print(body)
        return 0

    env = load_env(env_path)
    if to_override:
        env["EMAIL_TO"] = to_override
    try:
        to = send_email(subject, body, env)
        print("report emailed to %s (%d flagged)" % (to, flagged))
        return 0
    except Exception as e:
        print("email FAILED: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
