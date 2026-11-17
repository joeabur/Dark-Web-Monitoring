# Dark Web Exposure Monitor

This repository contains a Python 3 monitor that runs an authorized SpiderFoot
scan against a configured domain, compares findings with a local JSON state
file, and emails an HTML alert when it finds items not reported before. The
email includes severity counts, findings grouped by source, the top 25
findings, recommended response steps, and the complete SpiderFoot CSV report.
The script uses only the Python standard library.

## Requirements

- Linux monitoring host with Python 3 and a SpiderFoot installation.
- SpiderFoot virtual environment and any configured modules/API keys.
- Tor installed and running if the selected SpiderFoot modules need Tor.
- Gmail SMTP access with an app password (use a dedicated monitoring account).
- Authorization to scan the target and use the selected data sources.

Module availability depends on your SpiderFoot version and configuration. Check
the installed names with `python3 sf.py -M` and adjust `MODULES` in
[`darkweb_monitor.py`](./darkweb_monitor.py) if needed. API-key-backed sources
require valid keys in SpiderFoot settings; configuring them here does not
provide API access automatically.

## Configure and run

1. Install and configure SpiderFoot, its modules, and Tor separately.
2. Copy [`.env.example`](./.env.example) to a private file, such as
   `/etc/darkweb-monitor.env`. Fill in the target domain, sender, Gmail app
   password, comma-separated `RECEIVERS`, optional `CC_EMAILS`, and absolute
   SpiderFoot paths. Keep this file readable only by the monitoring account
   (for example, `chmod 600 /etc/darkweb-monitor.env`). Do not commit credentials.
3. Test interactively as the monitoring account:

   ```sh
   set -a
   . /etc/darkweb-monitor.env
   set +a
   /path/to/python3 /path/to/repository/darkweb_monitor.py
   ```

   `SPIDERFOOT_PYTHON` should be the Python executable in SpiderFoot's
   virtualenv, and `SPIDERFOOT_DIR` should be the directory containing `sf.py`.
   For production, set `STATE_FILE` to a persistent writable location such as
   `/var/lib/darkweb-monitor/darkweb_seen.json` and grant the monitoring account
   access to that directory.
4. Add a cron entry to run daily at 2:00 AM in the server's local time. Replace
   the paths and select a log path writable by the monitoring account:

   ```cron
   0 2 * * * set -a; . /etc/darkweb-monitor.env; set +a; /path/to/python3 /path/to/repository/darkweb_monitor.py >> /path/to/darkweb-monitor.log 2>&1
   ```

The script defaults to a one-hour scan timeout; set `SCAN_TIMEOUT_SECONDS` to
change it. A failed/timed-out scan exits with an error and does not send an
alert. Empty or unexpected CSV output is treated as an error rather than as
"no findings." Concurrent runs sharing a state file are prevented by a
non-blocking file lock. No email is sent when there are no new findings.
Findings are saved in the state file only after the alert is sent, so a failed
email attempt is retried on the next run. Back up this state file if the
monitor is moved to another host.

The attached report may contain sensitive exposure details. Restrict recipients
to the response team, use an appropriately protected mailbox, and follow your
organization's retention and incident-handling policies.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `TARGET_DOMAIN` | Yes | Domain SpiderFoot is authorized to scan |
| `SENDER_EMAIL` | Yes | Gmail account used to send alerts |
| `SMTP_APP_PASSWORD` | Yes | Gmail app password; never use or commit your account password |
| `RECEIVERS` | Yes | Comma-separated security team email addresses |
| `CC_EMAILS` | No | Optional comma-separated CC addresses |
| `SPIDERFOOT_PYTHON` | Yes | Python executable in the SpiderFoot virtualenv |
| `SPIDERFOOT_DIR` | Yes | SpiderFoot installation directory containing `sf.py` |
| `STATE_FILE` | No | Persistent JSON state path; defaults beside the script |
| `SCAN_TIMEOUT_SECONDS` | No | Scan timeout; defaults to `3600` |

Finding de-duplication uses a SHA-256 hash of each row, excluding timestamp-like
columns. The local state file stores hashes, not the finding details.