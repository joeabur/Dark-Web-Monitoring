#!/usr/bin/env python3
"""Scan an authorized domain with SpiderFoot and email alerts for new findings."""

import csv
import fcntl
import hashlib
import html
import io
import json
import os
import re
import smtplib
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

MODULES = [
    "sfp_darkweb",
    "sfp_ahmia",
    "sfp_torch",
    "sfp_onioncity",
    "sfp_psbdmp",
    "sfp_pastebin",
    "sfp_leakix",
    "sfp_github",
    "sfp_grayhatwarfare",
    "sfp_phishtank",
    "sfp_openphish",
    "sfp_haveibeenpwned",
    "sfp_intelx",
    "sfp_dehashed",
]
SEVERITY_HINTS = {
    "LEAKSITE": "High",
    "DARKNET": "High",
    "BREACH": "High",
    "PASSWORD": "High",
    "CREDENTIAL": "High",
    "CLOUD_STORAGE": "High",
    "PHISHING": "Medium",
    "MALICIOUS": "Medium",
    "PASTE": "Medium",
}
STATE_FILE = Path(__file__).with_name("darkweb_seen.json")
MAX_ROWS_IN_EMAIL = 25


def required_setting(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


def normalize_domain(value):
    if "://" in value or "/" in value or any(char.isspace() for char in value):
        raise ValueError("TARGET_DOMAIN must be a hostname, not a URL or path")
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("TARGET_DOMAIN is not a valid hostname") from exc
    labels = domain.split(".")
    if (not domain or len(domain) > 253
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in labels)):
        raise ValueError("TARGET_DOMAIN is not a valid hostname")
    return domain


def settings():
    receivers = [item.strip() for item in required_setting("RECEIVERS").split(",")
                 if item.strip()]
    if not receivers:
        raise ValueError("RECEIVERS must contain at least one email address")

    try:
        timeout = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "3600"))
    except ValueError as exc:
        raise ValueError("SCAN_TIMEOUT_SECONDS must be an integer") from exc
    if timeout <= 0:
        raise ValueError("SCAN_TIMEOUT_SECONDS must be greater than zero")

    target = normalize_domain(required_setting("TARGET_DOMAIN"))
    python_executable = Path(required_setting("SPIDERFOOT_PYTHON")).expanduser()
    spiderfoot_dir = Path(required_setting("SPIDERFOOT_DIR")).expanduser()
    state_file = Path(os.environ.get("STATE_FILE") or STATE_FILE).expanduser()
    for name, path in (
        ("SPIDERFOOT_PYTHON", python_executable),
        ("SPIDERFOOT_DIR", spiderfoot_dir),
        ("STATE_FILE", state_file),
    ):
        if not path.is_absolute():
            raise ValueError(f"{name} must be an absolute path")

    return {
        "target": target,
        "sender": required_setting("SENDER_EMAIL"),
        "password": required_setting("SMTP_APP_PASSWORD"),
        "receivers": receivers,
        "cc_emails": [item.strip() for item in os.environ.get("CC_EMAILS", "").split(",")
                      if item.strip()],
        "python": python_executable,
        "spiderfoot_dir": spiderfoot_dir,
        "scan_timeout": timeout,
        "state_file": state_file,
    }


def run_scan(config):
    command = [
        str(config["python"]), "sf.py", "-q", "-s", config["target"],
        "-m", ",".join(MODULES), "-o", "csv",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=config["scan_timeout"], cwd=config["spiderfoot_dir"],
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SpiderFoot scan timed out after {config['scan_timeout']} seconds"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Could not launch SpiderFoot: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip()[:500]
        raise RuntimeError(
            f"SpiderFoot failed (exit code {result.returncode})"
            f"{': ' + detail if detail else ''}"
        )
    return result.stdout


def parse_findings(raw_csv):
    if not raw_csv.strip():
        raise RuntimeError("SpiderFoot returned empty output instead of a CSV report")
    try:
        reader = csv.DictReader(io.StringIO(raw_csv))
        fieldnames = reader.fieldnames or []
        normalized_names = {name.strip().lower() for name in fieldnames if name}
        if not {"type", "module"}.issubset(normalized_names):
            raise RuntimeError(
                "SpiderFoot output is not the expected CSV format "
                "(required columns: Type and Module)"
            )
        rows = [
            row for row in reader
            if any((value or "").strip() for value in row.values())
        ]
    except csv.Error as exc:
        raise RuntimeError(f"Could not parse SpiderFoot CSV output: {exc}") from exc
    return rows, fieldnames


def fingerprint(row):
    stable = {
        key: value for key, value in row.items()
        if key and key.lower() not in ("updated", "time", "timestamp")
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True).encode("utf-8")
    ).hexdigest()


def find_new_findings(rows, seen):
    new_rows = []
    new_fingerprints = set()
    for row in rows:
        row_fingerprint = fingerprint(row)
        if row_fingerprint not in seen and row_fingerprint not in new_fingerprints:
            new_rows.append(row)
            new_fingerprints.add(row_fingerprint)
    return new_rows, new_fingerprints


def load_seen(state_file):
    try:
        contents = state_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()
    try:
        entries = json.loads(contents)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"State file is not valid JSON: {state_file}") from exc
    if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
        raise RuntimeError(f"State file must contain a JSON list of hashes: {state_file}")
    return set(entries)


def save_seen(seen, state_file):
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=state_file.parent,
            delete=False, prefix=f".{state_file.name}.",
        ) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(sorted(seen), temp_file)
            temp_file.write("\n")
        os.replace(temp_path, state_file)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


@contextmanager
def process_lock(state_file):
    state_file.parent.mkdir(parents=True, exist_ok=True)
    lock_file = state_file.with_name(f".{state_file.name}.lock")
    with lock_file.open("a", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another monitor run is already in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def column(row, *names):
    for name in names:
        for key in row:
            if key and key.lower() == name.lower():
                return row[key] or ""
    return ""


def severity(row):
    event_type = column(row, "Type").upper()
    for keyword, level in SEVERITY_HINTS.items():
        if keyword in event_type:
            return level
    return "Low"


def build_email(new_rows, report_csv, config):
    target = config["target"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_module = Counter(column(row, "Module") or "unknown" for row in new_rows)
    by_severity = Counter(severity(row) for row in new_rows)
    order = {"High": 0, "Medium": 1, "Low": 2}
    ranked = sorted(new_rows, key=lambda row: order[severity(row)])
    shown = ranked[:MAX_ROWS_IN_EMAIL]
    colors = {"High": "#c0392b", "Medium": "#e67e22", "Low": "#7f8c8d"}
    escape = lambda value: html.escape(str(value))[:300]

    text = [
        f"DARK WEB ALERT - {target}",
        f"Generated: {now}",
        f"New findings: {len(new_rows)} "
        f"(High: {by_severity['High']}, Medium: {by_severity['Medium']}, "
        f"Low: {by_severity['Low']})",
        "", "Top findings:",
    ]
    for row in shown:
        text.append(
            f"- [{severity(row)}] {column(row, 'Type')} | "
            f"{column(row, 'Module')} | {column(row, 'Data', 'Event')[:150]}"
        )
    text += [
        "", "The attached CSV contains the full SpiderFoot scan report.",
        "Recommended: triage High items first, validate, and follow the IR playbook.",
    ]

    rows_html = "".join(
        f"<tr><td style='padding:6px 8px;border-bottom:1px solid #eee'>"
        f"<span style='background:{colors[severity(row)]};color:#fff;padding:2px 8px;"
        f"border-radius:10px;font-size:11px'>{severity(row)}</span></td>"
        f"<td style='padding:6px 8px;border-bottom:1px solid #eee'>"
        f"{escape(column(row, 'Type'))}</td>"
        f"<td style='padding:6px 8px;border-bottom:1px solid #eee'>"
        f"{escape(column(row, 'Module'))}</td>"
        f"<td style='padding:6px 8px;border-bottom:1px solid #eee;word-break:break-all'>"
        f"{escape(column(row, 'Data', 'Event'))}</td></tr>"
        for row in shown
    )
    module_html = "".join(
        f"<li>{escape(module)}: <b>{count}</b></li>"
        for module, count in by_module.most_common()
    )
    more = (
        f"<p style='color:#666;font-size:12px'>Showing {len(shown)} of "
        f"{len(new_rows)} findings. See the attached CSV for the full report.</p>"
        if len(new_rows) > len(shown) else ""
    )
    body = f"""\
<html><body style="font-family:Segoe UI,Arial,sans-serif;color:#222;margin:0;background:#f4f5f7">
<div style="max-width:760px;margin:20px auto;background:#fff;border:1px solid #ddd;border-radius:6px">
  <div style="background:#1f2d3d;color:#fff;padding:16px 20px;border-radius:6px 6px 0 0">
    <div style="font-size:12px;letter-spacing:1px;opacity:.8">SECURITY ALERT</div>
    <div style="font-size:20px;font-weight:600">Dark Web Exposure Detected: {escape(target)}</div>
  </div>
  <div style="padding:20px">
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px">
      <tr><td style="padding:4px 0;color:#666;width:140px">Target</td><td>{escape(target)}</td></tr>
      <tr><td style="padding:4px 0;color:#666">Generated</td><td>{now}</td></tr>
      <tr><td style="padding:4px 0;color:#666">New findings</td><td><b>{len(new_rows)}</b></td></tr>
      <tr><td style="padding:4px 0;color:#666">Severity</td>
          <td><span style="color:{colors['High']}"><b>High {by_severity['High']}</b></span> &nbsp;
              <span style="color:{colors['Medium']}"><b>Medium {by_severity['Medium']}</b></span> &nbsp;
              <span style="color:{colors['Low']}"><b>Low {by_severity['Low']}</b></span></td></tr>
    </table>
    <h3 style="margin:16px 0 6px">Findings by source</h3>
    <ul style="margin:0 0 16px 18px;padding:0">{module_html}</ul>
    <h3 style="margin:16px 0 6px">Top findings</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="background:#f0f2f5;text-align:left">
        <th style="padding:6px 8px">Severity</th><th style="padding:6px 8px">Type</th>
        <th style="padding:6px 8px">Source</th><th style="padding:6px 8px">Detail</th></tr>
      {rows_html}
    </table>
    {more}
    <h3 style="margin:20px 0 6px">Recommended actions</h3>
    <ol style="margin:0 0 0 18px;padding:0;line-height:1.6">
      <li>Triage High severity items first and validate they are genuine.</li>
      <li>If credentials are exposed, force resets and revoke active sessions/tokens.</li>
      <li>Open an incident and follow the relevant incident response playbook.</li>
      <li>Record outcomes so recurring false positives can be tuned out.</li>
    </ol>
  </div>
  <div style="padding:12px 20px;background:#f8f8f8;color:#888;font-size:11px;border-radius:0 0 6px 6px">
    Automated alert from SpiderFoot monitoring. Previously reported findings are not re-alerted.
  </div>
</div></body></html>"""

    message = EmailMessage()
    message["Subject"] = (
        f"[Dark Web Alert] {target}: {len(new_rows)} new finding(s) "
        f"({by_severity['High']} high)"
    )
    message["From"] = config["sender"]
    message["To"] = ", ".join(config["receivers"])
    if config["cc_emails"]:
        message["Cc"] = ", ".join(config["cc_emails"])
    message.set_content("\n".join(text))
    message.add_alternative(body, subtype="html")

    filename_target = re.sub(r"[^A-Za-z0-9.-]", "_", target)
    message.add_attachment(
        report_csv.encode("utf-8"), maintype="text", subtype="csv",
        filename=f"{filename_target}_darkweb_report_{datetime.now():%Y%m%d_%H%M}.csv",
    )
    return message


def send_email(message, config):
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(config["sender"], config["password"])
        server.send_message(
            message, to_addrs=config["receivers"] + config["cc_emails"]
        )


def main():
    try:
        config = settings()
        with process_lock(config["state_file"]):
            raw_csv = run_scan(config)
            rows, _ = parse_findings(raw_csv)
            seen = load_seen(config["state_file"])
            new_rows, new_fingerprints = find_new_findings(rows, seen)

            if not new_rows:
                print(
                    f"No new findings for {config['target']} "
                    f"({len(rows)} total, all previously reported). No email sent."
                )
                return

            send_email(build_email(new_rows, raw_csv, config), config)
            seen.update(new_fingerprints)
            save_seen(seen, config["state_file"])
            print(
                f"{len(new_rows)} new finding(s) for {config['target']}. Alert sent to "
                f"{', '.join(config['receivers'])}."
            )
    except (OSError, RuntimeError, ValueError, smtplib.SMTPException) as exc:
        sys.exit(f"[!] {exc}")


if __name__ == "__main__":
    main()
