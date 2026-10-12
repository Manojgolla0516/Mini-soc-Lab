#!/usr/bin/env python3
"""Near-real-time Windows event watcher for the Mini SOC lab.

This independent watcher reads Windows event channels directly, so its
notifications do not depend on Splunk's scheduled-alert entitlement.
It polls every few seconds and uses only the Python standard library.

Run from Windows with permission to read the Security event log.
"""
import argparse
import base64
import csv
import datetime as dt
import fnmatch
import json
import logging
import os
import re
import smtplib
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

SECURITY_EVENTS = (4625, 4688, 1102, 4719, 4720, 4728, 4732)
DEFENDER_EVENTS = (1116,)
SECURITY_DESCRIPTIONS = {
    1102: "Windows Security audit log was cleared",
    4719: "Windows audit policy changed",
    4720: "Windows user account was created",
    4728: "Member added to a global security group",
    4732: "Member added to a local security group",
}
DEFAULT_BATCH_SIZE = 500
REQUEST_TIMEOUT_SECONDS = 12
MAX_SMS_CHARACTERS = 480
LOG = logging.getLogger("mini_soc_alert_watcher")


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def normalize_key(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def parse_wevtutil_xml(output):
    """Parse the XML fragments returned by wevtutil qe."""
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", output, flags=re.IGNORECASE).strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring("<Events>" + cleaned + "</Events>")
    except ET.ParseError as exc:
        raise RuntimeError("Could not parse Windows event XML") from exc

    parsed = []
    for event in root.iter():
        if local_name(event.tag) != "Event":
            continue
        system = next(
            (child for child in event if local_name(child.tag) == "System"),
            None,
        )
        if system is None:
            continue

        event_id = None
        record_id = None
        computer = ""
        timestamp = ""
        for child in system:
            name = local_name(child.tag)
            if name == "EventID":
                try:
                    event_id = int((child.text or "").strip())
                except ValueError:
                    pass
            elif name == "EventRecordID":
                try:
                    record_id = int((child.text or "").strip())
                except ValueError:
                    pass
            elif name == "Computer":
                computer = (child.text or "").strip()
            elif name == "TimeCreated":
                timestamp = child.attrib.get("SystemTime", "")

        fields = {}
        for node in event.iter():
            if local_name(node.tag) == "Data":
                name = node.attrib.get("Name", "").strip()
                value = "".join(node.itertext()).strip()
                if name and value:
                    fields[normalize_key(name)] = value

        if event_id is not None and record_id is not None:
            parsed.append({
                "event_id": event_id,
                "record_id": record_id,
                "computer": computer,
                "timestamp": timestamp,
                "fields": fields,
            })

    return sorted(parsed, key=lambda item: item["record_id"])


def run_wevtutil(arguments):
    try:
        completed = subprocess.run(
            ["wevtutil.exe"] + arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("wevtutil.exe was not found; this watcher requires Windows") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Timed out reading the Windows event log") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        if "access is denied" in detail.lower() or "access denied" in detail.lower():
            raise RuntimeError("Access denied reading a Windows event channel; run with Security log read permission")
        raise RuntimeError("Windows event-log query failed: " + detail[:300])
    return completed.stdout


def latest_record_id(channel):
    output = run_wevtutil([
        "qe", channel, "/q:*", "/f:xml", "/rd:true", "/c:1",
    ])
    events = parse_wevtutil_xml(output)
    return max((event["record_id"] for event in events), default=0)


def query_new_events(channel, event_ids, after_record_id, batch_size):
    ids_expression = " or ".join("EventID=" + str(value) for value in event_ids)
    query = "*[System[(" + ids_expression + ") and (EventRecordID > " + str(after_record_id) + ")]]"
    output = run_wevtutil([
        "qe", channel, "/q:" + query, "/f:xml", "/rd:false", "/c:" + str(batch_size),
    ])
    return parse_wevtutil_xml(output)


def load_json(path, default):
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else default
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError):
        LOG.warning("State/config file could not be read; using an empty state")
        return default


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def read_browser_rules(path):
    rules = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"process_path", "browser_name", "suspicious_switches", "rule_description", "enabled"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("Browser rules CSV is missing required columns")
        for row in reader:
            if str(row.get("enabled", "")).strip().lower() not in ("1", "true", "yes", "on"):
                continue
            expression = str(row.get("suspicious_switches", "")).strip()
            if not expression:
                continue
            try:
                re.compile(expression, re.IGNORECASE)
            except re.error as exc:
                raise ValueError("Invalid browser rule regular expression for " + str(row.get("browser_name", "browser"))) from exc
            rules.append({
                "process_path": str(row.get("process_path", "")).strip().lower(),
                "browser_name": str(row.get("browser_name", "Browser")).strip(),
                "suspicious_switches": expression,
                "rule_description": str(row.get("rule_description", "Configured browser option")).strip(),
            })
    return rules


def event_timestamp_epoch(value):
    if not value:
        return time.time()
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def display_timestamp(value):
    if not value:
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return value


def event_host(event):
    return event.get("computer") or os.environ.get("COMPUTERNAME", "unknown-host")


def first_field(fields, *keys):
    for key in keys:
        value = fields.get(normalize_key(key), "")
        if value:
            return " ".join(value.split())[:120]
    return ""


def make_alert(rule_id, event, summary, **extra):
    alert = {
        "rule_id": rule_id,
        "host": event_host(event),
        "event_id": event.get("event_id", ""),
        "timestamp": display_timestamp(event.get("timestamp", "")),
        "summary": summary[:300],
    }
    alert.update(extra)
    return alert


def analyze_event(event, browser_rules, state, config):
    """Return zero or more concise alert summaries for one event."""
    event_id = event["event_id"]
    fields = event["fields"]
    alerts = []
    host = event_host(event)

    if event_id == 4688:
        process_path = first_field(fields, "NewProcessName", "ProcessName", "Image").lower()
        command_line = first_field(fields, "CommandLine", "ProcessCommandLine")
        if process_path and command_line:
            for rule in browser_rules:
                if fnmatch.fnmatch(process_path, rule["process_path"]):
                    if re.search(rule["suspicious_switches"], command_line, re.IGNORECASE):
                        alerts.append(make_alert(
                            "browser:" + rule["browser_name"].lower().replace(" ", "-"),
                            event,
                            rule["rule_description"] + " (" + rule["browser_name"] + ")",
                            browser=rule["browser_name"],
                        ))

    elif event_id == 4625:
        user = first_field(fields, "TargetUserName", "AccountName", "SubjectUserName") or "unknown"
        source = first_field(fields, "IpAddress", "SourceNetworkAddress", "WorkstationName") or "unknown"
        now = event_timestamp_epoch(event.get("timestamp", ""))
        window = int(config.get("failed_logon_window_seconds", 300))
        attempts = [
            item for item in state.get("failed_logons", [])
            if now - float(item.get("time", 0)) <= window
        ]
        identity = host + "|" + user + "|" + source
        attempts.append({"key": identity, "time": now, "host": host, "user": user, "source": source})
        state["failed_logons"] = attempts
        matching = [item for item in attempts if item.get("key") == identity]
        threshold = max(2, int(config.get("failed_logon_threshold", 5)))
        if len(matching) >= threshold:
            alerts.append(make_alert(
                "failed-logon:" + identity,
                event,
                str(len(matching)) + " failed Windows logons for " + user + " from " + source +
                " within " + str(window) + " seconds",
                user=user,
                source=source,
                count=len(matching),
            ))

    elif event_id in SECURITY_DESCRIPTIONS:
        actor = first_field(fields, "SubjectUserName", "SubjectUsername", "AccountName") or "unknown"
        target = first_field(fields, "TargetUserName", "MemberName", "GroupName") or "unknown"
        detail = SECURITY_DESCRIPTIONS[event_id] + "; actor " + actor + "; target " + target
        alerts.append(make_alert("windows-security:" + str(event_id), event, detail, user=actor))

    elif event_id == 1116:
        threat = first_field(fields, "ThreatName", "Name") or "unknown threat"
        severity = first_field(fields, "ThreatSeverity", "SeverityName", "Severity") or "unknown"
        alerts.append(make_alert(
            "defender:1116:" + threat,
            event,
            "Microsoft Defender detected " + threat + " (severity " + severity + ")",
            threat=threat,
            severity=severity,
        ))

    return alerts


def required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("Missing required environment variable: " + name)
    return value


def send_sms(alert):
    account_sid = required_env("TWILIO_ACCOUNT_SID")
    api_key_sid = required_env("TWILIO_API_KEY_SID")
    api_key_secret = required_env("TWILIO_API_KEY_SECRET")
    from_number = required_env("TWILIO_FROM_NUMBER")
    to_number = required_env("SOC_ALERT_TO_NUMBER")
    if not re.fullmatch(r"AC[0-9a-fA-F]{32}", account_sid):
        raise ValueError("TWILIO_ACCOUNT_SID must be a Twilio Account SID")
    if not re.fullmatch(r"SK[0-9a-fA-F]{32}", api_key_sid):
        raise ValueError("TWILIO_API_KEY_SID must be a Twilio API Key SID")
    for name, number in (("TWILIO_FROM_NUMBER", from_number), ("SOC_ALERT_TO_NUMBER", to_number)):
        if not re.fullmatch(r"\+[1-9][0-9]{7,14}", number):
            raise ValueError(name + " must use E.164 format")

    message = (
        "Mini SOC: " + alert["rule_id"] + "\n" +
        "Host: " + alert["host"] + "\n" +
        "Event " + str(alert["event_id"]) + ": " + alert["summary"]
    )[:MAX_SMS_CHARACTERS]
    endpoint = "https://api.twilio.com/2010-04-01/Accounts/" + quote(account_sid, safe="") + "/Messages.json"
    body = urlencode({"From": from_number, "To": to_number, "Body": message}).encode("utf-8")
    credentials = base64.b64encode((api_key_sid + ":" + api_key_secret).encode("utf-8")).decode("ascii")
    request = Request(
        endpoint,
        data=body,
        headers={
            "Authorization": "Basic " + credentials,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError("Twilio returned HTTP " + str(response.status))
    except HTTPError as exc:
        raise RuntimeError("Twilio returned HTTP " + str(exc.code)) from None
    except URLError:
        raise RuntimeError("Could not reach the Twilio API") from None


def send_email(alert):
    host = required_env("SOC_SMTP_HOST")
    port = int(os.environ.get("SOC_SMTP_PORT", "587"))
    sender = required_env("SOC_EMAIL_FROM")
    recipients = [item.strip() for item in required_env("SOC_EMAIL_TO").split(",") if item.strip()]
    if not recipients:
        raise ValueError("SOC_EMAIL_TO must contain at least one recipient")

    message = EmailMessage()
    message["Subject"] = "Mini SOC alert: " + alert["rule_id"]
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(
        "A Mini SOC detection was triggered.\n\n"
        "Host: " + alert["host"] + "\n"
        "Event ID: " + str(alert["event_id"]) + "\n"
        "Time (UTC): " + alert["timestamp"] + "\n"
        "Rule: " + alert["rule_id"] + "\n"
        "Summary: " + alert["summary"] + "\n\n"
        "The notification intentionally excludes the full process command line and raw event."
    )

    with smtplib.SMTP(host, port, timeout=REQUEST_TIMEOUT_SECONDS) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        username = os.environ.get("SOC_SMTP_USERNAME", "").strip()
        password = os.environ.get("SOC_SMTP_PASSWORD", "")
        if username:
            if not password:
                raise ValueError("SOC_SMTP_PASSWORD is required when SOC_SMTP_USERNAME is set")
            server.login(username, password)
        server.send_message(message)


def deliver_alert(alert, state, config, dry_run):
    key = alert["rule_id"] + "|" + alert["host"]
    now = time.time()
    cooldown = int(config.get("cooldown_seconds", 900))
    last_alerts = state.setdefault("last_alerts", {})
    previous = float(last_alerts.get(key, 0))
    if now - previous < cooldown:
        return

    LOG.warning(
        "ALERT rule=%s host=%s event_id=%s summary=%s",
        alert["rule_id"], alert["host"], alert["event_id"], alert["summary"],
    )
    if not dry_run:
        notifications = config.get("notifications", {})
        if notifications.get("email_enabled", False):
            try:
                send_email(alert)
                LOG.info("Email notification sent for %s", alert["rule_id"])
            except Exception as exc:
                LOG.error("Email notification failed for %s: %s", alert["rule_id"], exc)
        if notifications.get("sms_enabled", False):
            try:
                send_sms(alert)
                LOG.info("SMS notification sent for %s", alert["rule_id"])
            except Exception as exc:
                LOG.error("SMS notification failed for %s: %s", alert["rule_id"], exc)
    last_alerts[key] = now


def resolve_path(config_path, configured):
    path = Path(configured)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def poll_once(config_path, config, state, browser_rules, dry_run):
    channels = (
        ("Security", SECURITY_EVENTS),
        ("Microsoft-Windows-Windows Defender/Operational", DEFENDER_EVENTS),
    )
    record_ids = state.setdefault("record_ids", {})
    batch_size = max(1, int(config.get("batch_size", DEFAULT_BATCH_SIZE)))

    for channel, event_ids in channels:
        try:
            latest = latest_record_id(channel)
        except RuntimeError as exc:
            LOG.error("%s", exc)
            continue

        if channel not in record_ids:
            record_ids[channel] = latest
            LOG.info("Starting at the current end of %s (record %s)", channel, latest)
            continue
        if latest < int(record_ids[channel]):
            LOG.warning("Record IDs reset in %s; resuming from its earliest available event", channel)
            record_ids[channel] = 0

        try:
            events = query_new_events(channel, event_ids, int(record_ids[channel]), batch_size)
        except RuntimeError as exc:
            LOG.error("%s", exc)
            continue

        for event in events:
            for alert in analyze_event(event, browser_rules, state, config):
                deliver_alert(alert, state, config, dry_run)

        if len(events) >= batch_size:
            record_ids[channel] = max(event["record_id"] for event in events)
        else:
            record_ids[channel] = latest


def main():
    parser = argparse.ArgumentParser(description="Near-real-time Windows event alerts for the Mini SOC lab")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).with_name("windows_alert_config.example.json")),
        help="Path to the JSON configuration file",
    )
    parser.add_argument("--dry-run", action="store_true", help="Log matches without sending notifications")
    parser.add_argument("--once", action="store_true", help="Poll each event channel once and exit")
    args = parser.parse_args()

    if os.name != "nt":
        LOG.error("This watcher must run on Windows")
        return 2

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config_path = Path(args.config).resolve()
    config = load_json(config_path, {})
    if not config:
        LOG.error("Could not load a non-empty JSON configuration from %s", config_path)
        return 2

    browser_rules_path = resolve_path(config_path, config.get(
        "browser_rules_csv",
        "../splunk/mini_soc_alerts/lookups/browser_alert_rules.csv",
    ))
    state_path = resolve_path(config_path, config.get("state_file", ".windows_alert_state.json"))
    try:
        browser_rules = read_browser_rules(browser_rules_path)
    except (OSError, ValueError) as exc:
        LOG.error("Could not load browser rules: %s", exc)
        return 2

    default_state = {"record_ids": {}, "last_alerts": {}, "failed_logons": []}
    state = load_json(state_path, default_state)
    poll_seconds = max(2, int(config.get("poll_seconds", 5)))
    LOG.info(
        "Watcher started: poll=%ss browser_rules=%s dry_run=%s",
        poll_seconds, len(browser_rules), args.dry_run,
    )

    while True:
        poll_once(config_path, config, state, browser_rules, args.dry_run)
        try:
            save_state(state_path, state)
        except OSError as exc:
            LOG.error("Could not save watcher state: %s", exc)
        if args.once:
            break
        time.sleep(poll_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
