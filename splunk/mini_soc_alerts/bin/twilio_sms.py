#!/usr/bin/env python3
"""Splunk custom alert action that sends a concise SMS through Twilio.

Configure credentials and numbers in the Splunk service environment:
TWILIO_ACCOUNT_SID, TWILIO_API_KEY_SID, TWILIO_API_KEY_SECRET,
TWILIO_FROM_NUMBER, and SOC_ALERT_TO_NUMBER.
"""

import base64
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

TIMEOUT_SECONDS = 12
MAX_SMS_CHARACTERS = 480


def log(message):
    sys.stderr.write("mini_soc_twilio_sms: " + message + "\n")


def first_value(mapping, *keys):
    if not isinstance(mapping, dict):
        return ""
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        if value is not None and str(value).strip():
            return " ".join(str(value).split())[:120]
    return ""


def build_message(payload):
    result = payload.get("result") or {}
    if not isinstance(result, dict):
        result = {}

    search_name = first_value(payload, "search_name", "alert_name") or "Security rule triggered"
    detection = first_value(result, "detection", "rule_description")
    lines = ["Mini SOC: " + search_name[:100]]

    if detection:
        lines.append("Detection: " + detection)

    for label, keys in (
        ("Host", ("host",)),
        ("Browser", ("browser_name",)),
        ("Event", ("EventCode", "event_code")),
        ("User", ("target_user", "TargetUserName", "Account_Name", "actor")),
        ("Source", ("source", "Source_Network_Address", "source_ip")),
        ("Count", ("count",)),
        ("Threat", ("threat_name",)),
        ("Severity", ("severity",)),
    ):
        value = first_value(result, *keys)
        if value:
            lines.append(label + ": " + value)

    # Do not include process command lines, paths, message subjects, or raw events in SMS.
    return "\n".join(lines)[:MAX_SMS_CHARACTERS]


def required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("Missing required environment variable: " + name)
    return value


def send_sms(message):
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
            raise ValueError(name + " must use E.164 format, for example +15551234567")

    endpoint = (
        "https://api.twilio.com/2010-04-01/Accounts/"
        + quote(account_sid, safe="")
        + "/Messages.json"
    )
    form_data = urlencode({
        "From": from_number,
        "To": to_number,
        "Body": message,
    }).encode("utf-8")
    credentials = (api_key_sid + ":" + api_key_secret).encode("utf-8")
    authorization = base64.b64encode(credentials).decode("ascii")
    request = Request(
        endpoint,
        data=form_data,
        headers={
            "Authorization": "Basic " + authorization,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError("Twilio returned HTTP " + str(response.status))
    except HTTPError as error:
        raise RuntimeError("Twilio returned HTTP " + str(error.code)) from None
    except URLError:
        raise RuntimeError("Could not reach the Twilio API") from None


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("Expected the Splunk --execute argument")
        return 2

    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Splunk alert payload must be a JSON object")
        message = build_message(payload)
        send_sms(message)
    except (ValueError, RuntimeError, json.JSONDecodeError) as error:
        log(str(error))
        return 2

    log("SMS notification sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())