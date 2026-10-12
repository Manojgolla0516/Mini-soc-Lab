# Local Windows alert watcher

The watcher reads Windows Security and Defender event logs directly and checks the configurable rules in the repository. It polls every five seconds by default and can send concise email and Twilio SMS notifications. It does not rely on Splunk scheduled alerts, so it can be used when Splunk Free is used for searching.

## Requirements

- Windows 11.
- Python 3.8 or newer.
- Permission to read the Windows Security event log. For a single-machine lab, run it from an elevated account; use an appropriately restricted service account for a longer-running deployment.
- SMTP settings for email and a Twilio account/number for SMS. Notifications are disabled by default.

## Configure

1. From the repository root, copy `windows_alert_config.example.json` to `windows_alert_config.local.json` inside `collector/`.
2. Review the values:
   - `poll_seconds`: event polling interval; minimum is two seconds.
   - `failed_logon_threshold` and `failed_logon_window_seconds`: failed logon burst rule.
   - `cooldown_seconds`: suppresses repeat notifications for the same rule and host.
   - `browser_rules_csv`: uses the same browser rule lookup as the Splunk app.
   - `notifications.email_enabled` and `notifications.sms_enabled`: both default to `false`.
3. Configure notification credentials in the environment of the account that runs the watcher. Do not place secrets in the JSON file or commit them to Git.

Email variables:

- `SOC_SMTP_HOST`
- `SOC_SMTP_PORT` (defaults to `587`; STARTTLS is used)
- `SOC_SMTP_USERNAME` (optional when the SMTP relay does not require authentication)
- `SOC_SMTP_PASSWORD` (required when a username is set)
- `SOC_EMAIL_FROM`
- `SOC_EMAIL_TO` (one or more comma-separated addresses)

Twilio variables:

- `TWILIO_ACCOUNT_SID`
- `TWILIO_API_KEY_SID`
- `TWILIO_API_KEY_SECRET`
- `TWILIO_FROM_NUMBER` (E.164 format)
- `SOC_ALERT_TO_NUMBER` (E.164 format)

Twilio SMS delivery can incur provider charges. A real message is sent only when SMS is enabled, the watcher matches a new detection, and the Twilio environment variables are valid.

## Windows event collection

The watcher checks these events:

- Security 4688: browser process creation with a matching configured command-line switch.
- Security 4625: five or more failed logons for the same account and source inside the configured time window.
- Security 1102, 4719, 4720, 4728, and 4732: audit log cleared, audit policy changed, user created, or group membership changed.
- Defender Operational 1116: malware or potentially unwanted software detection.

Event 4688 is generated when process creation auditing is enabled. To inspect browser command-line switches, also enable **Include command line in process creation events** in Windows policy. Microsoft explains this event in [Event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688). Command lines can contain private data in plain text; restrict access to the Security log and avoid enabling command-line capture unless needed for this lab.

The watcher starts at the current end of each event channel and only processes events created after it starts. Its local record-ID, suppression, and failed-logon state is stored in `.windows_alert_state.json`, which is ignored by Git.

## Run safely

From the repository root, first run in dry-run mode:

```powershell
python collector\windows_alert_watcher.py --config collector\windows_alert_config.local.json --dry-run
```

Dry-run mode prints matching summaries but never sends email or SMS. It still monitors only new events after startup. Review the summaries and tune the browser rules and thresholds before enabling a provider.

To enable notifications, set the desired provider flag to `true` in `windows_alert_config.local.json`, then start the watcher without `--dry-run`:

```powershell
python collector\windows_alert_watcher.py --config collector\windows_alert_config.local.json
```

Keep this process running for near-real-time monitoring. Stop it with `Ctrl+C`. The watcher does not retry failed notification requests; check its log output if a configured provider reports an error. Email and SMS notifications intentionally omit raw events and complete process command lines.

## Splunk license note

Splunk Free can still be used for data ingestion and manual searches, but Splunk's built-in alerting is disabled. Use this watcher for local Windows email/SMS notifications, or use the saved-search alert app only on a Splunk installation with an active eligible license.
