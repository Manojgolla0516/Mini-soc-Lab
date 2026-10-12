# Mini SOC alerting app

This app adds editable browser launch rules, Windows Security and Microsoft Defender detections, email actions, and a Twilio SMS action to the Mini SOC lab.

The saved searches are installed with scheduling and notification actions disabled. Configure the recipients and Twilio credentials first; then enable the actions and schedules you want in Splunk.

## License requirement

Splunk Free disables built-in alerting. The saved-search actions in this app require an active Splunk license that includes alerting. For local Windows email/SMS notifications without Splunk scheduled alerts, use the separate [Windows alert watcher](../../collector/README.md).

## What it detects

- **Browser launch options:** Windows Security process-creation events (Event ID `4688`) for browsers enabled in `lookups/browser_alert_rules.csv`. The default rules flag remote-debugging, extension-loading, web-security-bypass, proxy-override, and Firefox automation/debug options.
- **Failed logon burst:** Five or more failed Windows logons for the same host, account, and source in a five-minute search window.
- **Windows Security changes:** Security audit log cleared (1102), audit policy changed (4719), user account created (4720), or a member added to a global/local security group (4728/4732).
- **Microsoft Defender detection:** Event ID 1116 in the Defender Operational log.

These are starter detections. Development tools can legitimately use browser debugging or automation options, and administrative changes can be expected. Tune the lookup and thresholds for your own lab before treating a match as malicious.

## Install and configure

1. Copy `splunk/mini_soc_alerts` from this repository into `%SPLUNK_HOME%\etc\apps\mini_soc_alerts` on your standalone Splunk instance.
2. Enable **Audit Process Creation** under Advanced Audit Policy Configuration. To capture browser arguments, also enable **Include command line in process creation events** under Computer Configuration > Administrative Templates > System > Audit Process Creation. Windows logs those command lines as plain text, so limit access to the Security log and Splunk index. See [Microsoft's Event 4688 guidance](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688).
3. Create a Twilio API key and an SMS-enabled Twilio number. Set these Windows **system** environment variables on the Splunk host:
   - `TWILIO_ACCOUNT_SID`
   - `TWILIO_API_KEY_SID`
   - `TWILIO_API_KEY_SECRET`
   - `TWILIO_FROM_NUMBER` (E.164 format)
   - `SOC_ALERT_TO_NUMBER` (E.164 format)
   
   Restart the Splunk service after changing system environment variables. The code uses Twilio's HTTPS [Messages API](https://www.twilio.com/docs/messaging/api/message-resource) with API key authentication; no Twilio secret belongs in Git.
4. Configure Splunk's SMTP settings.
5. Create `%SPLUNK_HOME%\etc\apps\mini_soc_alerts\local\savedsearches.conf` overrides for the rules you want to enable. In each chosen stanza, set `enableSched = 1`, `action.email = 1`, `action.email.to = your-address@example.com`, and `action.twilio_sms = 1`. Leave unselected rules disabled. The repository's `.gitignore` excludes the app's `local/` directory.
6. Restart Splunk after installing the app so it registers the Twilio alert action. Review the searches in `default/savedsearches.conf` and confirm they match your event field extractions before enabling schedules.

## Configure browser rules

Edit `lookups/browser_alert_rules.csv`:

- `process_path` is a wildcard pattern matched against the process path, such as `*brave.exe`.
- `browser_name` is the label shown in results and notifications.
- `suspicious_switches` is a regular expression matched against the process command line.
- Set `enabled` to `0` to disable a browser rule.

Only the rule description, browser, host, and selected alert fields are included in SMS. Full command lines and raw events are not sent.

## Tuning and privacy

- The browser search depends on 4688 events. If the search returns no results, inspect a Security 4688 event and adjust the process or command-line field names in the search for your Splunk extraction.
- The search window, failed-logon threshold, schedule, and 15-minute suppression are set in `default/savedsearches.conf`.
- Command-line auditing can record private arguments in plain text. Do not enable it without restricting log access, and avoid including command lines in notification output.
- The Twilio action uses only Python's standard library. It does not retry failed requests, avoiding duplicate SMS messages.
- SMS delivery requires a configured Twilio account and can incur provider charges. No live test message is sent by this repository change.

## Manual searches

The SPL in `default/savedsearches.conf` can be copied into Search & Reporting for review before enabling a schedule. The action settings are configured independently from the search logic.