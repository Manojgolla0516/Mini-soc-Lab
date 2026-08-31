import imaplib
import email
import json
from email.header import decode_header
from datetime import datetime
import getpass

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
OUTPUT_FILE = r"C:\GmailSplunkLab\gmail_events.json"

gmail_address = input("Enter your Gmail address: ")
app_password = getpass.getpass("Enter your Gmail App Password: ")

print("\nConnecting to Gmail...")

mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
mail.login(gmail_address, app_password)

mail.select("INBOX")

status, messages = mail.search(None, "ALL")

if status != "OK":
    print("Unable to search mailbox.")
    mail.logout()
    raise SystemExit

message_ids = messages[0].split()

# Only process the latest 20 messages for our lab
message_ids = message_ids[-20:]

events = []


def decode_text(value):
    if not value:
        return ""

    parts = decode_header(value)
    result = ""

    for part, encoding in parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="replace")
        else:
            result += part

    return result


for message_id in message_ids:

    status, data = mail.fetch(
        message_id,
        "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])"
    )

    if status != "OK":
        continue

    raw_headers = data[0][1]
    msg = email.message_from_bytes(raw_headers)

    event = {
        "timestamp": datetime.now().isoformat(),
        "from": decode_text(msg.get("From")),
        "to": decode_text(msg.get("To")),
        "subject": decode_text(msg.get("Subject")),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", "")
    }

    events.append(event)


mail.logout()

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"\nSUCCESS: Collected {len(events)} emails.")
print(f"Output: {OUTPUT_FILE}")