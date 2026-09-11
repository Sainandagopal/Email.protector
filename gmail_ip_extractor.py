"""
Gmail Sender IP Extractor
--------------------------
Polls your Gmail inbox for new messages and extracts the originating
IP address from the email's `Received` headers.

Setup: see 1_SETUP_INSTRUCTIONS.md in this same folder.

Requires: credentials.json (downloaded from Google Cloud Console)
placed in the same directory as this script.
"""

import base64
import re
import time
import json
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Read-only scope: this script can only READ mail, never send/delete/modify.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CREDENTIALS_FILE = 'Credentials.json' if os.path.exists('Credentials.json') else 'credentials.json'
TOKEN_FILE = 'token.json'
SEEN_IDS_FILE = 'seen_ids.json'
POLL_INTERVAL_SECONDS = 60

IP_PATTERN = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')

PRIVATE_IP_PREFIXES = ('10.', '192.168.', '127.', '172.16.', '172.17.',
                        '172.18.', '172.19.', '172.2', '172.3')


def get_gmail_service():
    """Authenticate and return a Gmail API service object."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def load_seen_ids():
    if os.path.exists(SEEN_IDS_FILE):
        with open(SEEN_IDS_FILE, 'r') as f:
            return set(json.load(f))
    return set()


def save_seen_ids(seen_ids):
    with open(SEEN_IDS_FILE, 'w') as f:
        json.dump(list(seen_ids), f)


def is_private_ip(ip):
    return ip.startswith(PRIVATE_IP_PREFIXES)


def get_sender_ip(service, msg_id):
    """Fetch a message's raw content and extract the originating IP
    from its Received headers, working from the oldest (bottom) header
    upward, since that is closest to the true origin."""
    msg = service.users().messages().get(
        userId='me', id=msg_id, format='raw'
    ).execute()

    raw = base64.urlsafe_b64decode(msg['raw']).decode('utf-8', errors='ignore')

    # Received headers can be folded across multiple lines; this pattern
    # captures each header block up to the next "Received:" or a blank line.
    received_headers = re.findall(
        r'Received:.*?(?=\nReceived:|\n\n)', raw, re.DOTALL
    )

    for header in reversed(received_headers):  # oldest first = closest to sender
        match = IP_PATTERN.search(header)
        if match:
            ip = match.group(1)
            if not is_private_ip(ip):
                return ip

    return None


def get_subject_and_from(service, msg_id):
    """Fetch basic metadata for logging/context."""
    msg = service.users().messages().get(
        userId='me', id=msg_id, format='metadata',
        metadataHeaders=['Subject', 'From']
    ).execute()

    headers = {h['name']: h['value'] for h in msg['payload']['headers']}
    return headers.get('Subject', '(no subject)'), headers.get('From', '(unknown sender)')


def poll_inbox(service, seen_ids):
    results = service.users().messages().list(
        userId='me', labelIds=['INBOX'], maxResults=20
    ).execute()

    messages = results.get('messages', [])

    for m in messages:
        msg_id = m['id']
        if msg_id in seen_ids:
            continue

        seen_ids.add(msg_id)
        subject, sender = get_subject_and_from(service, msg_id)
        ip = get_sender_ip(service, msg_id)

        print(f"\n--- New message ---")
        print(f"From:    {sender}")
        print(f"Subject: {subject}")
        print(f"IP:      {ip or 'Not found (sender likely used major webmail provider)'}")

    return seen_ids


def main():
    print("Authenticating with Gmail...")
    service = get_gmail_service()
    print("Authenticated. Starting inbox poll (every "
          f"{POLL_INTERVAL_SECONDS}s). Press Ctrl+C to stop.\n")

    seen_ids = load_seen_ids()

    # On first run, mark all current mail as "seen" so we only report
    # NEW mail from this point forward (avoids dumping your whole inbox).
    if not seen_ids:
        results = service.users().messages().list(
            userId='me', labelIds=['INBOX'], maxResults=50
        ).execute()
        seen_ids = {m['id'] for m in results.get('messages', [])}
        save_seen_ids(seen_ids)
        print(f"Initialized with {len(seen_ids)} existing messages marked as seen.\n")

    try:
        while True:
            seen_ids = poll_inbox(service, seen_ids)
            save_seen_ids(seen_ids)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == '__main__':
    main()
