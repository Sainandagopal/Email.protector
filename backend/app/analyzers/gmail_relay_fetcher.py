"""
Live Gmail Sender Origin IP Fetcher
-----------------------------------
Integrates with authenticated Gmail API credentials (token.json) to extract
the authentic 'Received:' header originating IP for incoming messages.
"""

import os
import re
import base64
import threading
from typing import Optional, Dict

IP_PATTERN = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')
PRIVATE_IP_PREFIXES = ('10.', '192.168.', '127.', '172.16.', '172.17.',
                        '172.18.', '172.19.', '172.2', '172.3', '0.', '255.')

_lock = threading.Lock()
_ip_cache: Dict[str, str] = {}

def _find_token_file() -> Optional[str]:
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "token.json")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "token.json")),
        os.path.abspath("token.json"),
        os.path.abspath(os.path.join("..", "token.json")),
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return None

def fetch_gmail_origin_ip(sender_email: str, subject: str = "") -> Optional[str]:
    """Fetch originating IP from Gmail API with thread safety and caching."""
    clean_email = sender_email.strip().lower()
    cache_key = f"{clean_email}:{subject[:20]}"
    
    if cache_key in _ip_cache:
        return _ip_cache[cache_key]
    if clean_email in _ip_cache:
        return _ip_cache[clean_email]

    token_file = _find_token_file()
    if not token_file:
        return None

    with _lock:
        # Check cache again inside lock
        if cache_key in _ip_cache:
            return _ip_cache[cache_key]

        try:
            from google.oauth2.credentials import Credentials
            from google.auth.transport.requests import Request
            from googleapiclient.discovery import build

            creds = Credentials.from_authorized_user_file(token_file, ['https://www.googleapis.com/auth/gmail.readonly'])
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())

            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

            q = f"from:{clean_email}"
            if subject and len(subject.strip()) > 3:
                clean_sub = re.sub(r'[^\w\s]', '', subject).strip()
                if clean_sub:
                    q += f' subject:"{clean_sub[:24]}"'

            res = service.users().messages().list(userId='me', q=q, maxResults=1).execute()
            messages = res.get('messages', [])
            if not messages:
                res = service.users().messages().list(userId='me', q=f"from:{clean_email}", maxResults=1).execute()
                messages = res.get('messages', [])

            if not messages:
                return None

            msg_id = messages[0]['id']
            msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
            raw = base64.urlsafe_b64decode(msg['raw']).decode('utf-8', errors='ignore')

            received_headers = re.findall(r'Received:.*?(?=\nReceived:|\n\n)', raw, re.DOTALL)
            for header in reversed(received_headers):
                match = IP_PATTERN.search(header)
                if match:
                    ip = match.group(1)
                    if not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
                        _ip_cache[cache_key] = ip
                        _ip_cache[clean_email] = ip
                        return ip
        except Exception as e:
            print(f"[SIH-Guard] Gmail API lookup safe note: {e}")

    return None

