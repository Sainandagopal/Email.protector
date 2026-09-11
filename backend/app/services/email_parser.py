import email
from email import policy
import hashlib
import re
from bs4 import BeautifulSoup
from typing import Dict, Any, List

class EmailParserService:
    """Parses raw EML/RFC-822 messages and structured JSON payloads into normalized format."""

    def parse_eml_text(self, raw_eml: str) -> Dict[str, Any]:
        msg = email.message_from_string(raw_eml, policy=policy.default)
        return self._extract_from_message(msg)

    def parse_eml_bytes(self, raw_bytes: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        return self._extract_from_message(msg)

    def _extract_from_message(self, msg) -> Dict[str, Any]:
        subject = msg.get('Subject', 'Untitled Subject')
        sender = msg.get('From', 'Unknown Sender')
        date_str = msg.get('Date', '')
        recipients = msg.get('To', '')

        # Extract headers dictionary
        headers = {}
        for k, v in msg.items():
            # Combine duplicate headers if any
            if k in headers:
                headers[k] += f"\n{v}"
            else:
                headers[k] = str(v)

        # Extract body (plain & html)
        body_plain = ""
        body_html = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition() or "")
                if "attachment" in content_disposition:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode(errors='replace')
                        if content_type == 'text/plain':
                            body_plain += decoded + "\n"
                        elif content_type == 'text/html':
                            body_html += decoded + "\n"
                except Exception:
                    pass
        else:
            content_type = msg.get_content_type()
            raw_content = ""
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    raw_content = payload.decode(errors='replace')
            except Exception:
                raw_content = str(msg.get_payload())

            if content_type == 'text/html' or "<html" in raw_content.lower():
                body_html = raw_content
            else:
                body_plain = raw_content

        links = []
        # If HTML exists, parse text and links from it
        if body_html:
            soup = BeautifulSoup(body_html, 'html.parser')
            if not body_plain.strip():
                body_plain = soup.get_text(separator=' ', strip=True)

            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                text = a.get_text(strip=True)
                if href and not href.startswith('mailto:') and not href.startswith('javascript:'):
                    links.append({"url": href, "text": text})

        # Also extract any plaintext URLs with regex
        combined_body = f"{body_plain} {body_html}"
        plain_urls = re.findall(r'https?://[^\s<>"\'\)]+', combined_body)
        existing_urls = {l["url"] for l in links}
        for u in plain_urls:
            u_clean = u.rstrip('.,;')
            if u_clean not in existing_urls:
                existing_urls.add(u_clean)
                links.append({"url": u_clean, "text": u_clean})

        body_hash = hashlib.sha256(body_plain.encode('utf-8')).hexdigest()

        return {
            "subject": str(subject),
            "sender": str(sender),
            "date": str(date_str),
            "recipients": str(recipients),
            "body": body_plain.strip(),
            "body_html": body_html.strip(),
            "headers": headers,
            "links": links,
            "body_hash": body_hash
        }
