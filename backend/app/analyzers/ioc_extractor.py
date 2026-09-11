import re
import hashlib
from typing import List, Dict, Any, Set

PRIVATE_IP_REGEX = re.compile(
    r'^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|'
    r'0\.0\.0\.0)$'
)

class IocExtractor:
    """Extracts and normalizes Indicators of Compromise (IOCs) from email data."""

    def extract_all(self, text: str, headers: Dict[str, str], links: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        iocs = []
        seen_values: Set[str] = set()

        combined_text = f"{text} " + " ".join([f"{k}: {v}" for k, v in headers.items()])
        for link in links:
            combined_text += f" {link.get('url', '')} {link.get('text', '')}"

        # 1. IP Addresses (IPv4)
        ip_candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', combined_text)
        for ip in ip_candidates:
            # Validate octets
            octets = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                if not PRIVATE_IP_REGEX.match(ip) and ip not in seen_values:
                    seen_values.add(ip)
                    # Determine source
                    source = "email_header" if ip in str(headers) else "email_body"
                    iocs.append({
                        "type": "ip",
                        "value": ip,
                        "risk": "medium",
                        "source": source
                    })

        # 2. URLs
        url_candidates = re.findall(r'https?://[^\s<>"\'\)]+', combined_text)
        for u in url_candidates:
            u_clean = u.rstrip('.,;')
            if u_clean not in seen_values:
                seen_values.add(u_clean)
                iocs.append({
                    "type": "url",
                    "value": u_clean,
                    "risk": "medium",
                    "source": "email_links"
                })

        # 3. Domains
        domain_candidates = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', combined_text)
        for d in domain_candidates:
            d_lower = d.lower()
            if d_lower not in seen_values and not d_lower.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                seen_values.add(d_lower)
                iocs.append({
                    "type": "domain",
                    "value": d_lower,
                    "risk": "low",
                    "source": "domain_reference"
                })

        # 4. Email Addresses
        email_candidates = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', combined_text)
        for e in email_candidates:
            e_lower = e.lower()
            if e_lower not in seen_values:
                seen_values.add(e_lower)
                iocs.append({
                    "type": "email",
                    "value": e_lower,
                    "risk": "low",
                    "source": "sender_recipient"
                })

        # 5. Hashes (MD5, SHA1, SHA256)
        hash_candidates = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
        for h in hash_candidates:
            h_lower = h.lower()
            if h_lower not in seen_values:
                seen_values.add(h_lower)
                hash_type = "sha256" if len(h) == 64 else ("sha1" if len(h) == 40 else "md5")
                iocs.append({
                    "type": hash_type,
                    "value": h_lower,
                    "risk": "high",
                    "source": "attachment_hash"
                })

        # Also add body content SHA-256 hash as an IOC
        if text.strip():
            body_sha256 = hashlib.sha256(text.encode('utf-8')).hexdigest()
            if body_sha256 not in seen_values:
                seen_values.add(body_sha256)
                iocs.append({
                    "type": "body_sha256",
                    "value": body_sha256,
                    "risk": "low",
                    "source": "cryptographic_fingerprint"
                })

        return iocs
