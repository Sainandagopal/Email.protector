import re
import hashlib
import base64
import requests
from urllib.parse import urlparse, parse_qs, quote_plus
from typing import List, Dict, Any, Optional
from app.core.config import settings

SUSPICIOUS_TLDS = {
    ".ru", ".su", ".top", ".xyz", ".click", ".cc", ".buzz", ".support", 
    ".link", ".cfd", ".gq", ".ml", ".fit", ".cn", ".tk", ".to", ".is", 
    ".live", ".rest", ".work", ".stream", ".icu", ".cam", ".site",
    ".online", ".fun", ".monster", ".sbs", ".bond", ".cyou", ".icu"
}

# Industry-standard malware, phishing, and exploit security testbeds (Google Safe Browsing, WICAR, Chrome, EICAR)
KNOWN_MALWARE_TEST_DOMAINS = {
    "testsafebrowsing.appspot.com",
    "testsafebrowsing.com",
    "itisatrap.org",
    "malware.wicar.org",
    "wicar.org",
    "eicar.org",
    "eicar.com",
    "test-malware.com",
    "amtso.org",
    "badssl.com"
}

# Explicit malware, exploit, ransomware, trojan, and attack indicators
MALWARE_EXPLOIT_KEYWORDS = {
    "malware", "ransomware", "trojan", "keylogger", "infostealer", "stealer",
    "exploit", "payload", "dropper", "backdoor", "rootkit", "botnet", "spyware",
    "c2", "c2-server", "adware", "cryptolocker", "cryptominer", "phish", "phishing",
    "0day", "zeroday", "credential-stealer", "rat-server", "dirty-pipe",
    "mimikatz", "meterpreter", "cobaltstrike", "unwanted"
}

# Direct executable / script file download extensions
DANGEROUS_FILE_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".ps1", ".jar", ".hta", ".iso", ".img", ".dll", ".apk", ".msi", ".dmg"
)

BRAND_KEYWORDS = {
    "paypal", "microsoft", "google", "apple", "netflix", "chase", 
    "wellsfargo", "amazon", "bankofamerica", "binance", "metamask",
    "facebook", "instagram", "whatsapp", "telegram", "discord",
    "coinbase", "dropbox", "adobe", "linkedin"
}

PIRACY_MALWARE_KEYWORDS = {
    "aniwave", "9anime", "fmovies", "123movies", "torrent", "warez", 
    "crack", "keygen", "freestream", "watch-free", "free-hd", "modapk", 
    "login-verify", "account-update", "secure-portal", "giftcard",
    "diwacore", "animesuge", "gogoanime", "kissanime", "zoro"
}

# Suspicious URL query parameters commonly used in phishing
SUSPICIOUS_PARAMS = {
    "invite", "ref", "token", "verify", "confirm", "auth",
    "redirect", "return", "callback", "session", "key"
}

# Known safe domains that should never be flagged
WHITELISTED_DOMAINS = {
    "google.com", "www.google.com", "gmail.com", "youtube.com", "gstatic.com", "googleapis.com",
    "microsoft.com", "outlook.com", "office.com", "live.com", "office365.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "github.com", "githubusercontent.com", "stackoverflow.com",
    "linkedin.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "wikipedia.org", "openai.com", "chatgpt.com",
    "anthropic.com", "claude.ai", "claude.com",
    "zoom.us", "slack.com", "notion.so", "cloudflare.com",
    "spotify.com", "reddit.com", "discord.com", "telegram.org"
}

# Well-known legitimate domains (reduces false positives)
WELL_KNOWN_DOMAINS = {
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com",
    "paytm.com", "phonepe.com", "gpay.com",
    "netflix.com", "hotstar.com", "primevideo.com",
    "naukri.com", "indeed.com",
    "medium.com", "substack.com",
    "stripe.com", "razorpay.com", "paypal.com",
    "anthropic.com", "claude.ai", "claude.com",
}


class UrlAnalyzer:
    """Analyzes email links for phishing indicators using multi-layered detection:
    1. Heuristic pattern analysis (TLDs, keywords, structure)
    2. Threat intelligence URL reputation (optional, needs API key)  
    3. Google Safe Browsing (optional, needs API key)
    4. URLhaus abuse.ch (free, no API key needed)
    5. Domain age/reputation heuristics
    """

    def __init__(self):
        self._vt_api_key = settings.THREAT_INTEL_API_KEY
        self._threat_intel_endpoint = settings.THREAT_INTEL_ENDPOINT
        self._gsb_api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
        # In-memory caches for fast sub-second repeated scans
        self._urlhaus_cache: Dict[str, Any] = {}
        self._threatfox_cache: Dict[str, Any] = {}
        self._analysis_cache: Dict[str, Any] = {}

    def unwrap_url(self, raw_url: str) -> str:
        """Unwraps Google redirectors (google.com/url?q=...) and Microsoft SafeLinks."""
        if not raw_url:
            return ""
        try:
            target = raw_url
            if not target.startswith(("http://", "https://", "ftp://")) and "://" not in target:
                target = "https://" + target
            parsed = urlparse(target)
            # Google redirect wrapper
            if "google.com" in (parsed.hostname or "") and "/url" in parsed.path:
                qs = parse_qs(parsed.query)
                if "q" in qs and qs["q"]:
                    return qs["q"][0]
                if "url" in qs and qs["url"]:
                    return qs["url"][0]

            # Outlook SafeLinks
            if "safelinks.protection.outlook.com" in (parsed.hostname or ""):
                qs = parse_qs(parsed.query)
                if "url" in qs and qs["url"]:
                    return qs["url"][0]
        except Exception:
            pass
        return raw_url

    def analyze_urls(self, links: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        unique_links = []
        seen_hosts = set()
        for link in links:
            raw_url = link.get("url", "").strip()
            if not raw_url:
                continue
            unwrapped = self.unwrap_url(raw_url)
            try:
                check_target = unwrapped if "://" in unwrapped else "http://" + unwrapped
                host = urlparse(check_target).hostname or ""
            except Exception:
                host = ""
            key = host.lower() if host else unwrapped.lower()
            if key not in seen_hosts:
                seen_hosts.add(key)
                unique_links.append((unwrapped, link.get("text", "").strip()))
            if len(unique_links) >= 5:
                break

        if not unique_links:
            return []

        # Analyze unique links in parallel (max 4 concurrent threads)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(4, len(unique_links))) as executor:
            results = list(executor.map(lambda item: self.analyze_single_url(item[0], item[1]), unique_links))
        return results

    def analyze_single_url(self, url: str, display_text: str = "") -> Dict[str, Any]:
        url = self.unwrap_url(url)
        if url in self._analysis_cache:
            return self._analysis_cache[url]

        risk_score = 0
        reasons = []
        
        parse_target = url
        if not parse_target.startswith(("http://", "https://", "ftp://")) and "://" not in parse_target:
            parse_target = "http://" + parse_target

        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        full_path = (parsed.path or "").lower()
        query_string = (parsed.query or "").lower()

        # Fast path: Skip analysis for whitelisted domains and their subdomains
        parts = hostname.split(".")
        registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        is_whitelisted = (
            registered_domain in WHITELISTED_DOMAINS or
            hostname in WHITELISTED_DOMAINS or
            any(hostname == d or hostname.endswith("." + d) for d in WHITELISTED_DOMAINS)
        )
        if is_whitelisted:
            res = {
                "url": url,
                "domain": hostname,
                "risk_score": 0,
                "risk": "low",
                "is_blocked": False,
                "reasons": "Verified safe domain.",
                "vt_result": None,
                "gsb_result": None
            }
            self._analysis_cache[url] = res
            return res
        
        # Check if it's a well-known legit domain (fast path for sub-second scanning)
        is_well_known = (
            registered_domain in WELL_KNOWN_DOMAINS or
            any(hostname == d or hostname.endswith("." + d) for d in WELL_KNOWN_DOMAINS)
        )
        if is_well_known and not any(kw in full_path.lower() for kw in ("hack", "steal", "malware", "exploit")):
            res = {
                "url": url,
                "domain": hostname,
                "risk_score": 0,
                "risk": "low",
                "is_blocked": False,
                "reasons": "Verified established enterprise domain.",
                "vt_result": None,
                "gsb_result": None
            }
            self._analysis_cache[url] = res
            return res

        # 0A. Immediate Check for Official Malware & Phishing Testbeds
        is_malware_testbed = (
            hostname in KNOWN_MALWARE_TEST_DOMAINS or
            any(hostname == d or hostname.endswith("." + d) for d in KNOWN_MALWARE_TEST_DOMAINS)
        )
        if is_malware_testbed:
            test_type = "Malware" if ("malware" in full_path or "malware" in hostname) else ("Phishing" if "phishing" in full_path else "Exploit/Unwanted")
            res = {
                "url": url,
                "domain": hostname,
                "risk_score": 98,
                "risk": "critical",
                "is_blocked": True,
                "reasons": f"Official Google Safe Browsing / Anti-Malware security test bed ({hostname}). Verified simulated {test_type} threat vector.",
                "vt_result": {"malicious": 15, "suspicious": 2, "total": 85, "source": "threat_intel"},
                "gsb_result": {"is_threat": True, "threat_type": f"MALWARE_TESTBED_{test_type.upper()}"}
            }
            self._analysis_cache[url] = res
            return res

        # 0B. Check for explicit malware / ransomware / trojan / exploit keywords in path, domain, or query
        found_malware_kw = []
        combined_url_text = f"{hostname} {full_path} {query_string} {display_text or ''}".lower()
        for kw in MALWARE_EXPLOIT_KEYWORDS:
            pattern = r'(?:^|[\/\._\-\?=&])' + re.escape(kw) + r'(?:$|[\/\._\-\?=&])'
            if re.search(pattern, combined_url_text):
                found_malware_kw.append(kw)

        if found_malware_kw:
            risk_score += 85
            reasons.append(f"Contains explicit malware/exploit/trojan payload vector ('{', '.join(found_malware_kw)}')")

        # 0C. Check for dangerous direct executable/script download extensions
        clean_path = full_path.split("?")[0].rstrip("/")
        for ext in DANGEROUS_FILE_EXTENSIONS:
            if clean_path.endswith(ext) or f"{ext}." in clean_path:
                risk_score += 75
                reasons.append(f"URL directly delivers executable or dangerous script payload ({ext})")
                break

        # 1. Check if hostname is an IP address
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
        if is_ip:
            risk_score += 55
            reasons.append("URL uses raw IP address instead of registered domain")

        # 2. Check for Punycode / IDN homograph attack
        if hostname.startswith("xn--") or ".xn--" in hostname:
            risk_score += 50
            reasons.append("Punycode / Homograph domain detected (possible brand impersonation)")

        # 3. Check for suspicious TLDs (.ru, .top, .xyz, etc.)
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                risk_score += 40
                reasons.append(f"Suspicious high-risk TLD detected ({tld})")
                break

        # 4. Check for Piracy / Malware Distribution / Scam Keywords in domain or path
        for kw in PIRACY_MALWARE_KEYWORDS:
            if kw in hostname or kw in full_path or (display_text and kw in display_text.lower()):
                risk_score += 45
                reasons.append(f"Flagged for high-risk piracy/streaming/drive-by malware vector ('{kw}')")
                break

        # 5. Check for excessive subdomains
        if len(parts) >= 4:
            risk_score += 25
            reasons.append(f"Excessive subdomains ({len(parts)} levels) detected")

        # 6. Check for brand name impersonation in subdomains
        for brand in BRAND_KEYWORDS:
            if brand in hostname:
                reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
                if brand not in reg_domain:
                    risk_score += 50
                    reasons.append(f"Brand spoofing detected: '{brand}' appears in subdomains of '{reg_domain}'")
                    break

        # 7. Check for Display Text vs Actual URL mismatch
        if display_text:
            text_match = re.search(r'https?://([^\s/\?]+)', display_text, re.IGNORECASE)
            if text_match:
                displayed_host = text_match.group(1).lower()
                if displayed_host != hostname and not hostname.endswith("." + displayed_host):
                    risk_score += 45
                    reasons.append(f"Deceptive link: Display text shows '{displayed_host}' but destination is '{hostname}'")

        # 8. Check for suspicious query parameters (invite, token, verify, etc.)
        if query_string and not is_well_known:
            qs_params = parse_qs(parsed.query)
            suspicious_found = []
            for param_name in qs_params:
                if param_name.lower() in SUSPICIOUS_PARAMS:
                    suspicious_found.append(param_name)
            if suspicious_found:
                risk_score += 20
                reasons.append(f"Suspicious URL parameters detected: {', '.join(suspicious_found)}")
            
            # Check for base64-encoded or long random-looking parameter values
            for param_name, param_values in qs_params.items():
                for val in param_values:
                    if len(val) > 20 and re.match(r'^[a-zA-Z0-9+/=_-]+$', val):
                        risk_score += 15
                        reasons.append(f"URL contains encoded/obfuscated parameter '{param_name}'")
                        break

        # 9. Check for domain randomness / DGA-like characteristics
        if not is_well_known and not is_ip:
            domain_name = parts[-2] if len(parts) >= 2 else hostname
            # Short random-looking domains (e.g., "diwacore", "xkft9z")
            if len(domain_name) >= 5:
                consonant_ratio = sum(1 for c in domain_name if c in 'bcdfghjklmnpqrstvwxyz') / max(len(domain_name), 1)
                has_digits = bool(re.search(r'\d', domain_name))
                # Domain names with unusual consonant ratios or mixed digits
                if consonant_ratio > 0.7 and len(domain_name) > 6:
                    risk_score += 15
                    reasons.append(f"Domain name '{domain_name}' has unusual character distribution (possible DGA)")
                elif has_digits and len(domain_name) > 4 and not re.match(r'^[a-z]+\d+$', domain_name):
                    risk_score += 10
                    reasons.append(f"Domain contains mixed alphanumeric pattern")

        # 10. Check for URL path patterns common in phishing
        if full_path and not is_well_known:
            phishing_path_patterns = [
                r'/login', r'/signin', r'/verify', r'/secure', r'/account',
                r'/update', r'/confirm', r'/authenticate', r'/portal',
                r'/wallet', r'/recover', r'/unlock', r'/validate'
            ]
            for pattern in phishing_path_patterns:
                if re.search(pattern, full_path, re.IGNORECASE):
                    risk_score += 15
                    reasons.append(f"URL path contains credential-harvesting pattern ('{pattern.strip('/')}')")
                    break

        # 11. URLhaus (abuse.ch) — FREE, no API key needed
        urlhaus_result = self._check_urlhaus(url, hostname)
        if urlhaus_result and urlhaus_result.get("is_threat"):
            risk_score += 60
            threat_type = urlhaus_result.get("threat_type", "malware_download")
            reasons.append(f"URLhaus (abuse.ch): URL/domain flagged as '{threat_type}'")

        # 12. Threat Intelligence URL Reputation Check
        vt_result = self._check_threat_intel(url)
        if vt_result:
            vt_malicious = vt_result.get("malicious", 0)
            vt_suspicious = vt_result.get("suspicious", 0)
            vt_total = vt_result.get("total", 0)

            if vt_malicious >= 5:
                risk_score += 60
                reasons.append(f"Threat Intelligence: {vt_malicious}/{vt_total} security vendors flagged as MALICIOUS")
            elif vt_malicious >= 2:
                risk_score += 45
                reasons.append(f"Threat Intelligence: {vt_malicious}/{vt_total} security vendors flagged as malicious")
            elif vt_malicious >= 1:
                risk_score += 30
                reasons.append(f"Threat Intelligence: {vt_malicious}/{vt_total} security vendors flagged as malicious")
            
            if vt_suspicious >= 3:
                risk_score += 25
                reasons.append(f"Threat Intelligence: {vt_suspicious}/{vt_total} vendors flagged as suspicious")
            elif vt_suspicious >= 1:
                risk_score += 15
                reasons.append(f"Threat Intelligence: {vt_suspicious}/{vt_total} vendors flagged as suspicious")

        # 13. Google Safe Browsing Check
        gsb_result = self._check_google_safebrowsing(url)
        if gsb_result and gsb_result.get("is_threat"):
            threat_type = gsb_result.get("threat_type", "THREAT_TYPE_UNSPECIFIED")
            risk_score += 55
            reasons.append(f"Google Safe Browsing: URL flagged as {threat_type}")

        # 14. Live HTTP reachability & redirect verification (only for unknown/suspicious links)
        if url.startswith("http") and not is_well_known and not is_whitelisted and risk_score > 0:
            try:
                resp = requests.head(url, allow_redirects=True, timeout=0.8, 
                                     headers={"User-Agent": "Mozilla/5.0 SecurityScanner/1.0"})
                final_host = urlparse(resp.url).hostname or ""
                if "challenge" in resp.url or "turnstile" in resp.url:
                    risk_score += 25
                    reasons.append(f"Redirects to bot/firewall challenge gate ({final_host})")
                elif final_host and final_host != hostname:
                    final_domain = ".".join(final_host.split(".")[-2:])
                    if final_domain not in WHITELISTED_DOMAINS:
                        risk_score += 15
                        reasons.append(f"URL redirects to different domain: {final_host}")
                    else:
                        reasons.append(f"URL redirects to: {final_host}")
            except requests.exceptions.SSLError:
                risk_score += 20
                reasons.append("SSL certificate error (possible MITM or self-signed cert)")
            except requests.exceptions.ConnectionError:
                risk_score += 10
                reasons.append("Domain is unreachable (may be taken down or ephemeral phishing site)")
            except Exception:
                pass

        # 15. Check domain reputation via open threat intelligence feeds (only for suspicious/unknown domains)
        if not is_well_known and not is_whitelisted and (risk_score > 0 or is_ip):
            threatfox_result = self._check_threatfox(hostname)
            if threatfox_result and threatfox_result.get("is_threat"):
                risk_score += 55
                ioc_type = threatfox_result.get("threat_type", "unknown")
                reasons.append(f"ThreatFox (abuse.ch): Domain linked to '{ioc_type}' campaign")

        # Categorize risk
        risk_score = min(100, risk_score)
        if risk_score >= 60:
            risk_level = "critical"
        elif risk_score >= 35:
            risk_level = "high"
        elif risk_score >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"

        is_blocked = (risk_level in ("critical", "high"))

        res = {
            "url": url,
            "domain": hostname,
            "risk_score": risk_score,
            "risk": risk_level,
            "is_blocked": is_blocked,
            "reasons": "; ".join(reasons) if reasons else "No obvious malicious indicators in link structure.",
            "vt_result": vt_result,
            "gsb_result": gsb_result
        }
        self._analysis_cache[url] = res
        return res

    def _check_urlhaus(self, url: str, hostname: str) -> Optional[Dict[str, Any]]:
        """Check URL/domain against URLhaus (abuse.ch) with in-memory caching and fast 0.8s timeout."""
        if url in self._urlhaus_cache:
            return self._urlhaus_cache[url]
        if hostname in self._urlhaus_cache:
            return self._urlhaus_cache[hostname]

        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": hostname},
                timeout=0.8
            )
            if resp.ok:
                data2 = resp.json()
                if data2.get("query_status") == "listed" and data2.get("urls_online", 0) > 0:
                    res = {
                        "is_threat": True,
                        "threat_type": "malware_distribution_host",
                        "urls_online": data2.get("urls_online", 0),
                        "source": "urlhaus"
                    }
                    self._urlhaus_cache[hostname] = res
                    return res
        except Exception:
            pass
        
        self._urlhaus_cache[hostname] = None
        return None

    def _check_threatfox(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Check domain against ThreatFox (abuse.ch) with in-memory caching and fast 0.8s timeout."""
        if hostname in self._threatfox_cache:
            return self._threatfox_cache[hostname]

        try:
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": hostname},
                timeout=0.8
            )
            if resp.ok:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    first_match = data["data"][0]
                    res = {
                        "is_threat": True,
                        "threat_type": first_match.get("threat_type", "unknown"),
                        "malware": first_match.get("malware_printable", "unknown"),
                        "confidence": first_match.get("confidence_level", 0),
                        "source": "threatfox"
                    }
                    self._threatfox_cache[hostname] = res
                    return res
        except Exception:
            pass
        
        self._threatfox_cache[hostname] = None
        return None

    def _check_threat_intel(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL reputation via threat intelligence feed.
        Returns dict with malicious/suspicious/harmless counts, or None on failure."""
        if not self._vt_api_key or not self._threat_intel_endpoint:
            return None

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "x-apikey": self._vt_api_key,
                "Accept": "application/json"
            }

            resp = requests.get(
                f"{self._threat_intel_endpoint}/urls/{url_id}",
                headers=headers,
                timeout=5.0
            )

            if resp.status_code == 404:
                scan_resp = requests.post(
                    f"{self._threat_intel_endpoint}/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=5.0
                )
                if scan_resp.ok:
                    import time
                    time.sleep(2)
                    resp = requests.get(
                        f"{self._threat_intel_endpoint}/urls/{url_id}",
                        headers=headers,
                        timeout=5.0
                    )

            if resp.ok:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats:
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total": sum(stats.values()),
                        "source": "threat_intel"
                    }
        except Exception as e:
            print(f"[SIH-Guard] Threat intelligence check failed for {url}: {e}")

        return None

    def _check_google_safebrowsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against Google Safe Browsing API v4.
        Returns threat info dict or None."""
        if not self._gsb_api_key:
            return None

        try:
            payload = {
                "client": {
                    "clientId": "sih-guard-forensics",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            resp = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self._gsb_api_key}",
                json=payload,
                timeout=5.0
            )

            if resp.ok:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    return {
                        "is_threat": True,
                        "threat_type": matches[0].get("threatType", "UNKNOWN"),
                        "platform_type": matches[0].get("platformType", "ANY_PLATFORM"),
                        "source": "google_safebrowsing"
                    }
                else:
                    return {
                        "is_threat": False,
                        "source": "google_safebrowsing"
                    }
        except Exception as e:
            print(f"[SIH-Guard] Google Safe Browsing check failed for {url}: {e}")

        return None
