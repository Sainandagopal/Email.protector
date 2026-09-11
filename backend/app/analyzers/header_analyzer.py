import re
from typing import Dict, List, Tuple, Any

class HeaderAnalyzer:
    """Analyzes email headers for SPF, DKIM, DMARC, Return-Path, and Received hop chains."""

    def analyze(self, headers: Dict[str, str], sender_str: str) -> Dict[str, Any]:
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        spf_status = self._check_spf(normalized_headers)
        dkim_status = self._check_dkim(normalized_headers)
        dmarc_status = self._check_dmarc(normalized_headers)
        mismatch_info = self._check_sender_alignment(normalized_headers, sender_str)
        hops = self._parse_received_hops(normalized_headers)

        # Risk score calculation for headers (0 to 100)
        risk_score = 0
        reasons = []

        if spf_status == "fail":
            risk_score += 35
            reasons.append("SPF validation failed (unauthorized sender IP)")
        elif spf_status == "softfail":
            risk_score += 20
            reasons.append("SPF softfail detected")

        if dkim_status == "fail":
            risk_score += 25
            reasons.append("DKIM cryptographic signature verification failed")

        if dmarc_status == "fail":
            risk_score += 30
            reasons.append("DMARC policy check failed")

        if mismatch_info["is_mismatch"]:
            risk_score += 35
            reasons.append(f"Sender spoofing detected: From domain ({mismatch_info['from_domain']}) does not match Return-Path ({mismatch_info['return_path_domain']})")

        risk_score = min(100, risk_score)

        auth_summary = "Pass"
        if risk_score > 50:
            auth_summary = "Fail"
        elif risk_score > 20:
            auth_summary = "Warning"

        return {
            "risk_score": risk_score,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "auth_summary": auth_summary,
            "sender_alignment": mismatch_info,
            "reasons": reasons,
            "hops": hops
        }

    def _check_spf(self, headers: Dict[str, str]) -> str:
        auth_results = headers.get("authentication-results", "").lower()
        received_spf = headers.get("received-spf", "").lower()

        combined = f"{auth_results} {received_spf}"
        if "spf=fail" in combined or "fail" in received_spf:
            return "fail"
        if "spf=softfail" in combined or "softfail" in received_spf:
            return "softfail"
        if "spf=pass" in combined or "pass" in received_spf:
            return "pass"
        return "none"

    def _check_dkim(self, headers: Dict[str, str]) -> str:
        auth_results = headers.get("authentication-results", "").lower()
        dkim_sig = headers.get("dkim-signature", "")

        if "dkim=fail" in auth_results:
            return "fail"
        if "dkim=pass" in auth_results:
            return "pass"
        if dkim_sig:
            return "present"
        return "none"

    def _check_dmarc(self, headers: Dict[str, str]) -> str:
        auth_results = headers.get("authentication-results", "").lower()
        dmarc_res = headers.get("dmarc-filter", "").lower()

        combined = f"{auth_results} {dmarc_res}"
        if "dmarc=fail" in combined:
            return "fail"
        if "dmarc=pass" in combined:
            return "pass"
        return "none"

    def _check_sender_alignment(self, headers: Dict[str, str], sender_str: str) -> Dict[str, Any]:
        return_path = headers.get("return-path", "").strip()
        reply_to = headers.get("reply-to", "").strip()

        from_email_match = re.search(r'[\w\.-]+@([\w\.-]+)', sender_str)
        return_path_match = re.search(r'[\w\.-]+@([\w\.-]+)', return_path)
        reply_to_match = re.search(r'[\w\.-]+@([\w\.-]+)', reply_to)

        from_domain = from_email_match.group(1).lower() if from_email_match else ""
        return_path_domain = return_path_match.group(1).lower() if return_path_match else ""
        reply_to_domain = reply_to_match.group(1).lower() if reply_to_match else ""

        is_mismatch = False
        if from_domain and return_path_domain and from_domain != return_path_domain:
            # Check if one is a subdomain of the other
            if not (return_path_domain.endswith("." + from_domain) or from_domain.endswith("." + return_path_domain)):
                is_mismatch = True

        return {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
            "is_mismatch": is_mismatch
        }

    def _parse_received_hops(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        hops = []
        # Support single string or multi-line received
        received_raw = headers.get("received", "")
        if not received_raw:
            return hops

        # Split by "from " occurrences if multiple hops are concatenated
        hop_blocks = re.split(r'(?=from\s+)', received_raw, flags=re.IGNORECASE)

        for idx, block in enumerate(hop_blocks):
            if not block.strip():
                continue

            # Extract from host / by host
            from_match = re.search(r'from\s+([^\s\(\)]+)', block, re.IGNORECASE)
            ip_match = re.search(r'\[?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\]?', block)
            by_match = re.search(r'by\s+([^\s\(\)]+)', block, re.IGNORECASE)

            from_host = from_match.group(1) if from_match else "unknown"
            ip = ip_match.group(1) if ip_match else None
            by_host = by_match.group(1) if by_match else "unknown"

            hops.append({
                "hop_number": idx + 1,
                "from_host": from_host,
                "ip": ip,
                "by_host": by_host,
                "raw": block.strip()
            })

        return hops
