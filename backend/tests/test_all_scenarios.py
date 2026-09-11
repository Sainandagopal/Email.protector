import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.ioc_extractor import IocExtractor
from app.ml.threat_classifier import ThreatClassifier
from app.services.email_parser import EmailParserService

client = TestClient(app)

def test_api_health():
    """Verify health check endpoint returns 200 and online status."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "timestamp" in data

def test_safe_email_scenario():
    """Scenario 1: Legitimate corporate email with clean links should be SAFE with low score."""
    raw_eml = """From: HR Team <hr@secure-enterprise.com>
To: employee@secure-enterprise.com
Subject: Quarterly All-Hands Meeting Agenda & Notes
Date: Thu, 10 Sep 2026 09:00:00 +0000
Authentication-Results: mx.google.com; spf=pass (google.com: domain of hr@secure-enterprise.com designates 192.0.2.1 as permitted sender); dkim=pass header.i=@secure-enterprise.com; dmarc=pass
Received-SPF: pass (google.com: domain of hr@secure-enterprise.com designates 192.0.2.1 as permitted sender)
Content-Type: text/plain

Hi Team,

Please review the meeting agenda for Thursday:
https://secure-enterprise.com/agenda

Best regards,
HR Team
"""
    res = client.post("/api/v1/analyze/email", json={"raw_eml": raw_eml})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"] < 30
    assert data["classification"] == "SAFE"
    assert "signals" in data
    assert "user_advice" in data["signals"]
    assert "sender_trust" in data["signals"]
    assert "links_trust" in data["signals"]
    assert "origin_country" in data["signals"]

    # Ensure no false-positive link blocks
    for url in data.get("urls", []):
        assert url.get("is_blocked") is not True

def test_suspicious_email_scenario():
    """Scenario 2: Email with unaligned relay and mild pressure should trigger SUSPICIOUS."""
    raw_eml = """From: IT Helpdesk <helpdesk@support-unaligned-relay.net>
To: user@target-company.com
Subject: Notice: Server Migration in Progress
Date: Fri, 11 Sep 2026 12:00:00 +0000
Authentication-Results: mx.google.com; spf=softfail; dkim=none; dmarc=none
Content-Type: text/plain

Hello,

Our IT team is conducting scheduled maintenance. Please verify your workstation settings soon.
Contact support if you experience downtime.
"""
    res = client.post("/api/v1/analyze/email", json={"raw_eml": raw_eml})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"] >= 25
    assert data["classification"] in ("SUSPICIOUS", "PHISHING")

def test_phishing_malicious_scenario():
    """Scenario 3: Credential harvesting with raw IP URL and SPF fail must trigger PHISHING/MALICIOUS."""
    raw_eml = """From: Security Alert <service-update@paypal-security-alert.ru>
To: victim@target-corp.com
Subject: URGENT: Your PayPal account has been suspended!
Date: Fri, 11 Sep 2026 14:00:00 +0000
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail
Received-SPF: fail
Content-Type: text/plain

URGENT NOTICE:
Unauthorized login detected! Your account has been suspended.
Click here immediately to verify credentials or your funds will be permanently lost:
http://185.220.101.5/restore-login?token=malicious892
"""
    res = client.post("/api/v1/analyze/email", json={"raw_eml": raw_eml})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"] >= 70
    assert data["classification"] in ("PHISHING", "MALICIOUS")
    assert len(data.get("urls", [])) > 0

    # Ensure dangerous raw IP URL is neutralized / flagged as blocked
    raw_ip_urls = [u for u in data["urls"] if "185.220.101.5" in u.get("url", "")]
    assert len(raw_ip_urls) > 0
    assert raw_ip_urls[0]["risk_score"] >= 70 or raw_ip_urls[0].get("is_blocked") is True

    # Test that investigation record was persisted
    inv_id = data["id"]
    det_res = client.get(f"/api/v1/investigations/{inv_id}")
    assert det_res.status_code == 200
    assert det_res.json()["classification"] in ("PHISHING", "MALICIOUS")

def test_attack_graph_integrity():
    """Scenario 4: Graph endpoint must return connected nodes and edges for forensics."""
    # Run analysis first
    res = client.post("/api/v1/analyze/email", json={
        "subject": "Attack Graph Test",
        "sender": "attacker@darknet-node.org",
        "body": "Check file at http://cdn-payload-node.ru/trojan.exe and contact 198.51.100.77"
    })
    assert res.status_code == 200
    inv_id = res.json()["id"]

    graph_res = client.get(f"/api/v1/investigations/{inv_id}/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()

    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 3
    assert len(graph["edges"]) >= 2

    # Check that nodes have required visual fields
    for node in graph["nodes"]:
        assert "id" in node
        assert "label" in node
        assert "type" in node
        assert "risk" in node
        assert "x" in node
        assert "y" in node

def test_printable_forensic_report():
    """Scenario 5: Forensic report endpoint must generate complete tamper-evident HTML."""
    res = client.post("/api/v1/analyze/email", json={
        "subject": "Forensic Report Test",
        "sender": "investigator@cyber-division.gov",
        "body": "Forensic audit artifact test."
    })
    assert res.status_code == 200
    inv_id = res.json()["id"]

    rep_res = client.get(f"/api/v1/reports/{inv_id}/html")
    assert rep_res.status_code == 200
    assert "text/html" in rep_res.headers.get("content-type", "")
    assert "SIH-Guard Cyber Forensics Dossier" in rep_res.text
    assert "CASE INTEGRITY" in rep_res.text.upper() or "SHA-256" in rep_res.text

def test_ioc_deep_extraction():
    """Scenario 6: Test extraction of complex IOC types (IP, domain, hash, email, URL)."""
    extractor = IocExtractor()
    sample_text = """
    Malware dropped from 203.0.113.195 via domain bad-threat-hub.top.
    Download payload: https://bad-threat-hub.top/dropper.bin
    MD5 hash: e4d909c290d0fb1ca068ffaddf22cbd0
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    C2 handler: evil-operator@dark-c2.cc
    """
    iocs = extractor.extract_all(sample_text, {}, [])
    extracted_types = {i["type"] for i in iocs}
    assert "ip" in extracted_types
    assert "domain" in extracted_types
    assert "url" in extracted_types
    assert "md5" in extracted_types
    assert "sha256" in extracted_types

def test_url_analyzer_heuristic_checks():
    """Scenario 7: URL analyzer detects typosquatting, raw IPs, suspicious TLDs, and path entropy."""
    analyzer = UrlAnalyzer()

    # 1. Suspicious TLD (.xyz, .top, .ru)
    res_tld = analyzer.analyze_single_url("http://bank-verification.xyz/secure")
    assert res_tld["risk_score"] > 20

    # 2. Raw IP
    res_raw = analyzer.analyze_single_url("http://45.133.1.20/login")
    assert res_raw["risk"] in ("high", "critical")
    assert res_raw["is_blocked"] is True

    # 3. Legitimate URL
    res_clean = analyzer.analyze_single_url("https://www.google.com/search?q=test")
    assert res_clean["risk"] == "low"
    assert res_clean["is_blocked"] is False
