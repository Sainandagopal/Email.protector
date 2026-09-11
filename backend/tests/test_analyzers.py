import pytest
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.ioc_extractor import IocExtractor
from app.ml.threat_classifier import ThreatClassifier
from app.services.email_parser import EmailParserService

def test_header_analyzer_spf_failure():
    analyzer = HeaderAnalyzer()
    headers = {
        "Received-SPF": "fail (google.com: domain does not designate sender)",
        "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        "Return-Path": "<attacker@evil-relay.ru>"
    }
    result = analyzer.analyze(headers, "Security <admin@paypal.com>")
    assert result["spf_status"] == "fail"
    assert result["dmarc_status"] == "fail"
    assert result["sender_alignment"]["is_mismatch"] is True
    assert result["risk_score"] >= 60

def test_url_analyzer_malicious_vectors():
    analyzer = UrlAnalyzer()
    # 1. IP hostname
    res_ip = analyzer.analyze_single_url("http://185.220.101.5/login")
    assert res_ip["risk"] in ("high", "critical")
    assert "raw IP address" in res_ip["reasons"]

    # 2. Punycode
    res_puny = analyzer.analyze_single_url("http://login.xn--microsft-p2a.com")
    assert "Punycode" in res_puny["reasons"]

    # 3. Deceptive display link
    res_deceptive = analyzer.analyze_single_url("http://evil.com/steal", "https://paypal.com/verify")
    assert "Deceptive link" in res_deceptive["reasons"]

def test_ioc_extractor():
    extractor = IocExtractor()
    text = "Contact 185.220.101.5 or check http://bad-domain.top/malware.exe with hash d41d8cd98f00b204e9800998ecf8427e"
    iocs = extractor.extract_all(text, {}, [])
    types = [i["type"] for i in iocs]
    assert "ip" in types
    assert "url" in types
    assert "domain" in types
    assert "md5" in types

def test_threat_classifier_phishing_vs_benign():
    classifier = ThreatClassifier()
    phish_text = "URGENT: Your account has been suspended! Verify your password and credentials immediately to avoid permanent forfeiture."
    benign_text = "Hi team, please find attached the weekly notes and team lunch agenda for Thursday."

    phish_res = classifier.analyze_text(phish_text)
    benign_res = classifier.analyze_text(benign_text)

    assert phish_res["nlp_score"] > benign_res["nlp_score"]
    assert len(phish_res["detected_triggers"]) > 0

def test_email_parser_eml():
    parser = EmailParserService()
    raw_eml = """From: Support <support@test.org>
To: user@enterprise.com
Subject: Test Email Parser
Date: Fri, 11 Sep 2026 10:00:00 +0000
Content-Type: text/plain

This is a test body with IP 198.51.100.24.
"""
    parsed = parser.parse_eml_text(raw_eml)
    assert parsed["subject"] == "Test Email Parser"
    assert "198.51.100.24" in parsed["body"]
    assert parsed["body_hash"] is not None
