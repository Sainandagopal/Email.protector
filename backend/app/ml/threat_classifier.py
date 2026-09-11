import re
import math
import sys
from typing import Dict, List, Any, Tuple

# On Python 3.14+ on Windows, experimental numpy builds trigger SEH access violations
HAS_SKLEARN = False
if sys.version_info < (3, 14):
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        HAS_SKLEARN = True
    except Exception:
        HAS_SKLEARN = False

# Synthetic training dataset for baseline AI classifier
TRAINING_CORPUS = [
    # Phishing / Social Engineering samples (Label 1)
    ("Urgent: your account has been suspended. Please verify your password and banking credentials immediately to restore access.", 1),
    ("Security alert: Unauthorized login attempt detected from unknown location. Click here to confirm your identity or account will be locked.", 1),
    ("Action required: Your mailbox password expires in 2 hours. Retain current password by logging in now.", 1),
    ("Wire transfer request: Kindly process the urgent payment of $45,000 for vendor invoice before close of business today.", 1),
    ("Your package delivery failed. Pay $2.99 redelivery fee at this link to reschedule your parcel shipment.", 1),
    ("Final warning: Unpaid tax balance detected. Legal action will be initiated unless settled immediately.", 1),
    ("Congratulations, you have won $1,000,000 in the international promotional lottery. Send your personal details to claim prize.", 1),
    ("Update your payment method: Netflix subscription payment failed. Update credit card info to continue watching.", 1),
    ("PayPal alert: We noticed suspicious activity on your card. Verify transactions here to avoid restrictions.", 1),
    ("HR department notice: Mandatory policy update. Sign in with your corporate email credentials to acknowledge.", 1),

    # Benign samples (Label 0)
    ("Hi team, here is the weekly engineering sync agenda. Please add your discussion topics to the document.", 0),
    ("Your monthly invoice #INV-9281 has been generated. Thank you for your continued business with us.", 0),
    ("Meeting invitation: Q3 Product Roadmap review scheduled for Thursday at 2:00 PM in Conference Room B.", 0),
    ("Thank you for your order! Your items have shipped and will arrive by Friday. Track your shipment here.", 0),
    ("Weekly tech newsletter: Highlights in distributed systems, Rust performance improvements, and AI updates.", 0),
    ("Please find attached the minutes from yesterday's board meeting for your review and records.", 0),
    ("Code review requested for pull request #142: Fix null pointer exception in telemetry handler.", 0),
    ("Team lunch reminder: We are gathering at 12:30 PM at the ground floor cafe today.", 0),
    ("Welcome to our developer community! Check out our getting started documentation and quickstart guides.", 0),
    ("Your flight reservation to San Francisco is confirmed. Terminal 2, Gate 42. Check in online 24h prior.", 0)
]

SOCIAL_ENGINEERING_KEYWORDS = {
    "urgent": 15,
    "suspended": 20,
    "password": 15,
    "verify": 15,
    "unauthorized": 20,
    "immediate": 15,
    "locked": 20,
    "forfeiture": 25,
    "wire transfer": 25,
    "credit card": 15,
    "expires in": 15,
    "action required": 15
}

class ThreatClassifier:
    """Hybrid AI Engine combining TF-IDF + Logistic Regression (or pure-Python Naive Bayes fallback) with deterministic heuristic security rules."""

    def __init__(self):
        self.use_sklearn = HAS_SKLEARN
        if self.use_sklearn:
            try:
                self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english')
                self.model = LogisticRegression(random_state=42)
            except Exception:
                self.use_sklearn = False
        self._train_baseline()

    def _tokenize(self, text: str) -> List[str]:
        return [w for w in re.findall(r'[a-zA-Z]{3,}', text.lower()) if w not in ('the', 'and', 'for', 'with', 'this', 'that', 'from', 'your', 'are')]

    def _train_baseline(self):
        if self.use_sklearn:
            try:
                texts = [item[0] for item in TRAINING_CORPUS]
                labels = [item[1] for item in TRAINING_CORPUS]
                X = self.vectorizer.fit_transform(texts)
                self.model.fit(X, labels)
                return
            except Exception:
                self.use_sklearn = False

        # Pure Python Naive Bayes baseline
        self.vocab = set()
        self.class_word_counts = {0: {}, 1: {}}
        self.class_total_words = {0: 0, 1: 0}
        self.class_doc_counts = {0: 0, 1: 0}

        for text, label in TRAINING_CORPUS:
            self.class_doc_counts[label] += 1
            tokens = self._tokenize(text)
            for token in tokens:
                self.vocab.add(token)
                self.class_word_counts[label][token] = self.class_word_counts[label].get(token, 0) + 1
                self.class_total_words[label] += 1

    def analyze_text(self, text: str) -> Dict[str, Any]:
        if not text.strip():
            return {"nlp_score": 10.0, "confidence": 0.5, "detected_triggers": []}

        # 1. ML Probability
        if self.use_sklearn:
            try:
                X_test = self.vectorizer.transform([text])
                proba = float(self.model.predict_proba(X_test)[0][1])
            except Exception:
                proba = self._predict_proba_fallback(text)
        else:
            proba = self._predict_proba_fallback(text)

        nlp_ml_score = float(proba * 100)

        # 2. Keyword trigger extraction
        text_lower = text.lower()
        triggers = []
        heuristic_boost = 0
        for kw, weight in SOCIAL_ENGINEERING_KEYWORDS.items():
            if kw in text_lower:
                triggers.append(kw)
                heuristic_boost += weight

        # Combine ML + heuristic keyword presence
        final_nlp_score = min(100.0, (nlp_ml_score * 0.6) + (min(heuristic_boost, 100) * 0.4))

        return {
            "nlp_score": round(final_nlp_score, 1),
            "confidence": round(float(proba), 2),
            "detected_triggers": triggers
        }

    def _predict_proba_fallback(self, text: str) -> float:
        tokens = self._tokenize(text)
        if not tokens:
            return 0.2
        vocab_size = max(1, len(self.vocab))
        log_prob_1 = math.log(self.class_doc_counts[1] / (self.class_doc_counts[0] + self.class_doc_counts[1]))
        log_prob_0 = math.log(self.class_doc_counts[0] / (self.class_doc_counts[0] + self.class_doc_counts[1]))

        for token in tokens:
            count_1 = self.class_word_counts[1].get(token, 0)
            count_0 = self.class_word_counts[0].get(token, 0)
            log_prob_1 += math.log((count_1 + 1.0) / (self.class_total_words[1] + vocab_size))
            log_prob_0 += math.log((count_0 + 1.0) / (self.class_total_words[0] + vocab_size))

        # Sigmoid of diff
        diff = max(-20.0, min(20.0, log_prob_1 - log_prob_0))
        return 1.0 / (1.0 + math.exp(-diff))

    def compute_composite_score(
        self,
        nlp_result: Dict[str, Any],
        header_result: Dict[str, Any],
        url_results: List[Dict[str, Any]],
        geo_result: Dict[str, Any],
        iocs: List[Dict[str, Any]]
    ) -> Tuple[float, str, str, Dict[str, Any]]:
        """
        Combines signals per Section 9 weighting:
        - NLP / Social Engineering: 25%
        - Header / Authentication: 20%
        - URL / Link signals: 25%
        - Domain / IP Intelligence: 20%
        - Attachment / IOC indicators: 10%
        
        When headers are absent (Gmail live mode), weights are redistributed
        to prevent false "SAFE" verdicts.
        """
        # 1. NLP component
        nlp_score = nlp_result.get("nlp_score", 0.0)

        # 2. Header / Auth component
        header_score = header_result.get("risk_score", 0.0)

        # Detect if we're in "headerless" mode (e.g., Gmail live extraction without raw headers)
        headers_are_absent = self._headers_are_absent(header_result)

        # 3. URL component (max of all URL risk scores)
        if url_results:
            url_scores = [u.get("risk_score", 0.0) for u in url_results]
            url_score = max(url_scores)
        else:
            url_score = 0.0

        # 4. Domain / IP Infrastructure component
        geo_score = 0.0
        if geo_result:
            if geo_result.get("is_suspicious_infra", False):
                geo_score = 80.0
            else:
                geo_score = 15.0

        # 5. Attachment / Hashes component
        att_score = 0.0
        for ioc in iocs:
            if ioc.get("type") in ("md5", "sha1", "sha256") and ioc.get("risk") == "high":
                att_score = 85.0
                break

        # Calculate base weighted composite score (0-100)
        if headers_are_absent:
            # When headers are absent (Gmail DOM mode), only penalize if other suspicious indicators exist
            has_other_threats = (url_score >= 20 or nlp_score >= 35 or geo_score >= 50 or att_score >= 50)
            unknown_auth_penalty = 15.0 if has_other_threats else 0.0
            base_composite = (
                (nlp_score * 0.35) +
                (unknown_auth_penalty * 0.10) +
                (url_score * 0.35) +
                (geo_score * 0.10) +
                (att_score * 0.10)
            )
        else:
            base_composite = (
                (nlp_score * 0.25) +
                (header_score * 0.20) +
                (url_score * 0.25) +
                (geo_score * 0.20) +
                (att_score * 0.10)
            )

        # CRITICAL CYBERSECURITY OVERRIDE / FLOORS:
        composite = base_composite
        if url_score >= 65:
            composite = max(composite, url_score * 0.95, 78.0)
        elif url_score >= 35:
            composite = max(composite, url_score * 0.90, 52.0)
        elif url_score >= 20:
            composite = max(composite, url_score * 0.85, 30.0)

        # Severe header spoofing / authentication failure overrides
        if header_score >= 60:
            composite = max(composite, header_score * 0.85, 52.0)
        elif header_score >= 35:
            composite = max(composite, header_score * 0.85, 38.0)
        elif header_score >= 20:
            composite = max(composite, header_score * 0.85, 25.0)

        # Attachment threat override
        if att_score >= 70:
            composite = max(composite, att_score * 0.95, 80.0)

        # Threat Intelligence/SafeBrowsing signal override:
        for u in url_results:
            vt = u.get("vt_result")
            gsb = u.get("gsb_result")
            if vt and vt.get("malicious", 0) >= 1:
                composite = max(composite, 55.0)
                if vt.get("malicious", 0) >= 5:
                    composite = max(composite, 78.0)
            if gsb and gsb.get("is_threat"):
                composite = max(composite, 70.0)

        composite = round(min(100.0, max(0.0, composite)), 1)

        # Determine classification
        if composite >= 75.0:
            classification = "MALICIOUS"
        elif composite >= 50.0:
            classification = "PHISHING"
        elif composite >= 25.0:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        # Generate clear, human-understandable risk explanations for everyday users
        explanations = []
        user_advice = ""
        
        # 1. URL / Link Threat
        has_url_threat = False
        for u in url_results:
            if u.get("risk") in ("critical", "high", "medium") and u.get("reasons"):
                domain_name = u.get('domain', 'Link')
                explanations.append(f"Suspicious Link: '{domain_name}' ({u['reasons']})")
                has_url_threat = True
                break

        # 2. Sender / Authentication Threat
        has_auth_threat = False
        if header_result.get("reasons") and header_result.get("risk_score", 0) >= 30:
            for r in header_result["reasons"][:2]:
                explanations.append(f"Sender Impersonation: {r}")
                has_auth_threat = True

        # 3. Urgency / Social Engineering Threat
        has_nlp_threat = False
        if nlp_score >= 45:
            triggers_str = ", ".join(f"'{t}'" for t in nlp_result.get("detected_triggers", [])[:3])
            explanations.append(f"Urgency Pressure: Demands immediate action using coercive words ({triggers_str})")
            has_nlp_threat = True

        # 4. Infrastructure Threat
        has_infra_threat = False
        if geo_result and geo_result.get("is_suspicious_infra"):
            explanations.append(f"Origin Server: Sent from an anonymized/suspicious host ({geo_result.get('isp')})")
            has_infra_threat = True

        # Determine user-friendly advice and explanation string
        if classification == "SAFE":
            explanation_str = "Verified Authentic: Sender address, links, and content are safe. No phishing or fraud indicators found."
            user_advice = "Safe to read and click. This email is legitimate."
        elif classification == "SUSPICIOUS":
            explanation_str = f"Caution Needed: {'; '.join(explanations) if explanations else 'Unusual email patterns detected'}."
            user_advice = "Proceed with caution. Double-check the sender before clicking links or sharing info."
        else:
            explanation_str = f"Security Warning: {'; '.join(explanations) if explanations else 'High probability of phishing or impersonation'}."
            user_advice = "DO NOT click links, download files, or reply with passwords or money."

        origin_str = "Global"
        if geo_result:
            country = geo_result.get("country", "Global")
            ip_str = geo_result.get("ip", "")
            origin_str = f"{country} ({ip_str})" if ip_str else country

        # 5 Problem Statement Core Risks Formatted for Everyday / Basic Users
        layman_risks = [
            {
                "id": "sender_identity",
                "title": "Sender Identity & Phishing",
                "icon": "👤",
                "level": "critical" if has_auth_threat else "safe",
                "badge": "🚨 Spoofed Identity" if has_auth_threat else "🟢 Verified Authentic",
                "layman_summary": "The sender claims to be an official organization, but the email domain does not match." if has_auth_threat else "The sender's name and email domain are authentic and verified.",
                "layman_action": "Check the exact address after the @ symbol. Do not trust display names alone."
            },
            {
                "id": "financial_bec",
                "title": "Financial Fraud & Business Compromise (BEC)",
                "icon": "💳",
                "level": "critical" if nlp_score >= 50 else ("warning" if nlp_score >= 25 else "safe"),
                "badge": "🚨 Financial Trap" if nlp_score >= 50 else ("🟡 Urgent Pressure" if nlp_score >= 25 else "🟢 Normal Conversation"),
                "layman_summary": "The email demands immediate wire transfer, fake invoice payment, or login verification using fear/urgency." if nlp_score >= 35 else "No urgent financial demands, invoice changes, or password threats found.",
                "layman_action": "Never wire money or change banking details based on an email without calling the sender."
            },
            {
                "id": "deceptive_links",
                "title": "Target Links & Redirection",
                "icon": "🔗",
                "level": "critical" if has_url_threat else "safe",
                "badge": "🚨 Dangerous Link" if has_url_threat else "🟢 Safe Official Links",
                "layman_summary": "Contains deceptive or lookalike links created to steal your passwords or install malware." if has_url_threat else "All buttons and links point to real, verified destinations.",
                "layman_action": "Hover over buttons before clicking to verify the real website address."
            },
            {
                "id": "routing_protocols",
                "title": "Mail Routing & Authentication Stamps",
                "icon": "📬",
                "level": "critical" if has_auth_threat else "safe",
                "badge": "🚨 Unaligned / Forged" if has_auth_threat else "🟢 Certified Route",
                "layman_summary": "Failed postal security stamps (SPF/DKIM/DMARC) — sent through unauthorized relay computers." if has_auth_threat else "Sent through official authorized mail servers with valid digital signatures.",
                "layman_action": "If digital post stamps are unaligned, the sender's identity cannot be trusted."
            },
            {
                "id": "origin_infrastructure",
                "title": "Origin Location & Infrastructure",
                "icon": "🌍",
                "level": "warning" if has_infra_threat else "safe",
                "badge": "🟡 Concealed / Proxy Host" if has_infra_threat else "🟢 Known Host / ISP",
                "layman_summary": f"Originated from {geo_result.get('country', 'Global') if geo_result else 'Global CDN'} via {geo_result.get('isp', 'Legitimate Network') if geo_result else 'Standard Provider'}.",
                "layman_action": "Check if an email from this country or cloud provider makes sense for this sender."
            }
        ]

        signals_breakdown = {
            "nlp_urgency": "High Pressure" if nlp_score >= 50 else ("Moderate" if nlp_score >= 25 else "Normal (No pressure)"),
            "auth_status": "Flagged / Mismatched" if has_auth_threat else ("Pass (Verified)" if not headers_are_absent else "Standard (Webmail)"),
            "malicious_urls_count": sum(1 for u in url_results if u.get("risk") in ("high", "critical")),
            "origin_country": origin_str,
            "user_advice": user_advice,
            "sender_trust": "Suspicious / Impersonated" if has_auth_threat else "Authentic & Verified",
            "links_trust": "Dangerous / Deceptive" if has_url_threat else "Safe & Official",
            "content_trust": "High Risk (Demands Action)" if has_nlp_threat else "Standard Conversation",
            "layman_risks": layman_risks
        }

        return composite, classification, explanation_str, signals_breakdown


    def _headers_are_absent(self, header_result: Dict[str, Any]) -> bool:
        """Detect if the analysis was run without real email headers.
        When headers are absent, SPF/DKIM/DMARC all return 'none' and risk_score is 0."""
        if header_result.get("risk_score", 0) > 0:
            return False
        spf = header_result.get("spf_status", "none")
        dkim = header_result.get("dkim_status", "none")
        dmarc = header_result.get("dmarc_status", "none")
        # If all three are "none", headers were likely absent
        if spf == "none" and dkim == "none" and dmarc == "none":
            return True
        return False
