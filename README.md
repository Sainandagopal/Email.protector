# SIH-Guard: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

**Problem Statement:** SIH26106 (AICTE / Blockchain & Cybersecurity)  
**Solution:** Chrome/Edge Browser Extension (Manifest V3) + FastAPI AI Threat Engine + React Forensic SOC Dashboard

---

## Architecture Overview

```
Active Gmail Message / .EML
           │
           ▼
 Chrome Extension (Manifest V3)
  - Content Script (Inline Gmail Banner & Scraper)
  - Popup UI (Gauge Score, Presets, Direct EML)
           │
           ▼ (HTTP/REST API)
 FastAPI Cyber-Forensic Backend
  ├── Email Parser (RFC-822 / MIME / Body Hash)
  ├── Header Analyzer (SPF, DKIM, DMARC, Routing Hops)
  ├── URL Analyzer (IP hosts, Punycode, TLDs, Deceptive Links)
  ├── IOC Extractor (IPv4, Domains, Hashes, Emails)
  ├── GeoLocation Engine (Public IP Infrastructure, ASN, ISP)
  ├── AI Threat Engine (TF-IDF + Heuristic Composite Scoring)
  └── Forensic Report Generator (HTML / PDF + SHA-256 Custody Hash)
           │
           ▼
 Web Forensic Dashboard (React + Vite)
  ├── SOC Overview (KPIs, Risk Distribution, Recent Dossiers)
  ├── Investigation Dossier (Header Pills, AI Reasoning, IOC Explorer)
  ├── Interactive GeoLocation Map (Leaflet Hop Tracer & Disclaimer)
  ├── Attack Timeline & Visual Attack Graph (Sender -> IP -> Domain -> URL)
  └── Forensic Report Export (Printable PDF & Digital Integrity Hash)
```

---

## Quick Start Guide

### 1. Start the FastAPI Backend
Open a terminal in the project root:
```bash
# Using run_backend.bat or via python
run_backend.bat
# or:
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Base: `http://localhost:8000`
- Interactive Swagger Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/v1/health`

### 2. Start the Web Forensic Dashboard
In a second terminal:
```bash
# Using run_dashboard.bat or via npm
run_dashboard.bat
# or:
cd dashboard
npm.cmd run dev
```
- Dashboard URL: `http://localhost:5173`

### 3. Load the Browser Extension (Chrome / Edge)
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `extension/` folder located at `C:\Users\vaitl\Desktop\SIH\extension`.
5. The **SIH-Guard Forensics** shield icon will appear in your browser extension toolbar!

---

## Testing & Demonstration Workflow

### Method A: Direct In-Extension Demonstration (No Gmail Login Required)
1. Click the **SIH-Guard** extension icon in your browser toolbar.
2. Click the **Demo Presets** tab.
3. Click any test scenario:
   - **PayPal Urgent Phishing** (Triggers SPF failure, IP hostname link, bulletproof host, Score: ~88/100)
   - **Microsoft 365 BEC Spoof** (Triggers punycode domain & urgency prompt, Score: ~75/100)
   - **Legitimate Invoice (Benign)** (Valid SPF/DKIM/DMARC authentic cloud mail, Score: ~12/100)
4. View the instant Threat Gauge, verdict badge, and AI summary.
5. Click **"Launch Forensic Dashboard ↗"** to jump into the full investigation dossier with Leaflet geolocation, visual attack graph, and PDF report.

### Method B: Manual .EML File Upload
1. Open the Dashboard at `http://localhost:5173`.
2. Click **Analyze Email** in the sidebar.
3. Drag & drop any of the pre-built sample emails from the `samples/` directory:
   - `samples/phishing_paypal_urgent.eml`
   - `samples/phishing_m365_credential.eml`
   - `samples/bec_wire_fraud.eml`
   - `samples/benign_invoice.eml`
4. Click **Analyze Threat Payload** to run live analysis.

### Method C: Live Gmail Mailbox Analysis
1. Open Gmail (`mail.google.com`) in your browser.
2. Open any email message.
3. You will see a blue button injected into the email header: **"🛡️ Analyze with SIH-Guard"**.
4. Click the button; SIH-Guard will inspect the visible email data, communicate with your local backend, and render the threat verdict directly inside your Gmail view.

---

## SIH26106 Acceptance Criteria Checklist
- [x] Analyze pasted or `.eml` email
- [x] Extension triggers analysis from Gmail in controlled environment
- [x] Explainable 0–100 threat score and classification
- [x] Full IOC extraction (IPs, URLs, domains, hashes, emails)
- [x] Public IP infrastructure geolocation with explicit limitation disclaimer
- [x] Forensic investigation dashboard with map, timeline, and attack graph
- [x] Downloadable forensic report with cryptographic chain of custody
- [x] Documented setup with no hard-coded secrets
