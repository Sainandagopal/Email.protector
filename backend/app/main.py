import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.models.database import init_db, SessionLocal, Investigation, EmailRecord, HeaderRecord, IocRecord, UrlAnalysisRecord, GeoResultRecord, TimelineEventRecord
from app.api.endpoints import router as api_router

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_initial_demo_data()
    yield

# Also ensure DB tables exist immediately
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform (SIH26106)",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Mount React SOC Dashboard directly from FastAPI
# Allows accessing the web dashboard directly at http://localhost:8000
import os
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

DASHBOARD_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "dashboard", "dist")
if os.path.exists(DASHBOARD_DIST):
    assets_dir = os.path.join(DASHBOARD_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        index_file = os.path.join(DASHBOARD_DIST, "index.html")
        return FileResponse(index_file)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def catch_all(full_path: str):
        file_path = os.path.join(DASHBOARD_DIST, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        index_file = os.path.join(DASHBOARD_DIST, "index.html")
        return FileResponse(index_file)

def seed_initial_demo_data():
    """Seeds baseline investigations if database is fresh."""
    db = SessionLocal()
    try:
        if db.query(Investigation).count() == 0:
            print("[SIH-Guard] Seeding initial forensic demo data...")
            now = datetime.datetime.now(datetime.timezone.utc)

            # Case 1: PayPal Phishing
            inv1 = Investigation(
                subject="URGENT: Suspicious activity on your PayPal account - Action Required",
                sender="PayPal Security Team <security-alert@paypa1-update-security.com>",
                classification="PHISHING",
                threat_score=88.5,
                explanation="Phishing risk (Score 88.5/100) because Language exhibits coercive urgency patterns ('urgent', 'suspended', 'verify'); SPF validation failed (unauthorized sender IP); Link threat: URL uses raw IP address instead of domain name; Origin infrastructure flagged as bulletproof/anonymizing host (Tor Exit & Bulletproof Infrastructure).",
                status="COMPLETED",
                created_at=now - datetime.timedelta(hours=2)
            )
            db.add(inv1)
            db.flush()

            db.add(EmailRecord(
                investigation_id=inv1.id,
                sender=inv1.sender,
                recipients="user@enterprise.org",
                subject=inv1.subject,
                body_hash="4a5e3b61f8a7e4b9d0c2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
            ))
            db.add(IocRecord(investigation_id=inv1.id, type="ip", value="185.220.101.5", risk="critical", source="mail_relay_header"))
            db.add(IocRecord(investigation_id=inv1.id, type="domain", value="paypa1-update-security.com", risk="high", source="sender_spoof"))
            db.add(IocRecord(investigation_id=inv1.id, type="url", value="http://185.220.101.5/login?ref=paypal_verify", risk="critical", source="hyperlink"))
            db.add(UrlAnalysisRecord(
                investigation_id=inv1.id,
                url="http://185.220.101.5/login?ref=paypal_verify",
                domain="185.220.101.5",
                risk="critical",
                reasons="URL uses raw IP address instead of domain name"
            ))
            db.add(GeoResultRecord(
                investigation_id=inv1.id,
                ip="185.220.101.5",
                country="Russia",
                region="Moscow",
                city="Moscow",
                asn="AS200052 (Zwiebelfreunde / Bulletproof Relay)",
                isp="Tor Exit & Bulletproof Infrastructure",
                latitude=55.7558,
                longitude=37.6173
            ))
            db.add(TimelineEventRecord(
                investigation_id=inv1.id,
                event_time=now - datetime.timedelta(hours=2, minutes=5),
                event_type="MAIL_DISPATCH",
                description="Message sent from unauthorized relay 185.220.101.5"
            ))
            db.add(TimelineEventRecord(
                investigation_id=inv1.id,
                event_time=now - datetime.timedelta(hours=2),
                event_type="VERDICT_RENDERED",
                description="Threat score 88.5/100 rendered. Tagged as High-Risk Phishing."
            ))

            # Case 2: Benign Invoice
            inv2 = Investigation(
                subject="Your Monthly Cloud Infrastructure Invoice #INV-2026-09",
                sender="Billing Department <billing@enterprise-cloud-services.com>",
                classification="SAFE",
                threat_score=12.0,
                explanation="No prominent security threats identified. Authentic mail signatures and low language risk.",
                status="COMPLETED",
                created_at=now - datetime.timedelta(hours=5)
            )
            db.add(inv2)
            db.flush()

            db.add(EmailRecord(
                investigation_id=inv2.id,
                sender=inv2.sender,
                recipients="user@enterprise.org",
                subject=inv2.subject,
                body_hash="9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c"
            ))
            db.add(IocRecord(investigation_id=inv2.id, type="ip", value="142.250.190.46", risk="low", source="google_relay"))
            db.add(IocRecord(investigation_id=inv2.id, type="domain", value="enterprise-cloud-services.com", risk="low", source="sender_domain"))
            db.add(UrlAnalysisRecord(
                investigation_id=inv2.id,
                url="https://enterprise-cloud-services.com/dashboard/invoices",
                domain="enterprise-cloud-services.com",
                risk="low",
                reasons="No obvious malicious indicators in link structure."
            ))
            db.add(GeoResultRecord(
                investigation_id=inv2.id,
                ip="142.250.190.46",
                country="United States",
                region="California",
                city="Mountain View",
                asn="AS15169 (Google LLC)",
                isp="Google Mail Exchange Relay",
                latitude=37.4220,
                longitude=-122.0841
            ))

            db.commit()
            print("[SIH-Guard] Seed completed.")
    except Exception as e:
        db.rollback()
        print(f"[SIH-Guard] Seed warning: {e}")
    finally:
        db.close()
