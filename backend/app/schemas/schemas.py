import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class LinkItem(BaseModel):
    url: str
    text: Optional[str] = ""

class EmailAnalysisRequest(BaseModel):
    subject: Optional[str] = "Untitled Email"
    sender: Optional[str] = "Unknown"
    sender_email: Optional[str] = None
    date: Optional[str] = None
    body: Optional[str] = ""
    body_html: Optional[str] = ""
    headers: Optional[Dict[str, str]] = {}
    links: Optional[List[LinkItem]] = []
    raw_eml: Optional[str] = None

class IocItem(BaseModel):
    id: Optional[int] = None
    type: str
    value: str
    risk: str = "low"
    source: str = "email_body"

class UrlItem(BaseModel):
    id: Optional[int] = None
    url: str
    domain: str
    risk: str = "low"
    risk_score: Optional[float] = 0.0
    is_blocked: Optional[bool] = False
    reasons: Optional[str] = ""


class GeoItem(BaseModel):
    id: Optional[int] = None
    ip: str
    country: str
    region: str
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    source: str = "header_received"

class TimelineItem(BaseModel):
    id: Optional[int] = None
    event_time: datetime.datetime
    event_type: str
    description: str

class SignalsSummary(BaseModel):
    nlp_urgency: str = "Low"
    auth_status: str = "Pass"
    malicious_urls_count: int = 0
    origin_country: str = "Global"
    user_advice: Optional[str] = "Safe to read. This email appears legitimate."
    sender_trust: Optional[str] = "Authentic & Verified"
    links_trust: Optional[str] = "Safe & Official"
    content_trust: Optional[str] = "Standard Conversation"
    layman_risks: Optional[List[Dict[str, Any]]] = []


class EmailAnalysisResponse(BaseModel):
    id: int
    subject: str
    sender: str
    classification: str
    threat_score: float
    explanation: str
    signals: SignalsSummary
    iocs: List[IocItem] = []
    urls: List[UrlItem] = []
    geo: Optional[GeoItem] = None
    created_at: datetime.datetime

class InvestigationSummary(BaseModel):
    id: int
    subject: str
    sender: str
    classification: str
    threat_score: float
    created_at: datetime.datetime
    status: str

class InvestigationDetail(BaseModel):
    id: int
    subject: str
    sender: str
    classification: str
    threat_score: float
    explanation: str
    status: str
    created_at: datetime.datetime
    body_hash: Optional[str] = None
    headers: List[Dict[str, str]] = []
    iocs: List[IocItem] = []
    urls: List[UrlItem] = []
    geo_results: List[GeoItem] = []
    timeline: List[TimelineItem] = []
