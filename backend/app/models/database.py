import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), default="Forensic Analyst")
    email = Column(String(150), unique=True, index=True)
    password_hash = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now)

class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    subject = Column(String(255), default="Untitled Investigation")
    sender = Column(String(255), default="Unknown")
    classification = Column(String(50), default="SUSPICIOUS") # SAFE, SUSPICIOUS, PHISHING, MALICIOUS
    threat_score = Column(Float, default=0.0)
    explanation = Column(Text, default="")
    status = Column(String(50), default="COMPLETED")
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    email_records = relationship("EmailRecord", back_populates="investigation", cascade="all, delete-orphan")
    headers = relationship("HeaderRecord", back_populates="investigation", cascade="all, delete-orphan")
    iocs = relationship("IocRecord", back_populates="investigation", cascade="all, delete-orphan")
    urls = relationship("UrlAnalysisRecord", back_populates="investigation", cascade="all, delete-orphan")
    geo_results = relationship("GeoResultRecord", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEventRecord", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("ReportRecord", back_populates="investigation", cascade="all, delete-orphan")

class EmailRecord(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    sender = Column(String(255))
    recipients = Column(Text)
    subject = Column(String(255))
    body_hash = Column(String(64))
    raw_storage_reference = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="email_records")

class HeaderRecord(Base):
    __tablename__ = "headers"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    header_name = Column(String(100))
    header_value = Column(Text)

    investigation = relationship("Investigation", back_populates="headers")

class IocRecord(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    type = Column(String(50)) # ip, domain, url, email, hash
    value = Column(Text)
    risk = Column(String(50), default="low") # low, medium, high, critical
    source = Column(String(100), default="email_body")

    investigation = relationship("Investigation", back_populates="iocs")

class UrlAnalysisRecord(Base):
    __tablename__ = "url_analysis"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    url = Column(Text)
    domain = Column(String(255))
    risk = Column(String(50), default="low")
    reasons = Column(Text)

    investigation = relationship("Investigation", back_populates="urls")

class GeoResultRecord(Base):
    __tablename__ = "geo_results"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    ip = Column(String(45))
    country = Column(String(100))
    region = Column(String(100))
    city = Column(String(100), nullable=True)
    asn = Column(String(100), nullable=True)
    isp = Column(String(150), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    source = Column(String(100), default="header_received")

    investigation = relationship("Investigation", back_populates="geo_results")

class TimelineEventRecord(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    event_time = Column(DateTime, default=utc_now)
    event_type = Column(String(100)) # mail_sent, relay_hop, mail_received, analysis_started, verdict_rendered
    description = Column(Text)

    investigation = relationship("Investigation", back_populates="timeline_events")

class ReportRecord(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    file_reference = Column(String(255))
    report_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)

    investigation = relationship("Investigation", back_populates="reports")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
