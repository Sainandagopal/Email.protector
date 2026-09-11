import datetime
import hashlib
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.models.database import (
    get_db, Investigation, EmailRecord, HeaderRecord,
    IocRecord, UrlAnalysisRecord, GeoResultRecord,
    TimelineEventRecord, ReportRecord
)
from app.schemas.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse,
    InvestigationSummary, InvestigationDetail,
    IocItem, UrlItem, GeoItem, TimelineItem, SignalsSummary
)
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.ioc_extractor import IocExtractor
from app.analyzers.geo_engine import GeoEngine
from app.ml.threat_classifier import ThreatClassifier
from app.services.email_parser import EmailParserService
from app.reports.report_generator import ForensicReportGenerator

router = APIRouter()

# Initialize singletons
header_analyzer = HeaderAnalyzer()
url_analyzer = UrlAnalyzer()
ioc_extractor = IocExtractor()
geo_engine = GeoEngine()
threat_classifier = ThreatClassifier()
email_parser = EmailParserService()
report_generator = ForensicReportGenerator()

@router.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "SIH26106 Cyber-Forensic API",
        "version": "1.0.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@router.post("/analyze/email")
def analyze_email(payload: EmailAnalysisRequest, db: Session = Depends(get_db)):
    # 1. Parse from raw_eml if provided
    parsed_data = {}
    if payload.raw_eml:
        parsed_data = email_parser.parse_eml_text(payload.raw_eml)

    subject = parsed_data.get("subject") or payload.subject or "Untitled Email"
    sender = parsed_data.get("sender") or payload.sender or "Unknown"
    body = parsed_data.get("body") or payload.body or ""
    headers = {**parsed_data.get("headers", {}), **payload.headers}
    links = parsed_data.get("links") or [l.model_dump() for l in payload.links] or []
    body_hash = parsed_data.get("body_hash") or hashlib.sha256(body.encode('utf-8')).hexdigest()

    # 2. Run Analyzers
    header_res = header_analyzer.analyze(headers, sender)
    
    # Fallback: extract URLs from body text if no links were provided
    if not links and body:
        import re as re_mod
        extracted_urls = re_mod.findall(r'https?://[^\s<>"\'\\)]+', body)
        seen_urls = set()
        for u in extracted_urls:
            u_clean = u.rstrip('.,;')
            if u_clean not in seen_urls:
                seen_urls.add(u_clean)
                links.append({"url": u_clean, "text": u_clean})
        # Also extract bare domain references (e.g., "aniwaves.ru" mentioned without http)
        bare_domains = re_mod.findall(
            r'\b([a-zA-Z0-9-]+\.(?:ru|su|top|xyz|click|cc|buzz|tk|cn|cfd|gq|ml|cam|icu|site|online|live|rest|work|stream|info|me|tv|fit))\b',
            body, re_mod.IGNORECASE
        )
        for d in bare_domains:
            synthetic_url = f"https://{d}"
            if synthetic_url not in seen_urls:
                seen_urls.add(synthetic_url)
                links.append({"url": synthetic_url, "text": d})

    url_res = url_analyzer.analyze_urls(links)
    raw_iocs = ioc_extractor.extract_all(body, headers, links)

    # 3. GeoIP Lookup for public IPs
    target_ip = None
    target_ip_source = "header_received"
    additional_ips = []

    # Priority 1: Check synthetic or raw originating IP headers
    originating_header_ip = headers.get("X-Originating-IP") or headers.get("X-Sender-IP") or headers.get("X-Client-IP")
    if originating_header_ip and geo_engine._is_valid_public_ip(originating_header_ip.strip()):
        target_ip = originating_header_ip.strip()
        target_ip_source = "header_originating_ip"
        raw_iocs.append({
            "type": "ip",
            "value": target_ip,
            "risk": "medium",
            "source": "header_originating_ip"
        })

    # Priority 2: Check relay hops from Received headers
    if not target_ip:
        for hop in header_res.get("hops", []):
            if hop.get("ip") and geo_engine._is_valid_public_ip(hop["ip"]):
                target_ip = hop["ip"]
                target_ip_source = "header_received_hop"
                break

    # Priority 2.5: Live Gmail API Origin Extraction (using authenticated token.json)
    if not target_ip:
        search_email = payload.sender_email or (sender.split("<")[-1].strip(">").strip() if "<" in sender else sender)
        if search_email and "@" in search_email:
            try:
                from app.analyzers.gmail_relay_fetcher import fetch_gmail_origin_ip
                live_origin_ip = fetch_gmail_origin_ip(search_email, subject)
                if live_origin_ip and geo_engine._is_valid_public_ip(live_origin_ip):
                    target_ip = live_origin_ip
                    target_ip_source = f"gmail_received_hop:{search_email}"
                    raw_iocs.append({
                        "type": "ip",
                        "value": target_ip,
                        "risk": "low",
                        "source": "sender_originating_ip:gmail_api"
                    })
            except Exception as e:
                print(f"[SIH-Guard] Live Gmail origin IP lookup note: {e}")

    # Priority 3: Check extracted public IPs from body/headers IOCs
    if not target_ip:
        for ioc in raw_iocs:
            if ioc["type"] == "ip" and geo_engine._is_valid_public_ip(ioc["value"]):
                target_ip = ioc["value"]
                target_ip_source = "extracted_email_ip"
                break

    # Priority 4: SENDER MAIL SERVER INFRASTRUCTURE RESOLUTION
    # When headers lack raw hops (e.g. webmail DOM), resolve the sender domain's mail host
    sender_domain = ""
    if headers.get("X-Sender-Domain"):
        sender_domain = headers["X-Sender-Domain"].strip().lower()
    elif headers.get("X-Mailed-By"):
        sender_domain = headers["X-Mailed-By"].strip().lower()
    elif payload.sender_email and "@" in payload.sender_email:
        sender_domain = payload.sender_email.split("@")[-1].strip(">").strip().lower()
    elif sender and "@" in sender:
        sender_domain = sender.split("@")[-1].strip(">").strip().lower()

    if not target_ip and sender_domain and "." in sender_domain:
        import socket
        socket.setdefaulttimeout(0.6)
        try:
            resolved_sender_ip = socket.gethostbyname(sender_domain)
            if geo_engine._is_valid_public_ip(resolved_sender_ip):
                target_ip = resolved_sender_ip
                target_ip_source = f"sender_mail_server:{sender_domain}"
                raw_iocs.append({
                    "type": "ip",
                    "value": target_ip,
                    "risk": "low",
                    "source": f"sender_infrastructure:{sender_domain}"
                })
        except Exception as e:
            print(f"[SIH-Guard] Could not resolve sender domain {sender_domain}: {e}")

    # Priority 5: As last resort, resolve host IP from hyperlinks
    if links:
        import socket
        from urllib.parse import urlparse
        socket.setdefaulttimeout(0.6)

        for l in links[:3]:
            url_val = l.get("url", "")
            try:
                host = urlparse(url_val).hostname
                if host and not geo_engine._is_valid_public_ip(host):
                    resolved_link_ip = socket.gethostbyname(host)
                    if geo_engine._is_valid_public_ip(resolved_link_ip):
                        if not target_ip:
                            target_ip = resolved_link_ip
                            target_ip_source = f"link_host:{host}"
                        else:
                            additional_ips.append((resolved_link_ip, f"link_host:{host}"))
                        raw_iocs.append({
                            "type": "ip",
                            "value": resolved_link_ip,
                            "risk": "high" if any(u.get("risk") in ("critical", "high") for u in url_res) else "low",
                            "source": f"link_host:{host}"
                        })
            except Exception:
                pass

    geo_data = geo_engine.geolocate_ip(target_ip) if target_ip else None
    if geo_data:
        geo_data["source"] = target_ip_source


    # 4. AI NLP & Composite Threat Score
    nlp_res = threat_classifier.analyze_text(f"{subject}\n{body}")
    threat_score, classification, explanation, signals_breakdown = threat_classifier.compute_composite_score(
        nlp_res, header_res, url_res, geo_data, raw_iocs
    )

    # 5. Persist Investigation to DB
    inv = Investigation(
        subject=subject,
        sender=sender,
        classification=classification,
        threat_score=threat_score,
        explanation=explanation,
        status="COMPLETED",
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(inv)
    db.flush()

    # Save Email Record
    email_rec = EmailRecord(
        investigation_id=inv.id,
        sender=sender,
        recipients=parsed_data.get("recipients", ""),
        subject=subject,
        body_hash=body_hash,
        raw_storage_reference=payload.raw_eml[:500] if payload.raw_eml else None
    )
    db.add(email_rec)

    # Save Headers
    for hk, hv in list(headers.items())[:20]: # save top 20 headers
        db.add(HeaderRecord(investigation_id=inv.id, header_name=hk, header_value=str(hv)))

    # Save IOCs
    ioc_items = []
    for item in raw_iocs:
        ioc_rec = IocRecord(
            investigation_id=inv.id,
            type=item["type"],
            value=item["value"],
            risk=item["risk"],
            source=item["source"]
        )
        db.add(ioc_rec)
        ioc_items.append(IocItem(type=item["type"], value=item["value"], risk=item["risk"], source=item["source"]))

    # Save URL Analysis
    url_items = []
    for u in url_res:
        u_rec = UrlAnalysisRecord(
            investigation_id=inv.id,
            url=u["url"],
            domain=u["domain"],
            risk=u["risk"],
            reasons=u["reasons"]
        )
        score_val = float(u.get("risk_score", 0.0))
        blocked = score_val >= 70.0 or u.get("risk") in ("critical", "high")
        url_items.append(UrlItem(
            url=u["url"],
            domain=u["domain"],
            risk=u["risk"],
            risk_score=score_val,
            is_blocked=blocked,
            reasons=u["reasons"]
        ))


    # Save Geo Result
    geo_item = None
    if geo_data:
        g_rec = GeoResultRecord(
            investigation_id=inv.id,
            ip=geo_data["ip"],
            country=geo_data["country"],
            region=geo_data["region"],
            city=geo_data.get("city"),
            asn=geo_data.get("asn"),
            isp=geo_data.get("isp"),
            latitude=geo_data.get("latitude"),
            longitude=geo_data.get("longitude"),
            source=geo_data.get("source", "header_received")
        )
        db.add(g_rec)
        geo_item = GeoItem(
            ip=geo_data["ip"],
            country=geo_data["country"],
            region=geo_data["region"],
            city=geo_data.get("city"),
            asn=geo_data.get("asn"),
            isp=geo_data.get("isp"),
            latitude=geo_data.get("latitude"),
            longitude=geo_data.get("longitude"),
            source=geo_data.get("source", "header_received")
        )

    # Also persist additional mapped IPs (e.g. hops or link hosts) for Google Maps
    seen_geo_ips = {geo_data["ip"]} if geo_data else set()
    for add_ip, add_source in additional_ips:
        if add_ip not in seen_geo_ips:
            seen_geo_ips.add(add_ip)
            add_geo = geo_engine.geolocate_ip(add_ip)
            if add_geo and add_geo.get("latitude"):
                db.add(GeoResultRecord(
                    investigation_id=inv.id,
                    ip=add_geo["ip"],
                    country=add_geo["country"],
                    region=add_geo["region"],
                    city=add_geo.get("city"),
                    asn=add_geo.get("asn"),
                    isp=add_geo.get("isp"),
                    latitude=add_geo.get("latitude"),
                    longitude=add_geo.get("longitude"),
                    source=add_source
                ))


    # Save Timeline Events
    now = datetime.datetime.now(datetime.timezone.utc)
    events = [
        TimelineEventRecord(
            investigation_id=inv.id,
            event_time=now - datetime.timedelta(seconds=12),
            event_type="MESSAGE_INGESTION",
            description=f"Received message payload from {sender}."
        ),
        TimelineEventRecord(
            investigation_id=inv.id,
            event_time=now - datetime.timedelta(seconds=8),
            event_type="HEADER_AUTHENTICATION",
            description=f"SPF: {header_res['spf_status']}, DKIM: {header_res['dkim_status']}, DMARC: {header_res['dmarc_status']}."
        ),
        TimelineEventRecord(
            investigation_id=inv.id,
            event_time=now - datetime.timedelta(seconds=5),
            event_type="IOC_EXTRACTION",
            description=f"Extracted {len(raw_iocs)} indicators of compromise and {len(url_res)} hyperlinks."
        ),
        TimelineEventRecord(
            investigation_id=inv.id,
            event_time=now - datetime.timedelta(seconds=2),
            event_type="INFRASTRUCTURE_GEOLOCATION",
            description=f"Resolved routing hop to {geo_data['country'] if geo_data else 'Global CDN'}."
        ),
        TimelineEventRecord(
            investigation_id=inv.id,
            event_time=now,
            event_type="VERDICT_RENDERED",
            description=f"Assigned threat score of {threat_score}/100 ({classification})."
        )
    ]
    for ev in events:
        db.add(ev)

    db.commit()
    db.refresh(inv)

    return EmailAnalysisResponse(
        id=inv.id,
        subject=inv.subject,
        sender=inv.sender,
        classification=inv.classification,
        threat_score=inv.threat_score,
        explanation=inv.explanation,
        signals=SignalsSummary(**signals_breakdown),
        iocs=ioc_items,
        urls=url_items,
        geo=geo_item,
        created_at=inv.created_at
    )

@router.get("/investigations", response_model=List[InvestigationSummary])
def list_investigations(limit: int = 50, db: Session = Depends(get_db)):
    items = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(limit).all()
    return items

@router.get("/investigations/{inv_id}", response_model=InvestigationDetail)
def get_investigation_detail(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    email_rec = db.query(EmailRecord).filter(EmailRecord.investigation_id == inv_id).first()
    headers = db.query(HeaderRecord).filter(HeaderRecord.investigation_id == inv_id).all()
    iocs = db.query(IocRecord).filter(IocRecord.investigation_id == inv_id).all()
    urls = db.query(UrlAnalysisRecord).filter(UrlAnalysisRecord.investigation_id == inv_id).all()
    geos = db.query(GeoResultRecord).filter(GeoResultRecord.investigation_id == inv_id).all()
    timeline = db.query(TimelineEventRecord).filter(TimelineEventRecord.investigation_id == inv_id).order_by(TimelineEventRecord.event_time.asc()).all()

    return InvestigationDetail(
        id=inv.id,
        subject=inv.subject,
        sender=inv.sender,
        classification=inv.classification,
        threat_score=inv.threat_score,
        explanation=inv.explanation,
        status=inv.status,
        created_at=inv.created_at,
        body_hash=email_rec.body_hash if email_rec else "N/A",
        headers=[{"name": h.header_name, "value": h.header_value} for h in headers],
        iocs=[IocItem(
            id=i.id,
            type=i.type,
            value=i.value,
            risk=i.risk,
            source=i.source
        ) for i in iocs],
        urls=[UrlItem(
            id=u.id,
            url=u.url,
            domain=u.domain,
            risk=u.risk,
            risk_score=85.0 if u.risk in ("critical", "high") else (35.0 if u.risk == "medium" else 5.0),
            is_blocked=(u.risk in ("critical", "high")),
            reasons=u.reasons
        ) for u in urls],
        geo_results=sorted([GeoItem(
            id=g.id, ip=g.ip, country=g.country, region=g.region, city=g.city,
            asn=g.asn, isp=g.isp, latitude=g.latitude, longitude=g.longitude, source=g.source
        ) for g in geos], key=lambda x: 0 if any(k in (x.source or "").lower() for k in ("sender", "header", "received", "gmail", "hop")) else 1),
        timeline=[TimelineItem(
            id=t.id, event_time=t.event_time, event_type=t.event_type, description=t.description
        ) for t in timeline]
    )

@router.get("/investigations/{inv_id}/iocs", response_model=List[IocItem])
def get_investigation_iocs(inv_id: int, db: Session = Depends(get_db)):
    items = db.query(IocRecord).filter(IocRecord.investigation_id == inv_id).all()
    return [IocItem(id=i.id, type=i.type, value=i.value, risk=i.risk, source=i.source) for i in items]

@router.get("/investigations/{inv_id}/timeline", response_model=List[TimelineItem])
def get_investigation_timeline(inv_id: int, db: Session = Depends(get_db)):
    items = db.query(TimelineEventRecord).filter(TimelineEventRecord.investigation_id == inv_id).order_by(TimelineEventRecord.event_time.asc()).all()
    return [TimelineItem(id=t.id, event_time=t.event_time, event_type=t.event_type, description=t.description) for t in items]

@router.get("/investigations/{inv_id}/geo", response_model=List[GeoItem])
def get_investigation_geo(inv_id: int, db: Session = Depends(get_db)):
    items = db.query(GeoResultRecord).filter(GeoResultRecord.investigation_id == inv_id).all()
    return [GeoItem(
        id=g.id, ip=g.ip, country=g.country, region=g.region, city=g.city,
        asn=g.asn, isp=g.isp, latitude=g.latitude, longitude=g.longitude, source=g.source
    ) for g in items]

@router.get("/investigations/{inv_id}/graph")
def get_investigation_graph(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    urls = db.query(UrlAnalysisRecord).filter(UrlAnalysisRecord.investigation_id == inv_id).all()
    geos = db.query(GeoResultRecord).filter(GeoResultRecord.investigation_id == inv_id).all()
    iocs = db.query(IocRecord).filter(IocRecord.investigation_id == inv_id).all()
    email_rec = db.query(EmailRecord).filter(EmailRecord.investigation_id == inv_id).first()

    nodes = []
    edges = []
    seen_nodes = set()

    # 1. Origin Sender Node
    sender_raw = inv.sender or "Unknown Sender"
    sender_label = sender_raw
    sender_email = ""
    if "<" in sender_raw and ">" in sender_raw:
        sender_label = sender_raw.split("<")[0].strip().strip('"') or sender_raw
        sender_email = sender_raw.split("<")[1].split(">")[0].strip()
    elif "@" in sender_raw:
        sender_email = sender_raw.strip()
        sender_label = sender_email.split("@")[0].capitalize()

    sender_node_id = f"sender_{inv.id}"
    nodes.append({
        "id": sender_node_id,
        "label": sender_label[:26] if sender_label else "Origin Sender",
        "sub": (sender_email[:26] + "...") if len(sender_email) > 26 else (sender_email or "Sender Identity"),
        "type": "sender",
        "risk": inv.classification.lower()
    })
    seen_nodes.add(sender_node_id)

    # 2. Origin Mail Infrastructure / Relay IP Nodes
    ip_nodes_added = []
    for g in geos:
        ip_node_id = f"ip_{g.id}"
        if ip_node_id not in seen_nodes:
            seen_nodes.add(ip_node_id)
            loc = f"{g.city}, {g.country}" if g.city and g.city != 'Unknown' else (g.country or "Public Host")
            nodes.append({
                "id": ip_node_id,
                "label": f"IP: {g.ip}",
                "sub": loc[:22],
                "type": "ip",
                "risk": "critical" if inv.threat_score >= 50 else ("suspicious" if inv.threat_score >= 25 else "safe")
            })
            edges.append({
                "source": sender_node_id,
                "target": ip_node_id,
                "label": "originated_from"
            })
            ip_nodes_added.append(ip_node_id)

    # Check IOCs for IPs not already in geos
    for i in iocs:
        if i.type == "ip":
            ip_val = i.value.strip()
            ip_node_id = f"ioc_ip_{ip_val}"
            if ip_node_id not in seen_nodes and not any(g.ip == ip_val for g in geos):
                seen_nodes.add(ip_node_id)
                nodes.append({
                    "id": ip_node_id,
                    "label": f"IP: {ip_val}",
                    "sub": "Observed Relay IP",
                    "type": "ip",
                    "risk": i.risk or "safe"
                })
                edges.append({
                    "source": sender_node_id,
                    "target": ip_node_id,
                    "label": "relayed_through"
                })
                ip_nodes_added.append(ip_node_id)

    # Fallback: if no IP exists, add the mail domain as an infrastructure node
    if not ip_nodes_added:
        domain_name = ""
        if "@" in sender_email:
            domain_name = sender_email.split("@")[-1].strip()
        elif "@" in sender_raw:
            domain_name = sender_raw.split("@")[-1].split(">")[0].strip()
        
        if domain_name:
            infra_node_id = f"domain_{domain_name}"
            if infra_node_id not in seen_nodes:
                seen_nodes.add(infra_node_id)
                nodes.append({
                    "id": infra_node_id,
                    "label": domain_name[:24],
                    "sub": "Sender Mail Host",
                    "type": "ip",
                    "risk": "safe" if inv.threat_score < 30 else "suspicious"
                })
                edges.append({
                    "source": sender_node_id,
                    "target": infra_node_id,
                    "label": "hosted_on"
                })
                ip_nodes_added.append(infra_node_id)

    target_parent_id = ip_nodes_added[0] if ip_nodes_added else sender_node_id

    # 3. URL & Domain Target Nodes (from UrlAnalysisRecord AND IocRecord)
    link_nodes_added = []
    seen_urls = set()

    for u in urls:
        if u.url in seen_urls:
            continue
        seen_urls.add(u.url)
        url_node_id = f"url_{u.id}"
        if url_node_id not in seen_nodes:
            seen_nodes.add(url_node_id)
            d_label = u.domain or "Target Link"
            nodes.append({
                "id": url_node_id,
                "label": d_label[:24],
                "sub": (u.url[:28] + "...") if len(u.url) > 28 else u.url,
                "type": "url",
                "risk": u.risk or "safe"
            })
            edges.append({
                "source": target_parent_id,
                "target": url_node_id,
                "label": "embedded_link"
            })
            link_nodes_added.append(url_node_id)

    # Also extract URLs / domains from IOCs
    for i in iocs:
        if i.type in ("url", "domain"):
            val = i.value.strip()
            if val in seen_urls:
                continue
            seen_urls.add(val)
            ioc_link_id = f"ioc_link_{len(seen_nodes)}"
            seen_nodes.add(ioc_link_id)
            from urllib.parse import urlparse
            d_name = urlparse(val).hostname or val if "http" in val else val
            nodes.append({
                "id": ioc_link_id,
                "label": d_name[:24],
                "sub": (val[:28] + "...") if len(val) > 28 else val,
                "type": "url",
                "risk": i.risk or ("critical" if inv.threat_score >= 50 else "safe")
            })
            edges.append({
                "source": target_parent_id,
                "target": ioc_link_id,
                "label": "embedded_link" if i.type == "url" else "associated_domain"
            })
            link_nodes_added.append(ioc_link_id)

    # 4. Target Recipient / Victim Mailbox Node
    recipient_label = "Recipient Mailbox"
    if email_rec and email_rec.recipients:
        rec_clean = email_rec.recipients.split(",")[0].split("<")[-1].strip(">").strip()
        if rec_clean:
            recipient_label = rec_clean

    recipient_node_id = f"recipient_{inv.id}"
    nodes.append({
        "id": recipient_node_id,
        "label": recipient_label[:24],
        "sub": "Destination Inbox",
        "type": "recipient",
        "risk": "safe"
    })

    if link_nodes_added:
        for ln in link_nodes_added[:2]:
            edges.append({
                "source": ln,
                "target": recipient_node_id,
                "label": "delivered_to"
            })
    else:
        edges.append({
            "source": target_parent_id,
            "target": recipient_node_id,
            "label": "inbox_delivery"
        })

    for idx, node in enumerate(nodes):
        if "x" not in node:
            node["x"] = 120 + (idx % 3) * 220
        if "y" not in node:
            node["y"] = 100 + (idx // 3) * 160

    return {"nodes": nodes, "edges": edges}

@router.get("/reports/{inv_id}/html", response_class=HTMLResponse)
def get_report_html(inv_id: int, db: Session = Depends(get_db)):
    detail = get_investigation_detail(inv_id, db)
    html_content = report_generator.generate_html_report(detail.model_dump())
    return HTMLResponse(content=html_content)

@router.post("/reports/{inv_id}")
def generate_report(inv_id: int, db: Session = Depends(get_db)):
    detail = get_investigation_detail(inv_id, db)
    html_content = report_generator.generate_html_report(detail.model_dump())
    
    # Store reference
    rep = ReportRecord(
        investigation_id=inv_id,
        file_reference=f"/api/v1/reports/{inv_id}/html",
        report_hash=hashlib.sha256(html_content.encode('utf-8')).hexdigest()
    )
    db.add(rep)
    db.commit()

    return {
        "success": True,
        "report_id": rep.id,
        "report_url": f"/api/v1/reports/{inv_id}/html",
        "report_hash": rep.report_hash
    }
