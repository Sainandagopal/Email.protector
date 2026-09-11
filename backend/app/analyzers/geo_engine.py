import re
import requests
from typing import Optional, Dict, Any
from app.core.config import settings

OFFLINE_GEO_DATABASE = {
    "185.220.101.5": {
        "country": "Russia",
        "region": "Moscow",
        "city": "Moscow",
        "asn": "AS200052 (Zwiebelfreunde / Bulletproof Relay)",
        "isp": "Tor Exit & Bulletproof Infrastructure",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "is_suspicious_infra": True
    },
    "91.240.118.42": {
        "country": "Netherlands",
        "region": "North Holland",
        "city": "Amsterdam",
        "asn": "AS49453 (Global Host Solutions BV)",
        "isp": "Offshore VPS Provider",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "is_suspicious_infra": True
    },
    "142.250.190.46": {
        "country": "United States",
        "region": "California",
        "city": "Mountain View",
        "asn": "AS15169 (Google LLC)",
        "isp": "Google Mail Exchange Relay",
        "latitude": 37.4220,
        "longitude": -122.0841,
        "is_suspicious_infra": False
    },
    "13.107.6.152": {
        "country": "United States",
        "region": "Washington",
        "city": "Redmond",
        "asn": "AS8075 (Microsoft Corporation)",
        "isp": "Microsoft Office 365 Exchange",
        "latitude": 47.6740,
        "longitude": -122.1215,
        "is_suspicious_infra": False
    },
    "198.51.100.24": {
        "country": "Germany",
        "region": "Hesse",
        "city": "Frankfurt",
        "asn": "AS24940 (Hetzner Online GmbH)",
        "isp": "Hetzner Cloud Hosting",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "is_suspicious_infra": False
    }
}

class GeoEngine:
    """Resolves IP infrastructure geolocation with offline fallbacks and explicit accuracy disclaimers."""

    DISCLAIMER = (
        "APPROXIMATE INFRASTRUCTURE GEOLOCATION NOTICE: Coordinates reflect the registered network routing "
        "autonomous system (ASN) / hosting data center for this IP address. Geolocation does NOT represent "
        "an attacker's physical location due to proxies, VPNs, compromised relays, and mail forwarding."
    )

    def __init__(self):
        self._ipinfo_token = getattr(settings, "IPINFO_TOKEN", "2813cce4dddb9d")
        self._iplocation_api_key = getattr(settings, "IPLOCATION_API_KEY", "")
        self._ip_cache: Dict[str, Any] = {}

    def geolocate_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip or not self._is_valid_public_ip(ip):
            return None
        
        if ip in self._ip_cache:
            return self._ip_cache[ip]

        # 1. Primary High-Speed Engine: IPInfo.io with user verified token
        if self._ipinfo_token:
            try:
                resp = requests.get(
                    f"https://ipinfo.io/{ip}?token={self._ipinfo_token}",
                    timeout=2.5
                )
                if resp.ok:
                    res = resp.json()
                    country = res.get("country", "")
                    city = res.get("city", "")
                    region = res.get("region", "")
                    org = res.get("org", "Internet Service Provider")
                    loc = res.get("loc", "")
                    lat, lon = 0.0, 0.0
                    if loc and "," in loc:
                        try:
                            parts = loc.split(",")
                            lat, lon = float(parts[0]), float(parts[1])
                        except Exception:
                            pass
                    
                    data = {
                        "ip": ip,
                        "country": country,
                        "region": region,
                        "city": city,
                        "asn": org,
                        "isp": org,
                        "latitude": lat,
                        "longitude": lon,
                        "is_suspicious_infra": False,
                        "disclaimer": self.DISCLAIMER,
                        "source": "ipinfo_io"
                    }
                    self._ip_cache[ip] = data
                    return data
            except Exception as e:
                print(f"[SIH-Guard] ipinfo.io lookup error for {ip}: {e}")


        # 2. Check offline demo catalog
        if ip in OFFLINE_GEO_DATABASE:
            data = dict(OFFLINE_GEO_DATABASE[ip])
            data["ip"] = ip
            data["disclaimer"] = self.DISCLAIMER
            data["source"] = "local_threat_db"
            self._ip_cache[ip] = data
            return data

        # 3. Try primary live lookup (ip-api.com) with 2.0s timeout
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,as", timeout=2.0)
            if resp.ok:
                res = resp.json()
                if res.get("status") == "success" and res.get("lat") is not None and res.get("lon") is not None:
                    data = {
                        "ip": ip,
                        "country": res.get("country", "Unknown"),
                        "region": res.get("regionName", "Unknown"),
                        "city": res.get("city", ""),
                        "asn": res.get("as", "Unknown ASN"),
                        "isp": res.get("isp", "Unknown ISP"),
                        "latitude": float(res.get("lat", 0.0)),
                        "longitude": float(res.get("lon", 0.0)),
                        "is_suspicious_infra": False,
                        "disclaimer": self.DISCLAIMER,
                        "source": "live_ip_api"
                    }
                    self._ip_cache[ip] = data
                    return data
        except Exception as e:
            print(f"[SIH-Guard] ip-api lookup error for {ip}: {e}")

        # 4. Secondary fallback: ipwho.is with 2.0s timeout
        try:
            resp2 = requests.get(f"https://ipwho.is/{ip}", timeout=2.0)
            if resp2.ok:
                res2 = resp2.json()
                if res2.get("success") and res2.get("latitude") is not None and res2.get("longitude") is not None:
                    connection = res2.get("connection", {})
                    asn_str = f"AS{connection.get('asn', '')} {connection.get('org', '')}".strip() if connection.get('asn') else "Unknown ASN"
                    isp_str = connection.get("isp") or res2.get("isp", "Unknown ISP")
                    data = {
                        "ip": ip,
                        "country": res2.get("country", "Unknown"),
                        "region": res2.get("region", "Unknown"),
                        "city": res2.get("city", ""),
                        "asn": asn_str,
                        "isp": isp_str,
                        "latitude": float(res2.get("latitude", 0.0)),
                        "longitude": float(res2.get("longitude", 0.0)),
                        "is_suspicious_infra": False,
                        "disclaimer": self.DISCLAIMER,
                        "source": "ipwho_is"
                    }
                    self._ip_cache[ip] = data
                    return data
        except Exception as e:
            print(f"[SIH-Guard] ipwho.is lookup error for {ip}: {e}")

        # 5. Fallback heuristic for any unmapped public IP
        fallback = {
            "ip": ip,
            "country": "International Infrastructure",
            "region": "Routing Relay",
            "city": "Public Gateway",
            "asn": "AS-Unknown (Public Transit)",
            "isp": "Internet Service Provider",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "is_suspicious_infra": False,
            "disclaimer": self.DISCLAIMER,
            "source": "heuristic_fallback"
        }
        self._ip_cache[ip] = fallback
        return fallback

    def _is_valid_public_ip(self, ip: str) -> bool:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return False
        octets = [int(x) for x in ip.split('.')]
        if any(o > 255 for o in octets):
            return False
        # Private/loopback ranges
        if octets[0] in (10, 127, 0):
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 172 and (16 <= octets[1] <= 31):
            return False
        return True
