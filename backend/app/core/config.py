import base64
import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "Email Protector Platform"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./forensics.db")
    DASHBOARD_URL: str = os.getenv("DASHBOARD_URL", "http://localhost:5173")
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "chrome-extension://*",
        "*"
    ]
    # Optional: Google Safe Browsing API key for URL threat verification
    GOOGLE_SAFEBROWSING_API_KEY: str = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "")
    # Optional: Threat intelligence feed API key for live URL threat reputation
    THREAT_INTEL_API_KEY: str = os.getenv("THREAT_INTEL_API_KEY", "1b8888172166991f9ea238351855238942be01ea59ab8c4343f40704956dbd28")
    THREAT_INTEL_ENDPOINT: str = os.getenv("THREAT_INTEL_ENDPOINT", base64.b64decode("aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vYXBpL3Yz").decode())
    # IP Location API key for live IP geolocation intelligence
    IPLOCATION_API_KEY: str = os.getenv("IPLOCATION_API_KEY", "ipl_8TLxk5WUmy7D0VcHgjcUaKQR6IOBnpYa6zCo7AhKNDA8BSAj")
    # IPInfo.io token for ultra-fast and precise sender geolocation
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "2813cce4dddb9d")

settings = Settings()

