import httpx

from app.core.config import Settings
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.base import Provider
from app.providers.otx import OTXProvider
from app.providers.virustotal import VirusTotalProvider


def build_providers(settings: Settings, client: httpx.AsyncClient) -> list[Provider]:
    common = {
        "client": client,
        "demo_mode": settings.demo_mode,
        "timeout": settings.provider_timeout_seconds,
    }
    return [
        VirusTotalProvider(api_key=settings.virustotal_api_key, **common),
        AbuseIPDBProvider(api_key=settings.abuseipdb_api_key, **common),
        OTXProvider(api_key=settings.otx_api_key, **common),
    ]
