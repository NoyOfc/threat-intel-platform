from typing import Any

from app.providers.base import Provider
from app.providers.demo import (
    DEMO_COUNTRIES,
    DEMO_MESSAGE,
    DEMO_ORGANIZATION,
    DEMO_TAGS,
    DemoProfile,
    days_ago,
    demo_profile,
    demo_rng,
)
from app.providers.sanitize import clean_bool, clean_int, clean_text, from_iso
from app.schemas.provider import ProviderResult, ProviderStatus, Reputation
from app.services.ioc import IOC, IOCType

MAX_AGE_DAYS = 90


def reputation_from_confidence(confidence: int, whitelisted: bool | None) -> Reputation:
    if whitelisted:
        return Reputation.CLEAN
    if confidence >= 75:
        return Reputation.MALICIOUS
    if confidence >= 25:
        return Reputation.SUSPICIOUS
    return Reputation.CLEAN


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    api_host = "api.abuseipdb.com"
    api_key_env = "ABUSEIPDB_API_KEY"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})

    def build_request(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        return "/api/v2/check", {"ipAddress": ioc.value, "maxAgeInDays": str(MAX_AGE_DAYS)}

    def auth_headers(self, api_key: str) -> dict[str, str]:
        return {"Key": api_key}

    def normalize(self, ioc: IOC, payload: dict[str, Any]) -> ProviderResult:
        data = payload["data"]
        if not isinstance(data, dict):
            raise TypeError("data must be an object")
        confidence = max(0, min(100, clean_int(data.get("abuseConfidenceScore")) or 0))
        whitelisted = clean_bool(data.get("isWhitelisted"))
        return self.result(
            ProviderStatus.OK,
            reputation=reputation_from_confidence(confidence, whitelisted),
            confidence=confidence,
            report_count=clean_int(data.get("totalReports")),
            last_seen=from_iso(data.get("lastReportedAt")),
            country=clean_text(data.get("countryCode"), 2),
            organization=clean_text(data.get("isp")),
            raw_metadata_safe_subset={
                "usage_type": clean_text(data.get("usageType")),
                "domain": clean_text(data.get("domain")),
                "distinct_reporters": clean_int(data.get("numDistinctUsers")),
                "is_whitelisted": whitelisted,
                "is_tor": clean_bool(data.get("isTor")),
                "max_age_days": MAX_AGE_DAYS,
            },
        )

    def simulate(self, ioc: IOC) -> ProviderResult:
        rng = demo_rng(self.name, ioc)
        profile = demo_profile(ioc, self.name)
        if profile is DemoProfile.MALICIOUS:
            confidence, reports = rng.randint(75, 100), rng.randint(20, 400)
        elif profile is DemoProfile.SUSPICIOUS:
            confidence, reports = rng.randint(25, 55), rng.randint(2, 25)
        else:
            confidence, reports = rng.randint(0, 3), rng.randint(0, 1)
        return self.result(
            ProviderStatus.OK,
            DEMO_MESSAGE,
            simulated=True,
            reputation=reputation_from_confidence(confidence, whitelisted=False),
            confidence=confidence,
            report_count=reports,
            tags=list(DEMO_TAGS[profile][:1]),
            last_seen=days_ago(rng, 0, 45) if reports else None,
            country=rng.choice(DEMO_COUNTRIES),
            organization=DEMO_ORGANIZATION,
            raw_metadata_safe_subset={
                "usage_type": "Data Center/Web Hosting/Transit (simulated)",
                "distinct_reporters": max(0, reports // 3),
                "is_whitelisted": False,
                "is_tor": False,
                "max_age_days": MAX_AGE_DAYS,
            },
        )
