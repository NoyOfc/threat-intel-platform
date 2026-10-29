import base64
from typing import Any
from urllib.parse import quote

from app.providers.base import Provider
from app.providers.demo import (
    DEMO_ASNS,
    DEMO_COUNTRIES,
    DEMO_MALWARE_FAMILIES,
    DEMO_MESSAGE,
    DEMO_ORGANIZATION,
    DEMO_TAGS,
    DemoProfile,
    days_ago,
    demo_profile,
    demo_rng,
)
from app.providers.sanitize import clean_int, clean_list, clean_text, from_unix
from app.schemas.provider import ProviderResult, ProviderStatus, Reputation
from app.services.ioc import IOC, IOCType

_COLLECTIONS = {
    IOCType.IPV4: "ip_addresses",
    IOCType.IPV6: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}
_IP_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6})
_FILE_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})
_DEMO_ENGINES = 70


def reputation_from_detections(malicious: int, suspicious: int, engines: int) -> Reputation:
    if malicious >= 3:
        return Reputation.MALICIOUS
    if malicious >= 1 or suspicious >= 2:
        return Reputation.SUSPICIOUS
    return Reputation.CLEAN if engines > 0 else Reputation.UNKNOWN


class VirusTotalProvider(Provider):
    name = "virustotal"
    display_name = "VirusTotal"
    api_host = "www.virustotal.com"
    api_key_env = "VIRUSTOTAL_API_KEY"
    supported_types = frozenset(_COLLECTIONS)

    def build_request(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        if ioc.type is IOCType.URL:
            # VT identifies URLs by unpadded URL-safe base64 of the URL itself.
            identifier = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        else:
            identifier = ioc.value
        return f"/api/v3/{_COLLECTIONS[ioc.type]}/{quote(identifier, safe='')}", {}

    def auth_headers(self, api_key: str) -> dict[str, str]:
        return {"x-apikey": api_key}

    def normalize(self, ioc: IOC, payload: dict[str, Any]) -> ProviderResult:
        attributes = payload["data"]["attributes"]
        if not isinstance(attributes, dict):
            raise TypeError("attributes must be an object")
        stats = attributes.get("last_analysis_stats") or {}
        counts = {
            key: clean_int(stats.get(key)) or 0
            for key in ("malicious", "suspicious", "harmless", "undetected")
        }
        engines = (
            sum(clean_int(value) or 0 for value in stats.values()) if isinstance(stats, dict) else 0
        )

        classification = attributes.get("popular_threat_classification") or {}
        families = clean_list(
            entry.get("value")
            for entry in classification.get("popular_threat_name") or []
            if isinstance(entry, dict)
        )

        return self.result(
            ProviderStatus.OK,
            reputation=reputation_from_detections(
                counts["malicious"], counts["suspicious"], engines
            ),
            malicious_count=counts["malicious"],
            suspicious_count=counts["suspicious"],
            tags=clean_list(attributes.get("tags")),
            first_seen=from_unix(attributes.get("first_submission_date")),
            last_seen=from_unix(attributes.get("last_analysis_date")),
            country=clean_text(attributes.get("country"), 2),
            asn=clean_int(attributes.get("asn")),
            organization=clean_text(attributes.get("as_owner")),
            malware_families=families,
            raw_metadata_safe_subset={
                "engines_total": engines,
                "harmless": counts["harmless"],
                "undetected": counts["undetected"],
                "community_reputation": clean_int(attributes.get("reputation")),
                "threat_label": clean_text(classification.get("suggested_threat_label")),
                "type_description": clean_text(attributes.get("type_description")),
            },
        )

    def simulate(self, ioc: IOC) -> ProviderResult:
        rng = demo_rng(self.name, ioc)
        profile = demo_profile(ioc, self.name)
        if profile is DemoProfile.MALICIOUS:
            malicious, suspicious = rng.randint(8, 45), rng.randint(0, 5)
        elif profile is DemoProfile.SUSPICIOUS:
            malicious, suspicious = rng.randint(0, 2), rng.randint(1, 4)
        else:
            malicious, suspicious = 0, 0
        is_ip = ioc.type in _IP_TYPES
        tags = rng.sample(DEMO_TAGS[profile], k=min(2, len(DEMO_TAGS[profile])))
        families = (
            [rng.choice(DEMO_MALWARE_FAMILIES)]
            if profile is DemoProfile.MALICIOUS and ioc.type in _FILE_TYPES
            else []
        )
        return self.result(
            ProviderStatus.OK,
            DEMO_MESSAGE,
            simulated=True,
            reputation=reputation_from_detections(malicious, suspicious, _DEMO_ENGINES),
            malicious_count=malicious,
            suspicious_count=suspicious,
            tags=tags,
            first_seen=days_ago(rng, 120, 900),
            last_seen=days_ago(rng, 0, 60),
            country=rng.choice(DEMO_COUNTRIES) if is_ip else None,
            asn=rng.choice(DEMO_ASNS) if is_ip else None,
            organization=DEMO_ORGANIZATION if is_ip else None,
            malware_families=families,
            raw_metadata_safe_subset={
                "engines_total": _DEMO_ENGINES,
                "harmless": _DEMO_ENGINES - malicious - suspicious,
                "undetected": 0,
                "threat_label": f"trojan.{families[0].lower()}" if families else None,
            },
        )
