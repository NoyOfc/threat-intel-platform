import re
from typing import Any
from urllib.parse import quote

from app.providers.base import Provider
from app.providers.demo import (
    DEMO_ASNS,
    DEMO_COUNTRIES,
    DEMO_MALWARE_FAMILIES,
    DEMO_MESSAGE,
    DEMO_TAGS,
    DEMO_THREAT_ACTORS,
    DemoProfile,
    days_ago,
    demo_profile,
    demo_rng,
)
from app.providers.sanitize import MAX_LIST_ITEMS, clean_int, clean_list, clean_text, from_iso
from app.schemas.provider import ProviderResult, ProviderStatus, Reputation
from app.services.ioc import IOC, IOCType

_SECTIONS = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}
_IP_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6})
_ASN = re.compile(r"AS(\d{1,10})\s*(.*)", re.IGNORECASE)


def reputation_from_pulses(pulse_count: int, has_attribution: bool) -> Reputation:
    # OTX is not a verdict service: popular benign indicators appear in pulses too.
    if pulse_count >= 1 and has_attribution:
        return Reputation.MALICIOUS
    if pulse_count >= 1:
        return Reputation.SUSPICIOUS
    return Reputation.UNKNOWN


def _names(values: Any) -> list[Any]:
    if not isinstance(values, list):
        return []
    return [value.get("display_name") if isinstance(value, dict) else value for value in values]


class OTXProvider(Provider):
    name = "otx"
    display_name = "AlienVault OTX"
    api_host = "otx.alienvault.com"
    api_key_env = "OTX_API_KEY"
    supported_types = frozenset(_SECTIONS)

    def build_request(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        return f"/api/v1/indicators/{_SECTIONS[ioc.type]}/{quote(ioc.value, safe='')}/general", {}

    def auth_headers(self, api_key: str) -> dict[str, str]:
        return {"X-OTX-API-KEY": api_key}

    def normalize(self, ioc: IOC, payload: dict[str, Any]) -> ProviderResult:
        pulse_info = payload.get("pulse_info") or {}
        if not isinstance(pulse_info, dict):
            raise TypeError("pulse_info must be an object")
        pulse_count = clean_int(pulse_info.get("count")) or 0
        pulses = [p for p in pulse_info.get("pulses") or [] if isinstance(p, dict)]

        tags, families, actors = [], [], []
        for pulse in pulses:
            tags.extend(pulse.get("tags") or [])
            families.extend(_names(pulse.get("malware_families")))
            actors.append(pulse.get("adversary"))
        related = pulse_info.get("related") or {}
        for source in related.values() if isinstance(related, dict) else []:
            if isinstance(source, dict):
                families.extend(_names(source.get("malware_families")))
                actors.extend(_names(source.get("adversary")))

        created = [d for d in (from_iso(p.get("created")) for p in pulses) if d]
        modified = [d for d in (from_iso(p.get("modified")) for p in pulses) if d]
        asn, organization = _parse_asn(payload.get("asn"))
        families_clean, actors_clean = clean_list(families), clean_list(actors)

        return self.result(
            ProviderStatus.OK,
            reputation=reputation_from_pulses(pulse_count, bool(families_clean or actors_clean)),
            pulse_count=pulse_count,
            tags=clean_list(tags, max_items=MAX_LIST_ITEMS),
            first_seen=min(created, default=None),
            last_seen=max(modified or created, default=None),
            country=clean_text(payload.get("country_code"), 2),
            asn=asn,
            organization=organization,
            malware_families=families_clean,
            threat_actors=actors_clean,
            raw_metadata_safe_subset={
                "pulse_count": pulse_count,
                "pulses_returned": len(pulses),
            },
        )

    def simulate(self, ioc: IOC) -> ProviderResult:
        rng = demo_rng(self.name, ioc)
        profile = demo_profile(ioc, self.name)
        pulses = {
            DemoProfile.MALICIOUS: rng.randint(3, 25),
            DemoProfile.SUSPICIOUS: rng.randint(1, 3),
            DemoProfile.CLEAN: 0,
        }[profile]
        malicious = profile is DemoProfile.MALICIOUS
        families = [rng.choice(DEMO_MALWARE_FAMILIES)] if malicious else []
        actors = [rng.choice(DEMO_THREAT_ACTORS)] if malicious and rng.random() < 0.5 else []
        is_ip = ioc.type in _IP_TYPES
        return self.result(
            ProviderStatus.OK,
            DEMO_MESSAGE,
            simulated=True,
            reputation=reputation_from_pulses(pulses, bool(families or actors)),
            pulse_count=pulses,
            tags=rng.sample(DEMO_TAGS[profile], k=min(3, len(DEMO_TAGS[profile]))),
            first_seen=days_ago(rng, 90, 700) if pulses else None,
            last_seen=days_ago(rng, 0, 80) if pulses else None,
            country=rng.choice(DEMO_COUNTRIES) if is_ip else None,
            asn=rng.choice(DEMO_ASNS) if is_ip else None,
            malware_families=families,
            threat_actors=actors,
            raw_metadata_safe_subset={"pulse_count": pulses, "pulses_returned": min(pulses, 10)},
        )


def _parse_asn(value: Any) -> tuple[int | None, str | None]:
    text = clean_text(value)
    match = _ASN.fullmatch(text) if text else None
    if not match:
        return None, None
    return int(match.group(1)), clean_text(match.group(2)) or None
