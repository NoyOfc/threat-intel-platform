import json
from datetime import UTC, date, datetime, time
from typing import Any

from app.feeds.base import FeedParseError, FeedSource
from app.feeds.extract import CVE
from app.providers.sanitize import clean_list, clean_text
from app.schemas.feed import KEVDetails, Severity, ThreatCategory, ThreatEventData

MAX_ENTRIES = 5000


class CISAKEVSource(FeedSource):
    """CISA Known Exploited Vulnerabilities catalog (official JSON feed)."""

    name = "cisa_kev"
    display_name = "CISA KEV"
    endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    link_hosts = frozenset({"www.cisa.gov"})
    category = ThreatCategory.EXPLOITED_VULNERABILITY
    refresh_minutes = 60
    timeout_seconds = 30.0

    def parse(self, body: bytes) -> list[ThreatEventData]:
        try:
            catalog = json.loads(body)
        except ValueError:
            raise FeedParseError("KEV catalog is not valid JSON.") from None
        entries = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
        if not isinstance(entries, list):
            raise FeedParseError("KEV catalog has no vulnerabilities list.")
        return [event for entry in entries[:MAX_ENTRIES] if (event := self._event(entry))]

    def _event(self, entry: Any) -> ThreatEventData | None:
        if not isinstance(entry, dict):
            return None
        cve = clean_text(entry.get("cveID"), 20)
        if not cve or not CVE.fullmatch(cve):
            return None  # every KEV event is keyed by a valid CVE; skip anything else
        cve = cve.upper()

        kev = KEVDetails(
            cve=cve,
            vendor=clean_text(entry.get("vendorProject")),
            product=clean_text(entry.get("product")),
            vulnerability_name=clean_text(entry.get("vulnerabilityName"), 300),
            date_added=_date(entry.get("dateAdded")),
            required_action=clean_text(entry.get("requiredAction"), 2000),
            due_date=_date(entry.get("dueDate")),
            known_ransomware_campaign_use=clean_text(entry.get("knownRansomwareCampaignUse"), 40),
            notes=clean_text(entry.get("notes"), 2000),
            cwes=clean_list(entry.get("cwes")),
        )
        ransomware = (kev.known_ransomware_campaign_use or "").casefold() == "known"
        product = " ".join(p for p in (kev.vendor, kev.product) if p)

        return ThreatEventData(
            source=self.name,
            external_id=cve,
            title=f"{cve}: {kev.vulnerability_name or product or 'Known exploited vulnerability'}",
            summary=clean_text(entry.get("shortDescription"), 2000),
            source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve}",
            published_at=datetime.combine(kev.date_added, time(), UTC) if kev.date_added else None,
            # KEV publishes no severity. This rating is derived and labeled as such.
            severity=Severity.CRITICAL if ransomware else Severity.HIGH,
            severity_basis=(
                "Derived: listed in CISA KEV with known ransomware campaign use"
                if ransomware
                else "Derived: listed in CISA KEV (confirmed exploitation)"
            ),
            category=self.category,
            known_exploited=True,
            kev=kev,
            cves=[cve],
            affected_products=[product] if product else [],
            tags=["ransomware"] if ransomware else [],
        )


def _date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None
