from app.feeds.rss import RSSFeedSource
from app.schemas.feed import ThreatCategory


class CISAAdvisoriesSource(RSSFeedSource):
    """CISA Cybersecurity Advisories (official RSS)."""

    name = "cisa_advisories"
    display_name = "CISA Advisories"
    endpoint = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
    link_hosts = frozenset({"www.cisa.gov"})
    category = ThreatCategory.ADVISORY
    refresh_minutes = 30
    planned_reason = (
        "CISA's site protection returns HTTP 403 to automated clients for this RSS feed. "
        "It stays disabled until an access method CISA permits for automated use is confirmed."
    )
