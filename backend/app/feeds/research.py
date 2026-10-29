"""Vendor threat-research blogs that publish official RSS feeds."""

from app.feeds.rss import RSSFeedSource
from app.schemas.feed import ThreatCategory


class MicrosoftThreatIntelSource(RSSFeedSource):
    name = "microsoft"
    display_name = "Microsoft Threat Intelligence"
    endpoint = "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"
    link_hosts = frozenset({"www.microsoft.com"})
    category = ThreatCategory.THREAT_RESEARCH


class CiscoTalosSource(RSSFeedSource):
    name = "talos"
    display_name = "Cisco Talos"
    endpoint = "https://blog.talosintelligence.com/rss/"
    link_hosts = frozenset({"blog.talosintelligence.com"})
    category = ThreatCategory.THREAT_RESEARCH


class SentinelOneLabsSource(RSSFeedSource):
    name = "sentinelone_labs"
    display_name = "SentinelOne Labs"
    endpoint = "https://www.sentinelone.com/labs/feed/"
    link_hosts = frozenset({"www.sentinelone.com"})
    category = ThreatCategory.THREAT_RESEARCH


class DFIRReportSource(RSSFeedSource):
    name = "dfir_report"
    display_name = "The DFIR Report"
    endpoint = "https://thedfirreport.com/feed/"
    link_hosts = frozenset({"thedfirreport.com"})
    category = ThreatCategory.INCIDENT_REPORT
    refresh_minutes = 60
