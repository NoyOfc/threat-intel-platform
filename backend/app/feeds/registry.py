import httpx

from app.feeds.base import FeedSource
from app.feeds.cisa import CISAAdvisoriesSource
from app.feeds.cisa_kev import CISAKEVSource
from app.feeds.research import (
    CiscoTalosSource,
    DFIRReportSource,
    MicrosoftThreatIntelSource,
    SentinelOneLabsSource,
)

SOURCE_CLASSES: tuple[type[FeedSource], ...] = (
    CISAKEVSource,
    CISAAdvisoriesSource,
    MicrosoftThreatIntelSource,
    CiscoTalosSource,
    SentinelOneLabsSource,
    DFIRReportSource,
)


def build_sources(client: httpx.AsyncClient) -> list[FeedSource]:
    return [cls(client) for cls in SOURCE_CLASSES]
