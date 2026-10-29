"""Safe RSS 2.0 parsing shared by the RSS-based sources."""

import re
import xml.etree.ElementTree as ET  # noqa: S405 - DTDs/entities rejected before parsing
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime

from app.feeds.base import FeedParseError, FeedSource, to_utc
from app.feeds.extract import (
    extract_attack_techniques,
    extract_cves,
    extract_iocs,
    extract_malware,
    extract_threat_actors,
    html_to_text,
    truncate,
)
from app.providers.sanitize import clean_list, clean_text
from app.schemas.feed import ThreatEventData

MAX_ITEMS = 100
SUMMARY_LENGTH = 600
_DTD_OR_ENTITY = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_CONTENT_ENCODED = "{http://purl.org/rss/1.0/modules/content/}encoded"
# Site-navigation categories that carry no intelligence value.
_IGNORED_TAGS = frozenset({"top story", "landing page top story", "uncategorized", "featured"})


@dataclass
class RSSItem:
    title: str | None
    link: str | None
    guid: str | None
    published: datetime | None
    description: str | None
    content: str | None
    categories: list[str] = field(default_factory=list)


def parse_rss(body: bytes) -> list[RSSItem]:
    if _DTD_OR_ENTITY.search(body):
        raise FeedParseError("Feed declares a DTD or entities; refusing to parse.")
    try:
        root = ET.fromstring(body)  # noqa: S314 - no DTD/entities possible (checked above)
    except ET.ParseError:
        raise FeedParseError("Feed is not well-formed XML.") from None
    channel = root.find("channel")
    if root.tag != "rss" or channel is None:
        raise FeedParseError("Document is not an RSS 2.0 feed.")

    items = []
    for element in channel.findall("item")[:MAX_ITEMS]:
        items.append(
            RSSItem(
                title=_text(element, "title"),
                link=_text(element, "link"),
                guid=_text(element, "guid"),
                published=_date(_text(element, "pubDate")),
                description=_text(element, "description"),
                content=_text(element, _CONTENT_ENCODED),
                categories=[c.text for c in element.findall("category") if c.text],
            )
        )
    return items


def _text(element: ET.Element, tag: str) -> str | None:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else None


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return to_utc(parsedate_to_datetime(value))
    except TypeError, ValueError, IndexError:
        return None


class RSSFeedSource(FeedSource):
    """An RSS source whose items are normalized into ThreatEvents."""

    def parse(self, body: bytes) -> list[ThreatEventData]:
        events = []
        for item in parse_rss(body):
            title = clean_text(item.title, 300)
            external_id = clean_text(item.guid or item.link, 500)
            if not title or not external_id:
                continue  # unusable item; never guess an identity
            summary_text = html_to_text(item.description or item.content)
            full_text = " ".join(
                [title, html_to_text(item.content or item.description), *item.categories]
            )
            tags = [t for t in clean_list(item.categories) if t.casefold() not in _IGNORED_TAGS]
            events.append(
                ThreatEventData(
                    source=self.name,
                    external_id=external_id,
                    title=title,
                    summary=truncate(summary_text, SUMMARY_LENGTH) or None,
                    source_url=self.safe_link(item.link),
                    published_at=item.published,
                    category=self.category,
                    threat_actors=extract_threat_actors(full_text),
                    malware_families=extract_malware(full_text),
                    cves=extract_cves(full_text),
                    attack_techniques=extract_attack_techniques(full_text),
                    tags=tags,
                    iocs=extract_iocs(full_text),
                )
            )
        return events
