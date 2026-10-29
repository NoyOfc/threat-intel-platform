"""Sample feed documents for tests. Content is fictional; hostile parts are deliberate."""

import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from html import escape

import httpx

from app.feeds.base import FeedSource
from tests.provider_helpers import Handler, RecordingTransport

SHA256 = "a" * 63 + "b"
HOSTILE_HTML = (
    "<script>alert('xss')</script><style>body{display:none}</style>"
    '<img src="x" onerror="alert(1)"><a href="javascript:alert(1)">click me</a>'
    "<iframe src='https://evil.example.com'></iframe>"
)


def ago(**delta: float) -> datetime:
    return datetime.now(UTC) - timedelta(**delta)


def rss_item(
    title: str | None = "Sample report",
    link: str | None = "https://blog.talosintelligence.com/sample-report/",
    guid: str | None = "guid-1",
    published: datetime | None = None,
    description: str | None = "<p>Short summary.</p>",
    content: str | None = None,
    categories: tuple[str, ...] = (),
) -> str:
    parts = []
    if title is not None:
        parts.append(f"<title>{escape(title)}</title>")
    if link is not None:
        parts.append(f"<link>{escape(link)}</link>")
    if guid is not None:
        parts.append(f"<guid>{escape(guid)}</guid>")
    parts.append(f"<pubDate>{format_datetime(published or ago(hours=2))}</pubDate>")
    if description is not None:
        parts.append(f"<description>{escape(description)}</description>")
    if content is not None:
        parts.append(f"<content:encoded>{escape(content)}</content:encoded>")
    parts.extend(f"<category>{escape(c)}</category>" for c in categories)
    return f"<item>{''.join(parts)}</item>"


def rss(*items: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">'
        f"<channel><title>Feed</title>{''.join(items)}</channel></rss>"
    ).encode()


RICH_CONTENT = (
    "<h2>Summary</h2><p>Volt Typhoon and Storm-0940 exploited CVE-2026-1111 and cve-2026-3333 "
    "using LockBit and Cobalt Strike (T1059.001, T1566).</p>"
    "<p>IOCs: hxxps://evil[.]example[.]com/payload, 45.33.32[.]156, 10.0.0[.]5, "
    f"{SHA256}. Benign mention: microsoft.com and lockbitten.</p>" + HOSTILE_HTML
)


def kev_entry(cve: str, date_added: str, ransomware: str = "Unknown", **overrides) -> dict:
    entry = {
        "cveID": cve,
        "vendorProject": "ExampleSoft",
        "product": "Gateway",
        "vulnerabilityName": "ExampleSoft Gateway Command Injection Vulnerability",
        "dateAdded": date_added,
        "shortDescription": "ExampleSoft Gateway contains a command injection vulnerability.",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
        "dueDate": "2026-11-10",
        "knownRansomwareCampaignUse": ransomware,
        "notes": "https://example.com/vendor-advisory",
        "cwes": ["CWE-78"],
    }
    entry.update(overrides)
    return entry


def kev(*entries: object) -> bytes:
    return json.dumps(
        {"title": "CISA KEV", "count": len(entries), "vulnerabilities": list(entries)}
    ).encode()


def recent_date(days: int = 1) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).date().isoformat()


def make_source(cls: type[FeedSource], handler: Handler) -> tuple[FeedSource, RecordingTransport]:
    transport = RecordingTransport(handler)
    return cls(httpx.AsyncClient(transport=transport, follow_redirects=False)), transport


def body(content: bytes, status: int = 200, **headers: str) -> Handler:
    return lambda request: httpx.Response(status, content=content, headers=headers)
