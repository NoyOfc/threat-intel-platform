"""Turn hostile feed content into plain text and literal, verifiable entities."""

import re
from html.parser import HTMLParser

from app.feeds.entities import ACTOR_DESIGNATION, ACTOR_PATTERNS, MALWARE_PATTERNS
from app.providers.sanitize import clean_list
from app.schemas.feed import FeedIOC
from app.services.ioc import IOCValidationError, parse_ioc

MAX_HTML_INPUT = 2 * 1024 * 1024
MAX_TEXT = 200_000
MAX_ENTITIES = 50
MAX_IOCS = 100

CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
ATTACK_TECHNIQUE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
# Only explicitly marked indicators: defanged notation, or bare file hashes.
DEFANGED_TOKEN = re.compile(
    r"\S*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\[:\]|hxxps?(?:\[?:\]?)?//)\S*", re.I
)
HASH_TOKEN = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])"
)
_TRAILING = ".,;:!?)]}'\"»>"
_LEADING = "([{'\"«<"


class _TextExtractor(HTMLParser):
    _SKIP = frozenset({"script", "style", "noscript", "template", "iframe", "object", "svg"})
    _BLOCK = frozenset(
        {
            "p", "div", "br", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6",
            "table", "ul", "ol", "section", "aside", "pre", "blockquote",
        }
    )  # fmt: skip

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Attributes (href, src, onerror, ...) are discarded entirely.
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._BLOCK:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(value: str | None, max_chars: int = MAX_TEXT) -> str:
    """Reduce untrusted HTML to plain text. No markup survives."""
    if not value:
        return ""
    parser = _TextExtractor()
    parser.feed(value[:MAX_HTML_INPUT])
    parser.close()
    text = "".join(parser.parts)
    text = "".join(" " if ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 else ch for ch in text)
    return re.sub(r"\s+", " ", text).strip()[:max_chars]


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars].rsplit(" ", 1)[0]
    return f"{cut}…"


def extract_cves(text: str) -> list[str]:
    found = (f"CVE-{year}-{number}" for year, number in CVE.findall(text))
    return clean_list(found, max_items=MAX_ENTITIES)


def extract_attack_techniques(text: str) -> list[str]:
    return clean_list(ATTACK_TECHNIQUE.findall(text), max_items=MAX_ENTITIES)


def extract_threat_actors(text: str) -> list[str]:
    named = [canonical for canonical, pattern in ACTOR_PATTERNS if pattern.search(text)]
    designated = ACTOR_DESIGNATION.findall(text)
    return clean_list([*named, *designated], max_items=MAX_ENTITIES)


def extract_malware(text: str) -> list[str]:
    return clean_list(
        [canonical for canonical, pattern in MALWARE_PATTERNS if pattern.search(text)],
        max_items=MAX_ENTITIES,
    )


def extract_iocs(text: str) -> list[FeedIOC]:
    """Indicators the report explicitly marks: defanged values and file hashes.

    Every candidate goes through the IOC engine. Internal/non-public values are
    dropped. Nothing extracted here is ever fetched or resolved.
    """
    candidates = [*DEFANGED_TOKEN.findall(text), *HASH_TOKEN.findall(text)]
    iocs: list[FeedIOC] = []
    seen: set[str] = set()
    for candidate in candidates:
        token = candidate.strip(_TRAILING).lstrip(_LEADING)
        try:
            ioc = parse_ioc(token)
        except IOCValidationError:
            continue
        if ioc.is_internal or ioc.value in seen:
            continue
        seen.add(ioc.value)
        iocs.append(FeedIOC(type=ioc.type, value=ioc.value))
        if len(iocs) == MAX_IOCS:
            break
    return iocs
