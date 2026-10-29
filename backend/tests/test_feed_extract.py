import pytest

from app.feeds.extract import (
    extract_attack_techniques,
    extract_cves,
    extract_iocs,
    extract_malware,
    extract_threat_actors,
    html_to_text,
    truncate,
)
from tests.feed_fixtures import HOSTILE_HTML, RICH_CONTENT, SHA256

# --- sanitization -----------------------------------------------------------


def test_html_to_text_removes_scripts_styles_and_markup() -> None:
    text = html_to_text("<p>Hello <b>analyst</b></p>" + HOSTILE_HTML)

    assert text == "Hello analyst click me"
    for forbidden in (
        "<",
        ">",
        "script",
        "alert",
        "onerror",
        "javascript",
        "display:none",
        "iframe",
    ):
        assert forbidden not in text


def test_html_to_text_unescapes_entities_without_reintroducing_markup() -> None:
    text = html_to_text("<p>AT&amp;T &lt;script&gt;alert(1)&lt;/script&gt; &quot;quoted&quot;</p>")

    # The result is plain text: the UI renders it escaped, so this can never execute.
    assert text == 'AT&T <script>alert(1)</script> "quoted"'


def test_html_to_text_strips_control_characters_and_collapses_whitespace() -> None:
    assert html_to_text("a\x00b\x1b[31m\n\n\tc\u0085d") == "a b [31m c d"


@pytest.mark.parametrize("value", [None, "", "<script>only script</script>"])
def test_html_to_text_empty(value) -> None:
    assert html_to_text(value) == ""


def test_html_to_text_handles_malformed_html() -> None:
    assert html_to_text("<p>unclosed <b>bold <i>italic</p></div></span>") == "unclosed bold italic"


def test_truncate_on_word_boundary() -> None:
    assert truncate("one two three four", 9) == "one two…"
    assert truncate("short", 100) == "short"


# --- CVE / ATT&CK -----------------------------------------------------------


def test_cve_extraction_normalizes_and_dedupes() -> None:
    text = "CVE-2026-1111, cve-2026-1111, CVE-2025-123456 and CVE-2024-12 (too short) CVE-26-1111"

    assert extract_cves(text) == ["CVE-2026-1111", "CVE-2025-123456"]


def test_cve_extraction_requires_word_boundaries() -> None:
    assert extract_cves("XCVE-2026-1111 CVE-2026-11112222") == []


def test_attack_technique_extraction() -> None:
    text = "Used T1059.001 and T1566, also T1059.001 again. Not T999 or T10000 or AT1234."

    assert extract_attack_techniques(text) == ["T1059.001", "T1566"]


# --- actors / malware -------------------------------------------------------


def test_actor_extraction_named_aliases_and_designations() -> None:
    text = (
        "Midnight Blizzard (APT29) and Storm-0940, with UAT-11473 and UNC3886. Also Volt Typhoon."
    )

    assert extract_threat_actors(text) == [
        "APT29",
        "Volt Typhoon",
        "Storm-0940",
        "UAT-11473",
        "UNC3886",
    ]


def test_attack_tactic_ids_are_not_threat_actors() -> None:
    # Found in a real CISA advisory: TA0001/TA0010 are ATT&CK tactics.
    assert extract_threat_actors(
        "Initial Access TA0001, Exfiltration TA0010, actor TA488 and TA4557"
    ) == [
        "TA488",
        "TA4557",
    ]


def test_malware_extraction_whole_words_only() -> None:
    assert extract_malware("LockBit 3.0 and Qbot, plus Cobalt Strike beacons") == [
        "LockBit",
        "QakBot",
        "Cobalt Strike",
    ]
    assert extract_malware("lockbitten emoteting conti-nued redline review") == []


def test_no_entities_invented_from_plain_text() -> None:
    text = "A routine product update with performance improvements."

    assert extract_threat_actors(text) == []
    assert extract_malware(text) == []
    assert extract_cves(text) == []
    assert extract_attack_techniques(text) == []
    assert extract_iocs(text) == []


# --- IOC extraction ---------------------------------------------------------


def test_ioc_extraction_takes_only_explicit_indicators() -> None:
    iocs = extract_iocs(html_to_text(RICH_CONTENT))

    assert [(i.type.value, i.value) for i in iocs] == [
        ("url", "https://evil.example.com/payload"),
        ("ipv4", "45.33.32.156"),
        ("sha256", SHA256),
    ]


def test_ioc_extraction_drops_internal_and_plain_mentions() -> None:
    iocs = extract_iocs(
        "10.0.0[.]5 127.0.0[.]1 hxxp://localhost/x example.com 8.8.8.8 https://example.org"
    )

    assert iocs == []


def test_ioc_extraction_strips_surrounding_punctuation_and_dedupes() -> None:
    iocs = extract_iocs("(evil[.]example[.]com), evil[.]example[.]com. 'evil[.]example[.]com'")

    assert [i.value for i in iocs] == ["evil.example.com"]


def test_ioc_extraction_is_bounded() -> None:
    text = " ".join(f"host{i}[.]example[.]com" for i in range(500))

    assert len(extract_iocs(text)) == 100
