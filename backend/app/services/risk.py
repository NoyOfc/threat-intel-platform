"""Explainable 0-100 risk score built from weighted signals.

Each signal contributes capped points with a human-readable reason, so a score
can always be traced back to evidence. See docs/risk-scoring.md.
"""

import re
from collections.abc import Callable
from datetime import UTC, datetime

from app.schemas.provider import RESPONDED_STATUSES, ProviderResult
from app.schemas.risk import RiskAssessment, RiskFactor, RiskLevel

# Lower bound of each level, highest first.
LEVEL_THRESHOLDS = (
    (80, RiskLevel.CRITICAL),
    (60, RiskLevel.HIGH),
    (40, RiskLevel.MEDIUM),
    (20, RiskLevel.LOW),
    (0, RiskLevel.INFORMATIONAL),
)

MALICIOUS_TAG_KEYWORDS = frozenset(
    {
        "apt", "backdoor", "botnet", "c2", "c&c", "cobalt", "exploit", "loader", "malware",
        "miner", "phishing", "ransomware", "rat", "stealer", "trojan", "worm",
    }
)  # fmt: skip
_TAG_WORD = re.compile(r"[a-z0-9&]+")


def level_for(score: int) -> RiskLevel:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.INFORMATIONAL


def _tiered(value: int, tiers: tuple[tuple[int, int], ...]) -> int:
    """Points for the highest tier whose minimum `value` reaches. Tiers are (minimum, points)."""
    return next((points for minimum, points in tiers if value >= minimum), 0)


def _best(results: list[ProviderResult], field: str) -> tuple[int, list[str]]:
    """Highest value of an integer field, and which providers reported it."""
    values = [(getattr(r, field), r.display_name) for r in results if getattr(r, field)]
    if not values:
        return 0, []
    top = max(value for value, _ in values)
    return top, [name for value, name in values if value == top]


# --- signals ----------------------------------------------------------------
# Each takes the responding providers and returns a factor, or None if it doesn't apply.


def _detections(results: list[ProviderResult]) -> RiskFactor | None:
    malicious, providers = _best(results, "malicious_count")
    points = _tiered(malicious, ((20, 40), (10, 35), (5, 28), (3, 20), (2, 15), (1, 10)))
    if not points:
        return None
    return RiskFactor(
        signal="Malicious vendor detections",
        points=points,
        detail=f"{malicious} security vendor(s) flagged this indicator as malicious.",
        providers=providers,
    )


def _suspicious_detections(results: list[ProviderResult]) -> RiskFactor | None:
    suspicious, providers = _best(results, "suspicious_count")
    if not suspicious:
        return None
    return RiskFactor(
        signal="Suspicious vendor detections",
        points=min(suspicious, 5),
        detail=f"{suspicious} vendor(s) rated this indicator suspicious.",
        providers=providers,
    )


def _abuse_confidence(results: list[ProviderResult]) -> RiskFactor | None:
    confidence, providers = _best(results, "confidence")
    points = round(confidence * 0.30)
    if not points:
        return None
    return RiskFactor(
        signal="Abuse confidence",
        points=points,
        detail=f"Abuse confidence score of {confidence}%.",
        providers=providers,
    )


def _report_volume(results: list[ProviderResult]) -> RiskFactor | None:
    reports, providers = _best(results, "report_count")
    points = _tiered(reports, ((100, 10), (25, 7), (5, 4), (1, 2)))
    if not points:
        return None
    return RiskFactor(
        signal="Abuse reports",
        points=points,
        detail=f"Reported {reports} time(s) by the community.",
        providers=providers,
    )


def _pulses(results: list[ProviderResult]) -> RiskFactor | None:
    pulses, providers = _best(results, "pulse_count")
    points = _tiered(pulses, ((10, 15), (5, 12), (2, 8), (1, 5)))
    if not points:
        return None
    return RiskFactor(
        signal="Threat intelligence pulses",
        points=points,
        detail=f"Referenced in {pulses} threat intelligence pulse(s).",
        providers=providers,
    )


def _attribution(results: list[ProviderResult]) -> RiskFactor | None:
    families = sorted({f for r in results for f in r.malware_families})
    actors = sorted({a for r in results for a in r.threat_actors})
    if not families and not actors:
        return None
    parts = []
    if families:
        parts.append(f"malware families: {', '.join(families[:5])}")
    if actors:
        parts.append(f"threat actors: {', '.join(actors[:5])}")
    return RiskFactor(
        signal="Malware or actor attribution",
        points=10,
        detail=f"Linked to {'; '.join(parts)}.",
        providers=[r.display_name for r in results if r.malware_families or r.threat_actors],
    )


def _is_malicious_tag(tag: str) -> bool:
    return any(word in MALICIOUS_TAG_KEYWORDS for word in _TAG_WORD.findall(tag.casefold()))


def _malicious_tags(results: list[ProviderResult]) -> RiskFactor | None:
    matched = sorted({tag for r in results for tag in r.tags if _is_malicious_tag(tag)})
    points = _tiered(len(matched), ((3, 8), (2, 6), (1, 4)))
    if not points:
        return None
    return RiskFactor(
        signal="Malicious tags",
        points=points,
        detail=f"Tagged as: {', '.join(matched[:8])}.",
        providers=[r.display_name for r in results if set(r.tags) & set(matched)],
    )


def _whitelisted(results: list[ProviderResult]) -> RiskFactor | None:
    providers = [
        r.display_name for r in results if r.raw_metadata_safe_subset.get("is_whitelisted") is True
    ]
    if not providers:
        return None
    return RiskFactor(
        signal="Allowlisted",
        points=-15,
        detail="Provider lists this indicator as allowlisted/trusted.",
        providers=providers,
    )


THREAT_SIGNALS: tuple[Callable[[list[ProviderResult]], RiskFactor | None], ...] = (
    _detections,
    _suspicious_detections,
    _abuse_confidence,
    _report_volume,
    _pulses,
    _attribution,
    _malicious_tags,
)


# --- modifiers that depend on the threat signals ----------------------------


def _agreement(results: list[ProviderResult]) -> RiskFactor | None:
    flagged = [r.display_name for r in results if r.flagged]
    if len(flagged) < 2:
        return None
    return RiskFactor(
        signal="Provider agreement",
        points=15 if len(flagged) >= 3 else 10,
        detail=f"{len(flagged)} independent providers flagged this indicator.",
        providers=flagged,
    )


def _recency(results: list[ProviderResult], now: datetime) -> RiskFactor | None:
    seen = [(r.last_seen, r.display_name) for r in results if r.last_seen]
    if not seen:
        return None
    last_seen, provider = max(seen)
    age_days = max(0, (now - last_seen).days)
    if age_days <= 7:
        points, detail = 10, "Observed within the last 7 days."
    elif age_days <= 30:
        points, detail = 7, "Observed within the last 30 days."
    elif age_days <= 90:
        points, detail = 4, "Observed within the last 90 days."
    elif age_days > 365:
        points, detail = -5, f"Last observed {age_days} days ago; activity may be stale."
    else:
        return None
    return RiskFactor(
        signal="Recent observation", points=points, detail=detail, providers=[provider]
    )


def assess(results: list[ProviderResult], now: datetime | None = None) -> RiskAssessment:
    now = now or datetime.now(UTC)
    responded = [r for r in results if r.status in RESPONDED_STATUSES]
    simulated = any(r.simulated for r in responded)
    flagged = sum(r.flagged for r in responded)

    if not responded:
        return RiskAssessment(
            score=None,
            level=RiskLevel.UNKNOWN,
            summary="No provider returned intelligence, so risk could not be assessed.",
            factors=[],
            providers_considered=0,
            providers_flagged=0,
            simulated=False,
        )

    factors = [factor for signal in THREAT_SIGNALS if (factor := signal(responded))]
    if factors:
        # Agreement and recency only amplify existing evidence; they never create risk alone.
        factors += [f for f in (_agreement(responded), _recency(responded, now)) if f]
    if whitelist := _whitelisted(responded):
        factors.append(whitelist)
    factors.sort(key=lambda factor: factor.points, reverse=True)

    score = max(0, min(100, sum(factor.points for factor in factors)))
    level = level_for(score)
    if not factors:
        summary = f"No threat signals from {len(responded)} responding provider(s)."
    else:
        summary = (
            f"{level.value.capitalize()} risk: {flagged} of {len(responded)} responding "
            f"provider(s) flagged this indicator."
        )
    return RiskAssessment(
        score=score,
        level=level,
        summary=summary,
        factors=factors,
        providers_considered=len(responded),
        providers_flagged=flagged,
        simulated=simulated,
    )
