from datetime import timedelta

import pytest

from app.schemas.provider import ProviderStatus, Reputation
from app.schemas.risk import RiskLevel
from app.services.risk import assess, level_for
from tests.provider_helpers import NOW, result


def signals(assessment) -> dict[str, int]:
    return {factor.signal: factor.points for factor in assessment.factors}


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, RiskLevel.INFORMATIONAL),
        (19, RiskLevel.INFORMATIONAL),
        (20, RiskLevel.LOW),
        (39, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (59, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (79, RiskLevel.HIGH),
        (80, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_level_boundaries(score: int, level: RiskLevel) -> None:
    assert level_for(score) is level


def test_no_responding_provider_is_unknown_not_safe() -> None:
    assessment = assess(
        [
            result(status=ProviderStatus.TIMEOUT),
            result("abuseipdb", ProviderStatus.NOT_CONFIGURED),
            result("otx", ProviderStatus.SKIPPED),
        ],
        NOW,
    )

    assert assessment.score is None
    assert assessment.level is RiskLevel.UNKNOWN
    assert assessment.factors == []


def test_providers_with_no_record_score_zero() -> None:
    assessment = assess([result(status=ProviderStatus.NOT_FOUND)], NOW)

    assert assessment.score == 0
    assert assessment.level is RiskLevel.INFORMATIONAL
    assert assessment.providers_considered == 1


def test_clean_results_score_zero_and_recency_does_not_add_risk() -> None:
    assessment = assess(
        [
            result(
                malicious_count=0, suspicious_count=0, reputation=Reputation.CLEAN, last_seen=NOW
            ),
            result(
                "abuseipdb",
                confidence=0,
                report_count=0,
                reputation=Reputation.CLEAN,
                last_seen=NOW,
            ),
        ],
        NOW,
    )

    assert assessment.score == 0
    assert assessment.factors == []


def test_single_provider_result_has_no_agreement_bonus() -> None:
    assessment = assess(
        [result(malicious_count=12, reputation=Reputation.MALICIOUS)],
        NOW,
    )

    assert signals(assessment) == {"Malicious vendor detections": 35}
    assert assessment.score == 35
    assert assessment.level is RiskLevel.LOW
    assert assessment.providers_flagged == 1


def test_single_flag_among_several_providers_gets_no_agreement_bonus() -> None:
    assessment = assess(
        [
            result(malicious_count=4, reputation=Reputation.MALICIOUS),
            result("abuseipdb", confidence=0, reputation=Reputation.CLEAN),
            result("otx", pulse_count=0),
        ],
        NOW,
    )

    assert "Provider agreement" not in signals(assessment)


def test_two_providers_agreeing_adds_ten() -> None:
    assessment = assess(
        [
            result(malicious_count=5, reputation=Reputation.MALICIOUS),
            result("abuseipdb", confidence=50, reputation=Reputation.SUSPICIOUS),
        ],
        NOW,
    )

    assert signals(assessment)["Provider agreement"] == 10


def test_all_signals_combine_into_explained_critical_score() -> None:
    assessment = assess(
        [
            result(
                malicious_count=25,
                suspicious_count=3,
                reputation=Reputation.MALICIOUS,
                tags=["c2", "botnet", "cobalt-strike"],
                last_seen=NOW - timedelta(days=2),
            ),
            result("abuseipdb", confidence=90, report_count=150, reputation=Reputation.MALICIOUS),
            result(
                "otx",
                pulse_count=12,
                reputation=Reputation.MALICIOUS,
                malware_families=["DemoLoader"],
                threat_actors=["DEMO-ACTOR-ALPHA"],
            ),
        ],
        NOW,
    )

    assert signals(assessment) == {
        "Malicious vendor detections": 40,
        "Suspicious vendor detections": 3,
        "Abuse confidence": 27,
        "Abuse reports": 10,
        "Threat intelligence pulses": 15,
        "Malware or actor attribution": 10,
        "Malicious tags": 8,
        "Provider agreement": 15,
        "Recent observation": 10,
    }
    assert assessment.score == 100  # clamped
    assert assessment.level is RiskLevel.CRITICAL
    assert [f.points for f in assessment.factors] == sorted(
        (f.points for f in assessment.factors), reverse=True
    )


def test_factors_explain_the_score_when_not_clamped() -> None:
    assessment = assess(
        [
            result(
                malicious_count=3,
                reputation=Reputation.MALICIOUS,
                last_seen=NOW - timedelta(days=20),
            ),
            result("abuseipdb", confidence=40, report_count=6, reputation=Reputation.SUSPICIOUS),
        ],
        NOW,
    )

    assert assessment.score == sum(f.points for f in assessment.factors)
    assert assessment.score == 20 + 12 + 4 + 10 + 7
    assert assessment.level is RiskLevel.MEDIUM
    assert all(f.detail and f.providers for f in assessment.factors)


@pytest.mark.parametrize(
    ("age_days", "points"),
    [(0, 10), (7, 10), (8, 7), (30, 7), (31, 4), (90, 4), (200, None), (400, -5)],
)
def test_recency_tiers(age_days: int, points: int | None) -> None:
    assessment = assess(
        [
            result(
                malicious_count=5,
                reputation=Reputation.MALICIOUS,
                last_seen=NOW - timedelta(days=age_days),
            )
        ],
        NOW,
    )

    assert signals(assessment).get("Recent observation") == points


def test_allowlisted_indicator_reduces_score() -> None:
    assessment = assess(
        [
            result(malicious_count=1, reputation=Reputation.SUSPICIOUS),
            result(
                "abuseipdb",
                confidence=0,
                reputation=Reputation.CLEAN,
                raw_metadata_safe_subset={"is_whitelisted": True},
            ),
        ],
        NOW,
    )

    assert signals(assessment)["Allowlisted"] == -15
    assert assessment.score == 0  # never below zero


def test_score_is_weighted_not_averaged() -> None:
    # One strong signal must not be diluted by providers that simply have no data.
    strong = assess([result(malicious_count=20, reputation=Reputation.MALICIOUS)], NOW)
    with_empty = assess(
        [
            result(malicious_count=20, reputation=Reputation.MALICIOUS),
            result("abuseipdb", status=ProviderStatus.NOT_FOUND),
            result("otx", pulse_count=0),
        ],
        NOW,
    )

    assert strong.score == with_empty.score == 40


def test_benign_tags_do_not_count() -> None:
    assessment = assess(
        [
            result(
                malicious_count=1,
                reputation=Reputation.SUSPICIOUS,
                tags=["cdn", "cloud", "ratings"],
            )
        ],
        NOW,
    )

    assert "Malicious tags" not in signals(assessment)


def test_simulated_flag_propagates() -> None:
    assessment = assess(
        [result(malicious_count=5, reputation=Reputation.MALICIOUS, simulated=True)], NOW
    )

    assert assessment.simulated is True
