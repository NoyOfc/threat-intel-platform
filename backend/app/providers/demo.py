"""Deterministic, clearly fictional sample data for DEMO_MODE.

The same IOC always yields the same simulated profile, so demos and tests are
repeatable. Names are invented, ASNs come from the RFC 5398 documentation range,
and every result is marked simulated=True. Nothing here touches the network.
"""

import hashlib
import random
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from app.services.ioc import IOC

DEMO_MESSAGE = "Simulated result (DEMO_MODE). Not real threat intelligence."
DEMO_ORGANIZATION = "Example Hosting Ltd (simulated)"
DEMO_ASNS = tuple(range(64496, 64512))  # RFC 5398 documentation ASNs
DEMO_COUNTRIES = ("US", "DE", "NL", "SG", "BR", "FR", "GB", "JP")
DEMO_MALWARE_FAMILIES = ("DemoLoader", "SampleStealer", "PlaceholderRAT", "MockBot")
DEMO_THREAT_ACTORS = ("DEMO-ACTOR-ALPHA", "DEMO-ACTOR-BRAVO", "DEMO-ACTOR-CHARLIE")
DEMO_TAGS = {
    "malicious": ("malware", "c2", "botnet", "phishing", "trojan"),
    "suspicious": ("scanner", "spam", "suspicious-activity"),
    "clean": (),
}


class DemoProfile(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


def demo_rng(salt: str, ioc: IOC) -> random.Random:
    digest = hashlib.sha256(f"{salt}|{ioc.type.value}|{ioc.value}".encode()).digest()
    # Not used for security: only to make sample data repeatable.
    return random.Random(int.from_bytes(digest[:8], "big"))  # noqa: S311


def demo_profile(ioc: IOC, provider: str) -> DemoProfile:
    """Shared profile per IOC so providers mostly agree; each provider occasionally
    rates it one step lower, which exercises the agreement logic."""
    shared = demo_rng("profile", ioc).choices(list(DemoProfile), weights=(45, 25, 30))[0]
    if shared is not DemoProfile.CLEAN and demo_rng(provider, ioc).random() < 0.2:
        return DemoProfile.SUSPICIOUS if shared is DemoProfile.MALICIOUS else DemoProfile.CLEAN
    return shared


def demo_now() -> datetime:
    """Midnight UTC today, so simulated timestamps are stable within a day."""
    return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def days_ago(rng: random.Random, low: int, high: int) -> datetime:
    return demo_now() - timedelta(days=rng.randint(low, high))
