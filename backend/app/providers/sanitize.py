"""Helpers for turning untrusted provider JSON into bounded, typed values."""

import re
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

MAX_TEXT_LENGTH = 200
MAX_TAG_LENGTH = 64
MAX_LIST_ITEMS = 25


def clean_text(value: Any, max_length: int = MAX_TEXT_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in value)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_length] or None


def clean_list(
    values: Any, max_items: int = MAX_LIST_ITEMS, max_length: int = MAX_TAG_LENGTH
) -> list[str]:
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes, dict)):
        return []
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = clean_text(value, max_length)
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
            if len(result) == max_items:
                break
    return result


def clean_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def clean_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def from_unix(value: Any) -> datetime | None:
    seconds = clean_int(value)
    if seconds is None or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except OverflowError, OSError, ValueError:
        return None


def from_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
