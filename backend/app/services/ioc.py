"""IOC parsing, normalization, validation, and type detection.

Everything here is pure string processing. This module must never resolve DNS,
open sockets, fetch URLs, or hand values to a shell: IOC values are untrusted
data, not destinations.

``network_scope`` describes what an address or hostname *is* (public, private,
loopback, ...) so analysts can see it. Private and loopback values are valid
IOC data. The scope is informational only and is never a permission to
connect: ThreatScope does not connect to any submitted indicator, whatever
its scope. Hostname scope is derived from the name alone; names are never
resolved.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_IOC_LENGTH = 2048


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class NetworkScope(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"
    INTERNAL_HOSTNAME = "internal_hostname"


@dataclass(frozen=True, slots=True)
class IOC:
    """Normalized internal representation of a validated indicator."""

    type: IOCType
    value: str
    original: str
    refanged: bool
    network_scope: NetworkScope | None

    @property
    def is_internal(self) -> bool:
        """True for non-public addresses/hostnames. Still valid data; never a target."""
        return self.network_scope not in (None, NetworkScope.PUBLIC)


class IOCValidationError(ValueError):
    def __init__(self, code: str, message: str, suspected_type: IOCType | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suspected_type = suspected_type


_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_HEX = re.compile(r"[0-9a-fA-F]+")
_ALNUM = re.compile(r"[0-9a-zA-Z]+")
# Integer, hex, or octal IPv4 forms (e.g. 2130706433, 0x7f000001, 0177.0.0.1, 127.1).
_IPV4_LIKE = re.compile(r"(?:0x[0-9a-f]*|\d+)(?:\.(?:0x[0-9a-f]*|\d+)){0,3}", re.IGNORECASE)
# Two or more colons and nothing else exotic: probably an attempted IPv6 address.
_IPV6_LIKE = re.compile(r"\[?[0-9a-z.%]*(?::[0-9a-z.%]*){2,}\]?", re.IGNORECASE)
_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
_TLD = re.compile(r"(?!-)[a-z0-9-]{2,63}(?<!-)")

_URL_SCHEMES = frozenset({"http", "https", "ftp"})
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".intranet", ".corp", ".home.arpa")

_REFANG_RULES = (
    (re.compile(r"^hxxp(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
)


def parse_ioc(raw: str) -> IOC:
    """Validate, normalize, and classify one IOC string. Raises IOCValidationError."""
    if len(raw) > MAX_IOC_LENGTH:
        raise IOCValidationError(
            "too_long", f"IOC exceeds the maximum length of {MAX_IOC_LENGTH} characters."
        )
    original = raw.strip()
    if not original:
        raise IOCValidationError("empty", "IOC is blank.")
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in original):
        raise IOCValidationError(
            "invalid_characters", "IOC contains whitespace or control characters."
        )

    value = refang(original)
    refanged = value != original

    def build(ioc_type: IOCType, normalized: str, scope: NetworkScope | None = None) -> IOC:
        return IOC(ioc_type, normalized, original, refanged, scope)

    if "://" in value:
        normalized, scope = _parse_url(value)
        return build(IOCType.URL, normalized, scope)

    if _HEX.fullmatch(value):
        if len(value) in _HASH_TYPES:
            return build(_HASH_TYPES[len(value)], value.lower())
        if len(value) >= 16 and not value.isdigit():
            raise IOCValidationError(
                "invalid_hash",
                f"Hex string of length {len(value)} is not an MD5 (32), SHA1 (40), "
                "or SHA256 (64) hash.",
            )
    elif _ALNUM.fullmatch(value) and len(value) in _HASH_TYPES:
        raise IOCValidationError(
            "invalid_hash",
            "Value has the length of a hash but contains non-hexadecimal characters.",
            suspected_type=_HASH_TYPES[len(value)],
        )

    address = _parse_ip(value)
    if address is not None:
        ioc_type = IOCType.IPV4 if address.version == 4 else IOCType.IPV6
        return build(ioc_type, str(address), classify_address(address))
    if _IPV4_LIKE.fullmatch(value):
        raise IOCValidationError(
            "invalid_ip",
            "Not a valid IPv4 address. Only standard dotted-decimal notation is accepted "
            "(integer, hex, octal, and shortened forms are rejected).",
            suspected_type=IOCType.IPV4,
        )
    if _IPV6_LIKE.fullmatch(value):
        raise IOCValidationError(
            "invalid_ip", "Not a valid IPv6 address.", suspected_type=IOCType.IPV6
        )

    if "." in value or value.lower() == "localhost":
        domain = _parse_domain(value)
        return build(IOCType.DOMAIN, domain, classify_hostname(domain))

    raise IOCValidationError(
        "unrecognized",
        "Could not identify the IOC type. Supported: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256.",
    )


def refang(value: str) -> str:
    """Undo common defanging (hxxp://, [.], (.), [:]) so the value can be parsed."""
    for pattern, replacement in _REFANG_RULES:
        value = pattern.sub(replacement, value)
    return value


def classify_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> NetworkScope:
    # Classify IPv4-mapped IPv6 (::ffff:127.0.0.1) by the IPv4 address it embeds.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return NetworkScope.UNSPECIFIED
    if address.is_loopback:
        return NetworkScope.LOOPBACK
    if address.is_link_local:
        return NetworkScope.LINK_LOCAL
    if address.is_multicast:
        return NetworkScope.MULTICAST
    if address.is_private:
        return NetworkScope.PRIVATE
    if address.is_global:
        return NetworkScope.PUBLIC
    return NetworkScope.RESERVED


def classify_hostname(hostname: str) -> NetworkScope:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return NetworkScope.LOOPBACK
    if hostname.endswith(_INTERNAL_SUFFIXES):
        return NetworkScope.INTERNAL_HOSTNAME
    return NetworkScope.PUBLIC


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    if ":" in candidate and "%" in candidate:
        raise IOCValidationError(
            "invalid_ip",
            "IPv6 zone identifiers (e.g. %eth0) are not supported.",
            suspected_type=IOCType.IPV6,
        )
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _parse_domain(value: str) -> str:
    name = value.lower()
    if name.endswith("."):
        name = name[:-1]
    if name == "localhost":
        return name
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            raise _invalid_domain("Internationalized domain name is not valid.") from None
    if len(name) > 253:
        raise _invalid_domain("Domain exceeds 253 characters.")
    labels = name.split(".")
    if len(labels) < 2:
        raise _invalid_domain("Domain must have at least two labels (e.g. example.com).")
    *subdomains, tld = labels
    for label in subdomains:
        if not _LABEL.fullmatch(label):
            raise _invalid_domain(
                "Each domain label must be 1-63 letters, digits, hyphens, or underscores, "
                "and cannot start or end with a hyphen."
            )
    if not _TLD.fullmatch(tld) or tld.isdigit():
        raise _invalid_domain("Domain has an invalid top-level domain.")
    return name


def _invalid_domain(message: str) -> IOCValidationError:
    return IOCValidationError("invalid_domain", message, suspected_type=IOCType.DOMAIN)


def _invalid_url(message: str) -> IOCValidationError:
    return IOCValidationError("invalid_url", message, suspected_type=IOCType.URL)


def _parse_url(value: str) -> tuple[str, NetworkScope]:
    """Parse a URL as text only. The URL is never requested."""
    try:
        parts: SplitResult = urlsplit(value)
        port = parts.port
    except ValueError:
        raise _invalid_url("URL is malformed (invalid host or port).") from None

    scheme = parts.scheme.lower()
    if scheme not in _URL_SCHEMES:
        raise IOCValidationError(
            "unsupported_url_scheme",
            f"URL scheme must be one of: {', '.join(sorted(_URL_SCHEMES))}.",
            suspected_type=IOCType.URL,
        )
    if "\\" in parts.netloc:
        raise _invalid_url("URL authority contains a backslash, which is ambiguous.")
    host = parts.hostname
    if not host:
        raise _invalid_url("URL has no host.")

    try:
        address = _parse_ip(host)
    except IOCValidationError as exc:
        raise _invalid_url(exc.message) from None
    if address is not None:
        scope = classify_address(address)
        host_text = f"[{address}]" if address.version == 6 else str(address)
    elif _IPV4_LIKE.fullmatch(host):
        raise _invalid_url(
            "URL host uses non-standard IP notation (integer, hex, or octal), a common "
            "obfuscation. Use dotted-decimal."
        )
    else:
        try:
            host_text = _parse_domain(host)
        except IOCValidationError as exc:
            raise _invalid_url(f"URL host is not a valid domain: {exc.message}") from None
        scope = classify_hostname(host_text)

    userinfo, _, _ = parts.netloc.rpartition("@")
    netloc = f"{userinfo}@" if userinfo else ""
    netloc += host_text
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment)), scope
