import pytest

from app.services.ioc import (
    MAX_IOC_LENGTH,
    IOCType,
    IOCValidationError,
    NetworkScope,
    parse_ioc,
)

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def assert_invalid(raw: str, code: str) -> IOCValidationError:
    with pytest.raises(IOCValidationError) as exc_info:
        parse_ioc(raw)
    assert exc_info.value.code == code
    return exc_info.value


# --- IPv4 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "scope"),
    [
        ("8.8.8.8", NetworkScope.PUBLIC),
        ("1.1.1.1", NetworkScope.PUBLIC),
        ("10.0.0.1", NetworkScope.PRIVATE),
        ("172.16.5.4", NetworkScope.PRIVATE),
        ("192.168.1.1", NetworkScope.PRIVATE),
        ("127.0.0.1", NetworkScope.LOOPBACK),
        ("127.255.255.254", NetworkScope.LOOPBACK),
        ("169.254.169.254", NetworkScope.LINK_LOCAL),  # cloud metadata service
        ("0.0.0.0", NetworkScope.UNSPECIFIED),  # noqa: S104 - IOC data, nothing binds to it
        ("224.0.0.1", NetworkScope.MULTICAST),
    ],
)
def test_ipv4_detected_with_scope(raw: str, scope: NetworkScope) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.IPV4
    assert ioc.value == raw
    assert ioc.network_scope is scope
    assert ioc.is_internal is (scope is not NetworkScope.PUBLIC)


def test_private_and_loopback_ips_are_valid_data_but_flagged_internal() -> None:
    for raw in ("10.1.2.3", "192.168.0.10", "127.0.0.1", "169.254.169.254"):
        ioc = parse_ioc(raw)
        assert ioc.is_internal, raw


def test_cgnat_address_is_not_public() -> None:
    assert parse_ioc("100.64.0.1").is_internal


@pytest.mark.parametrize(
    "raw",
    [
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "2130706433",  # integer form of 127.0.0.1
        "0x7f000001",  # hex form
        "0x7f.0.0.1",
        "0177.0.0.1",  # octal form
        "127.1",  # shortened form
        "01.02.03.04",  # leading zeros
    ],
)
def test_malformed_and_alternate_ipv4_rejected(raw: str) -> None:
    with pytest.raises(IOCValidationError) as exc_info:
        parse_ioc(raw)
    assert exc_info.value.code in {"invalid_ip", "invalid_domain"}


# --- IPv6 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized", "scope"),
    [
        ("2001:4860:4860::8888", "2001:4860:4860::8888", NetworkScope.PUBLIC),
        ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888", NetworkScope.PUBLIC),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", NetworkScope.PUBLIC),
        ("2001:4860:4860::8888".upper(), "2001:4860:4860::8888", NetworkScope.PUBLIC),
        ("[2001:4860:4860::8888]", "2001:4860:4860::8888", NetworkScope.PUBLIC),
        ("::1", "::1", NetworkScope.LOOPBACK),
        ("::", "::", NetworkScope.UNSPECIFIED),
        ("fe80::1", "fe80::1", NetworkScope.LINK_LOCAL),
        ("fc00::1", "fc00::1", NetworkScope.PRIVATE),
        ("fd12:3456:789a::1", "fd12:3456:789a::1", NetworkScope.PRIVATE),
        ("ff02::1", "ff02::1", NetworkScope.MULTICAST),
    ],
)
def test_ipv6_detected_normalized_and_scoped(
    raw: str, normalized: str, scope: NetworkScope
) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.IPV6
    assert ioc.value == normalized
    assert ioc.network_scope is scope


@pytest.mark.parametrize(
    ("raw", "scope"),
    [
        ("::ffff:127.0.0.1", NetworkScope.LOOPBACK),
        ("::ffff:10.0.0.1", NetworkScope.PRIVATE),
        ("::ffff:169.254.169.254", NetworkScope.LINK_LOCAL),
        ("::ffff:8.8.8.8", NetworkScope.PUBLIC),
    ],
)
def test_ipv4_mapped_ipv6_classified_by_embedded_ipv4(raw: str, scope: NetworkScope) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.IPV6
    assert ioc.network_scope is scope


@pytest.mark.parametrize(
    "raw",
    ["2001:db8::g", "1:2:3:4:5:6:7:8:9", "12:::1", "2001:db8:::1", ":::"],
)
def test_malformed_ipv6_rejected(raw: str) -> None:
    error = assert_invalid(raw, "invalid_ip")
    assert error.suspected_type is IOCType.IPV6


def test_ipv6_zone_identifier_rejected() -> None:
    assert_invalid("fe80::1%eth0", "invalid_ip")


# --- Domains ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
        ("example.com.", "example.com"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("my-host.example.org", "my-host.example.org"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("a1.b2.example.io", "a1.b2.example.io"),
    ],
)
def test_domain_detected_and_normalized(raw: str, normalized: str) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.DOMAIN
    assert ioc.value == normalized
    assert ioc.network_scope is NetworkScope.PUBLIC


@pytest.mark.parametrize(
    "raw",
    [
        "-example.com",
        "example-.com",
        "exa mple.com",
        "example..com",
        ".example.com",
        "example.c",
        "example.123",
        "exam!ple.com",
        "example.co_m",
        f"{'a' * 64}.com",
        ".".join(["a" * 63] * 4) + ".com",  # > 253 characters
    ],
)
def test_malformed_domain_rejected(raw: str) -> None:
    with pytest.raises(IOCValidationError) as exc_info:
        parse_ioc(raw)
    assert exc_info.value.code in {"invalid_domain", "invalid_characters"}


@pytest.mark.parametrize(
    ("raw", "scope"),
    [
        ("localhost", NetworkScope.LOOPBACK),
        ("LOCALHOST", NetworkScope.LOOPBACK),
        ("app.localhost", NetworkScope.LOOPBACK),
        ("printer.local", NetworkScope.INTERNAL_HOSTNAME),
        ("metadata.google.internal", NetworkScope.INTERNAL_HOSTNAME),
        ("router.home.arpa", NetworkScope.INTERNAL_HOSTNAME),
    ],
)
def test_localhost_and_internal_hostnames_valid_but_internal(raw: str, scope: NetworkScope) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.DOMAIN
    assert ioc.network_scope is scope
    assert ioc.is_internal


# --- URLs -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized", "scope"),
    [
        ("http://example.com", "http://example.com", NetworkScope.PUBLIC),
        (
            "HTTPS://Example.COM/Path?Q=1#Frag",
            "https://example.com/Path?Q=1#Frag",
            NetworkScope.PUBLIC,
        ),
        ("https://example.com:8443/x", "https://example.com:8443/x", NetworkScope.PUBLIC),
        ("ftp://files.example.org/a.zip", "ftp://files.example.org/a.zip", NetworkScope.PUBLIC),
        ("http://user@example.com/", "http://user@example.com/", NetworkScope.PUBLIC),
        ("http://8.8.8.8/payload", "http://8.8.8.8/payload", NetworkScope.PUBLIC),
        ("http://[2001:4860::8888]:80/", "http://[2001:4860::8888]:80/", NetworkScope.PUBLIC),
        ("http://localhost:8000/", "http://localhost:8000/", NetworkScope.LOOPBACK),
        ("http://127.0.0.1/admin", "http://127.0.0.1/admin", NetworkScope.LOOPBACK),
        ("http://[::1]/", "http://[::1]/", NetworkScope.LOOPBACK),
        ("http://192.168.1.1/", "http://192.168.1.1/", NetworkScope.PRIVATE),
        (
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/",
            NetworkScope.LINK_LOCAL,
        ),
        (
            "http://metadata.google.internal/",
            "http://metadata.google.internal/",
            NetworkScope.INTERNAL_HOSTNAME,
        ),
    ],
)
def test_url_detected_normalized_and_scoped(raw: str, normalized: str, scope: NetworkScope) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is IOCType.URL
    assert ioc.value == normalized
    assert ioc.network_scope is scope


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("http://", "invalid_url"),
        ("http:///path", "invalid_url"),
        ("http://exa mple.com", "invalid_characters"),
        ("http://example.com:99999/", "invalid_url"),
        ("http://example.com:abc/", "invalid_url"),
        ("http://[::1/", "invalid_url"),
        ("http://-bad-.com/", "invalid_url"),
        ("http://example.com\\@evil.com/", "invalid_url"),
        ("http://2130706433/", "invalid_url"),  # integer IPv4 obfuscation
        ("http://0x7f.0.0.1/", "invalid_url"),
        ("http://[fe80::1%25eth0]/", "invalid_url"),
        ("javascript://alert(1)", "unsupported_url_scheme"),
        ("file:///etc/passwd", "unsupported_url_scheme"),
        ("gopher://example.com/", "unsupported_url_scheme"),
        ("://example.com", "unsupported_url_scheme"),
    ],
)
def test_malformed_url_rejected(raw: str, code: str) -> None:
    assert_invalid(raw, code)


def test_scheme_less_javascript_is_not_a_url() -> None:
    assert_invalid("javascript:alert(1)", "unrecognized")


# --- Hashes -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "ioc_type"),
    [(MD5, IOCType.MD5), (SHA1, IOCType.SHA1), (SHA256, IOCType.SHA256)],
)
def test_hash_detected(raw: str, ioc_type: IOCType) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is ioc_type
    assert ioc.value == raw
    assert ioc.network_scope is None
    assert not ioc.is_internal


def test_hash_normalized_to_lowercase() -> None:
    assert parse_ioc(SHA256.upper()).value == SHA256


@pytest.mark.parametrize(
    "raw",
    [
        MD5[:-1],  # 31 chars
        SHA1 + "a",  # 41 chars
        SHA256 + "00",  # 66 chars
        "deadbeefdeadbeef",  # 16 hex chars
    ],
)
def test_wrong_length_hash_rejected(raw: str) -> None:
    assert_invalid(raw, "invalid_hash")


@pytest.mark.parametrize(
    ("raw", "suspected"),
    [
        ("g" + MD5[1:], IOCType.MD5),
        (SHA1[:-1] + "z", IOCType.SHA1),
        ("x" * 64, IOCType.SHA256),
    ],
)
def test_non_hex_hash_rejected(raw: str, suspected: IOCType) -> None:
    error = assert_invalid(raw, "invalid_hash")
    assert error.suspected_type is suspected


# --- Input hygiene ----------------------------------------------------------


@pytest.mark.parametrize("raw", ["", " ", "   ", "\t", "\n", " \t\r\n "])
def test_blank_input_rejected(raw: str) -> None:
    assert_invalid(raw, "empty")


@pytest.mark.parametrize("raw", ["  8.8.8.8  ", "\t8.8.8.8\n", "\n\nexample.com\r\n"])
def test_surrounding_whitespace_is_stripped(raw: str) -> None:
    ioc = parse_ioc(raw)

    assert ioc.value == raw.strip()
    assert ioc.original == raw.strip()


@pytest.mark.parametrize(
    "raw",
    ["8.8.8.8 1.1.1.1", "exa\tmple.com", "example\x00.com", "exam​ple.com", "a\x1b[31m.com"],
)
def test_internal_whitespace_and_control_characters_rejected(raw: str) -> None:
    assert_invalid(raw, "invalid_characters")


def test_oversized_input_rejected() -> None:
    oversized = "http://example.com/" + "a" * MAX_IOC_LENGTH
    assert_invalid(oversized, "too_long")


def test_input_at_max_length_accepted() -> None:
    url = "http://example.com/"
    raw = url + "a" * (MAX_IOC_LENGTH - len(url))

    assert parse_ioc(raw).type is IOCType.URL


def test_oversized_whitespace_padding_rejected_before_processing() -> None:
    assert_invalid(" " * (MAX_IOC_LENGTH + 1), "too_long")


@pytest.mark.parametrize("raw", ["hello", "cafe", "not an ioc", "user@example.com", "a:b"])
def test_unrecognized_input(raw: str) -> None:
    with pytest.raises(IOCValidationError):
        parse_ioc(raw)


# --- Defanged input ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "ioc_type", "normalized"),
    [
        ("hxxp://evil[.]com/x", IOCType.URL, "http://evil.com/x"),
        ("hXXps://evil(.)example[.]com", IOCType.URL, "https://evil.example.com"),
        ("http[://]evil.com", IOCType.URL, "http://evil.com"),
        ("evil[.]com", IOCType.DOMAIN, "evil.com"),
        ("evil[dot]com", IOCType.DOMAIN, "evil.com"),
        ("1.2.3[.]4", IOCType.IPV4, "1.2.3.4"),
        ("2001:4860[:]4860::8888", IOCType.IPV6, "2001:4860:4860::8888"),
    ],
)
def test_defanged_iocs_are_refanged(raw: str, ioc_type: IOCType, normalized: str) -> None:
    ioc = parse_ioc(raw)

    assert ioc.type is ioc_type
    assert ioc.value == normalized
    assert ioc.original == raw
    assert ioc.refanged


def test_fanged_input_not_marked_refanged() -> None:
    assert not parse_ioc("http://evil.com").refanged
