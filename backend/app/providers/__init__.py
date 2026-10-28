"""Outbound threat-intelligence provider adapters (none implemented yet).

Rules every adapter must follow (see CLAUDE.md "SSRF" and "Threat feeds"):

- The base URL is a constant or configured value for that provider. It is never
  derived from user input, IOC values, or feed content.
- IOC values are passed only as URL-encoded path/query parameters to that fixed
  host. They are never used as a URL to fetch.
- Redirects are not followed.
- When ``Settings.demo_mode`` is true, return canned data and make no network calls.
- API keys come from ``Settings`` (SecretStr) and are never logged or returned.
- Responses are untrusted. Validate them through Pydantic schemas before use.
"""
