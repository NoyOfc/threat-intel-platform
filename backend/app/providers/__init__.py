"""Outbound threat-intelligence provider adapters.

Rules every adapter follows (enforced in ``base.Provider``; see CLAUDE.md "SSRF"):

- The API host is a class constant (``api_host``). It is never derived from user
  input, IOC values, or provider responses, and every request URL is checked to
  be ``https://<api_host>`` before it is sent.
- IOC values appear only as percent-encoded path segments or query parameters.
- Redirects are never followed, and proxy/netrc environment settings are ignored.
- Internal IOCs (private, loopback, link-local, internal hostnames) are never
  sent to third parties.
- When ``Settings.demo_mode`` is true, adapters return deterministic, fictional
  results marked ``simulated=True`` and make no network calls. Live failures are
  never replaced with simulated data.
- API keys are SecretStr, sent only in request headers, and never logged,
  returned, or included in error messages.
- Responses are untrusted. Adapters keep only an allowlisted, sanitized subset.
"""
