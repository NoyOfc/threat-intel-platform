"""Defensive threat-intelligence feed adapters.

Rules every adapter follows (enforced in ``base.FeedSource``; see CLAUDE.md
"Threat feeds"):

- Each source's ``endpoint`` is a hardcoded HTTPS URL. Links and URLs inside feed
  content are data only and never decide where the backend connects.
- Redirects are not followed, responses are size-capped, and every fetch has a
  source-specific timeout. Conditional requests (ETag / Last-Modified) cache.
- Feed content is hostile: XML with DTDs/entities is rejected, HTML is reduced to
  plain text, nothing is executed, and no attachment or sample is downloaded.
- ``source_url`` is kept only when it is https on one of the source's own hosts.
- Nothing is invented: entities are extracted only when literally present
  (CVE/ATT&CK IDs, explicitly defanged IOCs or hashes, curated names).
"""
