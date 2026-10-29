# Security Model

The binding rules live in [`CLAUDE.md`](../CLAUDE.md). This document explains how the design enforces them.

## Assets
- Provider API keys (VirusTotal, AbuseIPDB, OTX)
- Analyst data: investigations, watchlists, notes
- The host running ThreatScope and its internal network

## Untrusted inputs
- Every IOC an analyst submits (IP addresses, domains, URLs, hashes, emails)
- Every threat-feed entry, including titles, bodies, and embedded links
- Every response from a third-party provider

## Threats and controls

| Threat | Control |
|--------|---------|
| **SSRF**: an IOC or feed URL makes the backend reach internal or metadata services | No code path fetches a user- or feed-supplied URL. Provider adapters use fixed base URLs, and IOC values are only URL-encoded parameters. Redirects are not followed. Any future outbound helper must reject loopback, RFC1918, link-local, metadata, and alternate IP encodings, re-checking after DNS resolution. |
| **Malicious content execution** | Passive enrichment only. Nothing is downloaded, executed, or detonated. IOC values never reach a shell, `eval`, or raw SQL. |
| **XSS from feed or provider content** | React escapes text by default. `dangerouslySetInnerHTML` is banned by an ESLint rule. Remote HTML is never rendered. |
| **Secret leakage** | Keys are read only by the backend as `SecretStr`, which stays masked in reprs and logs. The frontend container receives no `.env`. Vite exposes only `VITE_*` variables, and no secret uses that prefix. `.env` is git-ignored. |
| **Container breakout / lateral movement** | Containers run as non-root with `cap_drop: ALL` and `no-new-privileges`. There are no privileged containers, Docker socket mounts, or home-directory mounts. Source code is mounted read-only. Ports bind to `127.0.0.1`. |
| **Supply chain** | The dependency set is small, exact versions are pinned, `npm ci --ignore-scripts` is used, and CI runs with `contents: read`. |
| **IOC processing as an attack path** | `parse_ioc` is pure string processing with no DNS, sockets, or fetches. Private, loopback, and metadata values are accepted as data and labeled `is_internal`, never connected to. `tests/test_ioc_safety.py` blocks the network during processing and statically bans shell, `eval`, and `exec` in the backend, and network clients outside `providers/`. |
| **Obfuscated input** | Whitespace, control, and zero-width characters are rejected. Non-standard IPv4 notations are rejected rather than guessed at. Backslashes in a URL's host part are rejected. Defanged notation is refanged and flagged. |
| **Request abuse / DoS** | Each IOC is capped at 2048 characters, bulk requests at 500 items, and request bodies at 1 MiB with Content-Length required. Validation errors do not echo input back. |
| **Provider adapters as an SSRF path** | Each adapter's API host is a class constant, and every request URL is verified to be `https://<api_host>` before sending. IOC values are only percent-encoded path segments or query values. Redirects are not followed (a 3xx is an error), `trust_env=False` ignores proxy and netrc environment variables, there is a hard timeout per lookup, and responses are capped at 5 MiB. |
| **Leaking internal data to third parties** | IOCs labeled internal (private, loopback, link-local, internal hostnames) are never sent to any provider, even with keys configured. A safety test with a real HTTP client and network blocking proves it. |
| **Credential exposure via providers** | Keys are sent only in request headers, never in URLs. Error messages are fixed strings, logs record exception types only, provider `repr` omits the key, and `/api/providers/status` names the env variable but never any part of its value. Tests assert the key never appears in results, logs, or status output. |
| **Untrusted provider responses** | Only an allowlisted subset of fields is kept. Strings are stripped of control characters and length-capped, and lists are deduplicated and capped. Free-text fields such as report comments and WHOIS data are dropped. |
| **Misleading intelligence** | Demo data is labeled `simulated: true` at the result, enrichment, and risk level, and shown with a distinct SIMULATED badge. Live failures stay failures. When no provider responds, the risk is `unknown`, not 0. |
| **Hostile feed content** | Feed adapters contact only hardcoded https endpoints. Links inside reports never decide destinations, and redirects are not followed. XML containing a DTD or `ENTITY` is rejected before parsing (no XXE, no entity bombs). HTML is reduced to plain text server-side, so scripts, styles, and attributes are dropped, and the UI renders it escaped again. No attachment or sample is ever downloaded. |
| **Untrusted report links** | `source_url` is kept only if it is https on the source's own host, with no userinfo and no custom port. It is rendered as a clearly labeled link that opens only on click, in a new tab, with `noopener noreferrer nofollow`. IOC values and URLs in KEV notes are never links. |
| **Fabricated intelligence** | Entities are extracted only when literally present. KEV status comes only from the KEV catalog, and derived severity is labeled as derived. Trending is explicitly scoped to locally collected data. |
| **Feed IOCs triggering lookups** | Feed IOCs are never investigated automatically. "Investigate IOC" passes one value via router state (not a URL), so links can't trigger provider calls. |
| **Source access controls** | A source that blocks automated access is marked *planned*, not worked around (CISA Advisories RSS). |
| **Fabricated relationships** | IOC relationships and tags are stored only from live, non-simulated provider results or explicit analyst entry, with origin and evidence recorded. Domain → IP is analyst-only, because nothing is resolved. Analyst entries are validated by IOC type, and entering one never contacts the network (tested). |
| **Data integrity** | Foreign keys, unique constraints, and CHECK constraints are enforced, including on SQLite. Migrations are tested for drift and for preserving legacy data. LIKE searches escape wildcards. Notes and tags are stored as text and rendered escaped. |
| **Error-message leakage** | The health check reports `database: error` without exception detail, because connection errors can include the DB URL. |

## Demo mode
With `DEMO_MODE=true`, providers return canned data and make no outbound calls. This is the default, so the project can be run and reviewed without any API keys.
