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
| **Error-message leakage** | The health check reports `database: error` without exception detail, because connection errors can include the DB URL. |

## Demo mode
With `DEMO_MODE=true`, providers return canned data and make no outbound calls. This is the default, so the project can be run and reviewed without any API keys.
