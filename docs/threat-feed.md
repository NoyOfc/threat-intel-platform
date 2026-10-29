# Threat Feed

A defensive intelligence feed built from official public sources, implemented in `backend/app/feeds/` (adapters), `services/feed_refresh.py` (collection), and `services/threat_feed.py` (storage and queries). It is **read-only intelligence**: it never downloads samples or attachments, never runs feed content, and never visits URLs found inside reports.

## Sources

| Source | Endpoint (hardcoded) | Format | Status |
|--------|----------------------|--------|--------|
| CISA Known Exploited Vulnerabilities | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | ✅ Active (refresh ≥ 60 min) |
| Microsoft Threat Intelligence | `https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/` | RSS | ✅ Active (≥ 15 min) |
| Cisco Talos | `https://blog.talosintelligence.com/rss/` | RSS | ✅ Active (≥ 15 min) |
| SentinelOne Labs | `https://www.sentinelone.com/labs/feed/` | RSS | ✅ Active (≥ 15 min) |
| The DFIR Report | `https://thedfirreport.com/feed/` | RSS | ✅ Active (≥ 60 min) |
| CISA Cybersecurity Advisories | `https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml` | RSS | ⏸ **Planned** |

**Why CISA Advisories is planned:** CISA's site protection returns HTTP 403 to automated clients for this feed, even though the KEV catalog on the same domain is served normally. ThreatScope does not disguise its client to get around access controls. The adapter and parser are implemented and tested, but the source is never fetched (`planned_reason` in `feeds/cisa.py`) until an access method CISA permits for automated use is confirmed.

## Collection (`POST /api/feed/refresh`)

- Runs **only when an analyst clicks "Refresh Intelligence"**. Nothing is collected at startup or in the background. `FeedCollector.refresh()` is the single entry point, so a scheduler can call it later.
- All sources are fetched concurrently with **bounded concurrency** (3). Each source has its own **timeout** and a hard ceiling. One source failing never affects the others.
- **Caching:** a source refreshed successfully within its interval is skipped (`fresh`). Otherwise, conditional requests (`If-None-Match` / `If-Modified-Since`) let unchanged feeds answer `304` (`not_modified`).
- **Rate limits:** a `429` pauses that source for `Retry-After` seconds (default 15 minutes, maximum 6 hours).
- A second refresh while one is running returns `409`. `FEEDS_ENABLED=false` disables collection.
- **Deduplication:** event ID is `sha256(source, external_id)` (the GUID, link, or CVE). Re-collecting the same report updates it in place, and duplicate items in one feed collapse. Analyst status and notes are preserved across updates.
- **Storage:** CVEs, entities, tags, and IOCs are normalized child tables, and feed IOCs share the `iocs` table with investigations and the watchlist. Related events (pairs sharing a literal CVE, actor, malware family, technique, or campaign) are stored in `threat_event_relationships` and recomputed for changed events.

## Normalization (`ThreatEvent`)

Fields the source does not provide stay **empty**. Empty means "not identified", never "none".

| Field | How it is populated |
|-------|---------------------|
| title, summary, published_at | From the feed. HTML is reduced to plain text (scripts, styles, and attributes dropped). Summaries are capped at 600 characters for RSS. |
| source_url | The item link, kept only if it is `https` on that source's own host (no credentials, no custom port). The backend never requests it. |
| CVEs | `CVE-YYYY-NNNN` patterns found literally in the text |
| MITRE ATT&CK | Technique IDs (`T1xxx`, `T1xxx.yyy`) found literally |
| Threat actors | Curated names and aliases (`feeds/entities.py`) matched as whole words, plus explicit vendor designations (`APT29`, `Storm-0940`, `UAT-11473`, `UNC3886`, `TA505`). `TA00xx` ATT&CK tactic IDs are excluded. |
| Malware families | Curated names matched as whole words. Ambiguous everyday words are excluded. |
| IOCs | Only indicators the report marks explicitly: **defanged** values (`evil[.]com`, `hxxp://`) and **file hashes**. Each goes through the IOC engine, and internal or non-public values are dropped. Capped at 100. |
| affected_products | KEV vendor and product |
| campaigns, industries, countries | Not provided by current sources, so left empty |
| severity | KEV only, and **derived**: *high* for any KEV entry, *critical* when CISA lists known ransomware campaign use. Always labeled "Derived". Other sources publish no severity, so it is left empty. |

## CISA KEV

- **KNOWN EXPLOITED** is shown only for entries that come from the KEV catalog. It is never inferred from a CVE being mentioned.
- Preserved exactly as published: CVE, vendor, product, vulnerability name, date added, required action, due date, known ransomware campaign use, notes (shown as text), and CWEs.
- The detail page marks other events' CVEs with **· KEV** when that CVE is in the locally collected catalog.

## Trending

`GET /api/feed/trending?window=…` counts CVEs, malware, actors, ATT&CK techniques, and affected products across events **this instance has collected** in the window. The UI and API label it **"Trending in collected intelligence"**. It is not a measure of global activity.

## Analyst workflow

`PATCH /api/feed/events/{id}/analyst` sets `relevant`, `monitoring`, or `not_relevant`, or clears the status (stored in `threat_analyst_statuses`). Notes are a timestamped list (`POST`/`DELETE /api/feed/events/{id}/notes`, up to 5,000 characters each, kept as text and rendered escaped). Both are stored separately from feed data, so re-collection never changes them.

## IOC handoff

**Investigate IOC** on an event sends that one value to the Investigate page through in-app navigation state, not the URL. External links therefore can't trigger investigations, and a reload doesn't repeat one. Feed IOCs are never investigated automatically.
