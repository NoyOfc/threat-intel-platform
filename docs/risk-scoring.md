# Risk Scoring

Every investigation gets an explainable risk score from 0 to 100, implemented in `backend/app/services/risk.py`. The score is a **sum of weighted, capped signals**, not an average of provider scores. Each signal that contributes is returned as a factor with its points, a reason, and the providers it came from. As a result, every score can be traced back to evidence.

## Levels

| Score | Level |
|-------|-------|
| 80–100 | Critical |
| 60–79 | High |
| 40–59 | Medium |
| 20–39 | Low |
| 0–19 | Informational |
| — | **Unknown**: no provider returned intelligence |

`Unknown` is not the same as safe. It is used when every provider was skipped, not configured, unsupported, or failed. For example, internal IOCs are never sent to providers, so they are always `Unknown`.

## Inputs

Only provider results with status `ok` or `not_found` are considered. Failed lookups (`timeout`, `rate_limited`, `auth_error`, `unavailable`, `error`) contribute nothing and are never replaced with demo data. For each numeric signal, the **strongest** value reported by any provider is used.

## Threat signals

| Signal | Source field | Points |
|--------|--------------|--------|
| Malicious vendor detections | `malicious_count` (VirusTotal) | 1 → 10, 2 → 15, 3–4 → 20, 5–9 → 28, 10–19 → 35, 20+ → **40** |
| Suspicious vendor detections | `suspicious_count` | 1 per detection, max **5** |
| Abuse confidence | `confidence` (AbuseIPDB, 0–100) | `round(confidence × 0.30)`, max **30** |
| Abuse reports | `report_count` | 1+ → 2, 5+ → 4, 25+ → 7, 100+ → **10** |
| Threat intelligence pulses | `pulse_count` (OTX) | 1 → 5, 2+ → 8, 5+ → 12, 10+ → **15** |
| Malware or actor attribution | `malware_families`, `threat_actors` | any → **10** |
| Malicious tags | `tags` containing words like *malware, c2, botnet, phishing, ransomware, trojan, stealer, rat, exploit, apt, cobalt* | 1 → 4, 2 → 6, 3+ → **8** |

## Modifiers

These are applied **only if at least one threat signal fired**, because they amplify evidence and never create risk on their own. A clean indicator seen yesterday is still clean.

| Modifier | Rule | Points |
|----------|------|--------|
| Provider agreement | Number of responding providers whose reputation is malicious or suspicious | 2 → +10, 3+ → **+15** |
| Recent observation | Most recent `last_seen` across providers | ≤7 days → +10, ≤30 → +7, ≤90 → +4, >365 → **−5** (stale) |

One adjustment applies regardless of threat signals:

| Adjustment | Rule | Points |
|------------|------|--------|
| Allowlisted | A provider marks the indicator as allowlisted (AbuseIPDB `isWhitelisted`) | **−15** |

The final score is `clamp(sum of factor points, 0, 100)`. Factors are returned sorted by points, highest first. When the score isn't clamped, the factor points sum exactly to the score.

## Why weighted sums instead of averages

Averaging dilutes strong evidence. If VirusTotal reports 25 malicious detections and OTX simply has no pulses, an average would roughly halve the risk. With weighted sums, missing or empty data from one provider never lowers what another provider found, while independent agreement explicitly raises confidence.

## Provider reputations (used for agreement)

| Provider | Malicious | Suspicious | Clean |
|----------|-----------|------------|-------|
| VirusTotal | ≥3 malicious detections | ≥1 malicious or ≥2 suspicious | otherwise, if any engine reported |
| AbuseIPDB | confidence ≥75 | confidence ≥25 | otherwise, or allowlisted |
| OTX | pulses with malware/actor attribution | any pulse | (no "clean": absence from OTX proves nothing) |

## Worked example

| Factor | Points |
|--------|--------|
| 10 malicious vendor detections | +35 |
| 80% abuse confidence | +24 |
| 30 abuse reports | +7 |
| 2 providers agree | +10 |
| **Score** | **76 (High)** |

This exact case is covered by `tests/test_providers_api.py::test_live_investigation_scores_real_responses`.

## Demo mode

With `DEMO_MODE=true`, results are deterministic sample data, and both the results and the assessment are marked `simulated: true`. The score is computed by the same algorithm, but it reflects fictional data, and the UI labels it as such.
