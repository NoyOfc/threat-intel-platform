// Single entry point for backend calls. Always same-origin relative paths:
// the browser only ever talks to ThreatScope's own backend, never to IOC URLs.

export interface HealthResponse {
  status: 'ok' | 'degraded'
  service: string
  version: string
  database: 'ok' | 'error'
  demo_mode: boolean
}

export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256'

export type NetworkScope =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link_local'
  | 'multicast'
  | 'unspecified'
  | 'reserved'
  | 'internal_hostname'

export interface Ioc {
  type: IocType
  value: string
  original: string
  refanged: boolean
  network_scope: NetworkScope | null
  is_internal: boolean
}

export type ProviderResultStatus =
  | 'ok'
  | 'not_found'
  | 'not_supported'
  | 'skipped'
  | 'not_configured'
  | 'rate_limited'
  | 'auth_error'
  | 'timeout'
  | 'unavailable'
  | 'error'

export type Reputation = 'malicious' | 'suspicious' | 'clean' | 'unknown'

export interface ProviderResult {
  provider: string
  display_name: string
  status: ProviderResultStatus
  simulated: boolean
  message: string | null
  reputation: Reputation
  malicious_count: number | null
  suspicious_count: number | null
  confidence: number | null
  report_count: number | null
  pulse_count: number | null
  tags: string[]
  first_seen: string | null
  last_seen: string | null
  country: string | null
  asn: number | null
  organization: string | null
  malware_families: string[]
  threat_actors: string[]
  raw_metadata_safe_subset: Record<string, string | number | boolean | null>
}

export type RiskLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical' | 'unknown'

export interface RiskFactor {
  signal: string
  points: number
  detail: string
  providers: string[]
}

export interface RiskAssessment {
  score: number | null
  level: RiskLevel
  summary: string
  factors: RiskFactor[]
  providers_considered: number
  providers_flagged: number
  simulated: boolean
}

export interface Investigation {
  id: string
  created_at: string
  status: 'completed'
  ioc: Ioc
  enrichment: {
    status: 'completed' | 'partial' | 'failed' | 'no_providers'
    simulated: boolean
    results: ProviderResult[]
  }
  risk: RiskAssessment
}

export interface ProviderStatusInfo {
  name: string
  display_name: string
  status: 'configured' | 'not_configured' | 'unavailable'
  mode: 'live' | 'simulated'
  api_host: string
  api_key_env: string
  supported_types: IocType[]
  last_result: ProviderResultStatus | null
  last_checked_at: string | null
  detail: string
}

export interface ProvidersStatus {
  demo_mode: boolean
  providers: ProviderStatusInfo[]
}

export interface BulkItem {
  index: number
  input: string
  valid: boolean
  ioc: Ioc | null
  error: { code: string; message: string; suspected_type: IocType | null } | null
}

export interface BulkResponse {
  items: BulkItem[]
  summary: { total: number; valid: number; invalid: number; by_type: Partial<Record<IocType, number>> }
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: Record<string, unknown> | null

  constructor(status: number, code: string, message: string, details: Record<string, unknown> | null = null) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
  })
  const payload: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const error = (payload as { error?: { code?: string; message?: string; details?: Record<string, unknown> } })
      ?.error
    throw new ApiError(
      response.status,
      error?.code ?? 'http_error',
      error?.message ?? `Request failed (${response.status})`,
      error?.details ?? null,
    )
  }
  return payload as T
}

function postJson<T>(path: string, body: unknown): Promise<T> {
  return requestJson(path, { method: 'POST', body: JSON.stringify(body) })
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch('/health', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok && response.status !== 503) {
    throw new Error(`Health check failed (${response.status})`)
  }
  return (await response.json()) as HealthResponse
}

export async function getProvidersStatus(signal?: AbortSignal): Promise<ProvidersStatus> {
  const response = await fetch('/api/providers/status', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok) {
    throw new ApiError(response.status, 'http_error', `Could not load provider status (${response.status})`)
  }
  return (await response.json()) as ProvidersStatus
}

export function investigate(ioc: string): Promise<Investigation> {
  return postJson('/api/investigate', { ioc })
}

export function investigateBulk(iocs: string[]): Promise<BulkResponse> {
  return postJson('/api/investigate/bulk', { iocs })
}

// --- Threat feed ------------------------------------------------------------

export type FeedWindow = '24h' | '7d' | '30d'
export type ThreatCategory = 'exploited_vulnerability' | 'advisory' | 'threat_research' | 'incident_report'
export type FeedSeverity = 'critical' | 'high' | 'medium' | 'low'
export type AnalystStatus = 'relevant' | 'monitoring' | 'not_relevant'

export interface KevDetails {
  cve: string
  vendor: string | null
  product: string | null
  vulnerability_name: string | null
  date_added: string | null
  required_action: string | null
  due_date: string | null
  known_ransomware_campaign_use: string | null
  notes: string | null
  cwes: string[]
}

export interface ThreatEvent {
  id: string
  source: string
  source_name: string
  external_id: string
  title: string
  summary: string | null
  source_url: string | null
  published_at: string | null
  collected_at: string
  updated_at: string
  severity: FeedSeverity | null
  severity_basis: string | null
  category: ThreatCategory
  known_exploited: boolean
  kev: KevDetails | null
  threat_actors: string[]
  malware_families: string[]
  campaigns: string[]
  cves: string[]
  attack_techniques: string[]
  affected_products: string[]
  industries: string[]
  countries: string[]
  tags: string[]
  iocs: { type: IocType; value: string }[]
  analyst_status: AnalystStatus | null
  analyst_notes: string | null
  analyst_updated_at: string | null
}

export interface ThreatEventDetail extends ThreatEvent {
  related: { id: string; title: string; source_name: string; published_at: string | null; shared: string[] }[]
  kev_cves: string[]
}

export interface FacetValue {
  value: string
  count: number
}

export interface FeedList {
  window: FeedWindow
  total: number
  items: ThreatEvent[]
  facets: Record<'sources' | 'severities' | 'categories' | 'threat_actors' | 'malware_families', FacetValue[]>
}

export interface Trending {
  window: FeedWindow
  scope: string
  events_considered: number
  cves: FacetValue[]
  malware_families: FacetValue[]
  threat_actors: FacetValue[]
  attack_techniques: FacetValue[]
  affected_products: FacetValue[]
}

export interface RefreshResult {
  started_at: string
  finished_at: string
  sources: {
    source: string
    source_name: string
    status: 'updated' | 'not_modified' | 'fresh' | 'planned' | 'rate_limited' | 'timeout' | 'unavailable' | 'error'
    fetched: number
    new: number
    updated: number
    message: string | null
  }[]
}

export interface FeedSourceInfo {
  name: string
  display_name: string
  endpoint: string
  category: ThreatCategory
  refresh_minutes: number
  planned_reason: string | null
  event_count: number
  last_attempt_at: string | null
  last_success_at: string | null
  last_status: string | null
  last_error: string | null
}

export function getFeed(params: URLSearchParams, signal?: AbortSignal): Promise<FeedList> {
  return requestJson(`/api/feed/events?${params.toString()}`, { signal })
}

export function getThreatEvent(id: string, signal?: AbortSignal): Promise<ThreatEventDetail> {
  return requestJson(`/api/feed/events/${encodeURIComponent(id)}`, { signal })
}

export function updateAnalyst(
  id: string,
  body: { status?: AnalystStatus | null; notes?: string | null },
): Promise<ThreatEvent> {
  return requestJson(`/api/feed/events/${encodeURIComponent(id)}/analyst`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export function getTrending(window: FeedWindow, signal?: AbortSignal): Promise<Trending> {
  return requestJson(`/api/feed/trending?window=${window}`, { signal })
}

export function getFeedSources(signal?: AbortSignal): Promise<FeedSourceInfo[]> {
  return requestJson('/api/feed/sources', { signal })
}

export function refreshFeed(): Promise<RefreshResult> {
  return postJson('/api/feed/refresh', {})
}
