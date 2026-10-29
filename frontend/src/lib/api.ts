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

export interface Investigation {
  id: string
  created_at: string
  status: 'validated'
  ioc: Ioc
  enrichment: { status: 'not_started'; results: unknown[] }
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

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
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

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch('/health', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok && response.status !== 503) {
    throw new Error(`Health check failed (${response.status})`)
  }
  return (await response.json()) as HealthResponse
}

export function investigate(ioc: string): Promise<Investigation> {
  return postJson('/api/investigate', { ioc })
}

export function investigateBulk(iocs: string[]): Promise<BulkResponse> {
  return postJson('/api/investigate/bulk', { iocs })
}
