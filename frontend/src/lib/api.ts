// Single entry point for backend calls. Always same-origin relative paths:
// the browser only ever talks to ThreatScope's own backend, never to IOC URLs.

export interface HealthResponse {
  status: 'ok' | 'degraded'
  service: string
  version: string
  database: 'ok' | 'error'
  demo_mode: boolean
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch('/health', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok && response.status !== 503) {
    throw new Error(`Health check failed (${response.status})`)
  }
  return (await response.json()) as HealthResponse
}
