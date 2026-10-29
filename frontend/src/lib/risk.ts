import type { ProviderResultStatus, Reputation, RiskLevel } from './api'

export const RISK_LEVELS: Record<RiskLevel, { label: string; text: string; ring: string; bar: string }> = {
  critical: { label: 'Critical', text: 'text-rose-300', ring: 'ring-rose-500/40 bg-rose-500/10', bar: 'bg-rose-500' },
  high: { label: 'High', text: 'text-orange-300', ring: 'ring-orange-500/40 bg-orange-500/10', bar: 'bg-orange-500' },
  medium: { label: 'Medium', text: 'text-amber-300', ring: 'ring-amber-500/40 bg-amber-500/10', bar: 'bg-amber-400' },
  low: { label: 'Low', text: 'text-sky-300', ring: 'ring-sky-500/40 bg-sky-500/10', bar: 'bg-sky-400' },
  informational: {
    label: 'Informational',
    text: 'text-slate-300',
    ring: 'ring-slate-500/40 bg-slate-500/10',
    bar: 'bg-slate-400',
  },
  unknown: { label: 'Unknown', text: 'text-slate-400', ring: 'ring-slate-600/40 bg-slate-600/10', bar: 'bg-slate-600' },
}

export const PROVIDER_STATUS_LABELS: Record<ProviderResultStatus, string> = {
  ok: 'Responded',
  not_found: 'No record',
  not_supported: 'Not applicable',
  skipped: 'Skipped',
  not_configured: 'Not configured',
  rate_limited: 'Rate limited',
  auth_error: 'Auth failed',
  timeout: 'Timed out',
  unavailable: 'Unavailable',
  error: 'Error',
}

export const FAILED_STATUSES: ReadonlySet<ProviderResultStatus> = new Set([
  'rate_limited',
  'auth_error',
  'timeout',
  'unavailable',
  'error',
])

export const REPUTATION_STYLES: Record<Reputation, string> = {
  malicious: 'text-rose-300',
  suspicious: 'text-amber-300',
  clean: 'text-emerald-300',
  unknown: 'text-slate-400',
}

export function formatDate(value: string | null): string | null {
  return value ? new Date(value).toLocaleDateString(undefined, { dateStyle: 'medium' }) : null
}
