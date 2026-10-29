import type { AnalystStatus, FeedSeverity, FeedWindow, ThreatCategory } from './api'

export const WINDOWS: { value: FeedWindow; label: string }[] = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

export const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  exploited_vulnerability: 'Exploited vulnerability',
  advisory: 'Advisory',
  threat_research: 'Threat research',
  incident_report: 'Incident report',
}

export const SEVERITY_STYLES: Record<FeedSeverity, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  low: 'bg-sky-500/15 text-sky-300 ring-sky-500/40',
}

export const ANALYST_STATUSES: { value: AnalystStatus; label: string; tone: string }[] = [
  { value: 'relevant', label: 'Relevant', tone: 'bg-rose-500/15 text-rose-200 ring-rose-500/40' },
  { value: 'monitoring', label: 'Monitoring', tone: 'bg-amber-500/15 text-amber-200 ring-amber-500/40' },
  { value: 'not_relevant', label: 'Not Relevant', tone: 'bg-slate-500/15 text-slate-300 ring-slate-500/40' },
]

export function analystLabel(status: AnalystStatus | null): string | null {
  return ANALYST_STATUSES.find((s) => s.value === status)?.label ?? null
}

export function timeAgo(value: string | null): string | null {
  if (!value) return null
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000)
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))}m ago`
  if (seconds < 86_400) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86_400)}d ago`
}

export function formatDateTime(value: string | null): string | null {
  return value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : null
}

/** Hostname for labeling an external link. The URL itself is validated by the backend. */
export function hostOf(url: string): string | null {
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' ? parsed.host : null
  } catch {
    return null
  }
}

export const ENTITY_TONES = {
  cve: 'bg-violet-500/10 text-violet-300 ring-violet-500/30',
  actor: 'bg-orange-500/10 text-orange-300 ring-orange-500/30',
  malware: 'bg-rose-500/10 text-rose-300 ring-rose-500/30',
  technique: 'bg-sky-500/10 text-sky-300 ring-sky-500/30',
  product: 'bg-slate-500/10 text-slate-300 ring-slate-500/30',
  tag: 'bg-slate-500/10 text-slate-400 ring-slate-600/30',
}
