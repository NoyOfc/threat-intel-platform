import type { RelationType, WatchlistStatus } from './api'

export const WATCHLIST_STATUSES: { value: WatchlistStatus; label: string; tone: string }[] = [
  { value: 'monitoring', label: 'Monitoring', tone: 'bg-sky-500/15 text-sky-200 ring-sky-500/40' },
  { value: 'investigating', label: 'Investigating', tone: 'bg-amber-500/15 text-amber-200 ring-amber-500/40' },
  {
    value: 'confirmed_malicious',
    label: 'Confirmed Malicious',
    tone: 'bg-rose-500/15 text-rose-200 ring-rose-500/40',
  },
  {
    value: 'false_positive',
    label: 'False Positive',
    tone: 'bg-emerald-500/15 text-emerald-200 ring-emerald-500/40',
  },
  { value: 'closed', label: 'Closed', tone: 'bg-slate-500/15 text-slate-300 ring-slate-500/40' },
]

export function watchlistStatus(value: WatchlistStatus) {
  return WATCHLIST_STATUSES.find((s) => s.value === value) ?? WATCHLIST_STATUSES[0]
}

/** Relationship types, with the IOC types each one may start from. */
export const RELATIONS: { value: RelationType; label: string; from: string[]; placeholder: string }[] = [
  { value: 'resolves_to', label: 'Resolves to IP', from: ['domain'], placeholder: '203.0.113.10' },
  { value: 'asn', label: 'Belongs to ASN', from: ['ipv4', 'ipv6'], placeholder: 'AS15169' },
  { value: 'malware', label: 'Malware family', from: ['md5', 'sha1', 'sha256'], placeholder: 'DemoLoader' },
  { value: 'threat_actor', label: 'Threat actor', from: ['*'], placeholder: 'APT29' },
  { value: 'campaign', label: 'Campaign', from: ['*'], placeholder: 'Operation Example' },
]

export function relationLabel(value: RelationType): string {
  return RELATIONS.find((r) => r.value === value)?.label ?? value
}

export function originLabel(origin: string): string {
  return origin === 'analyst' ? 'analyst' : `via ${origin}`
}
