import type { AnalystStatus, FeedSeverity, ThreatCategory } from '../lib/api'
import { ANALYST_STATUSES, CATEGORY_LABELS, SEVERITY_STYLES } from '../lib/feed'

const base = 'inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 whitespace-nowrap'

export function KnownExploitedBadge() {
  return (
    <span
      title="Listed in the CISA Known Exploited Vulnerabilities catalog"
      className={`${base} bg-rose-600/20 font-mono font-bold tracking-wider text-rose-200 ring-rose-500/60`}
    >
      KNOWN EXPLOITED
    </span>
  )
}

export function SeverityBadge({ severity, basis }: { severity: FeedSeverity; basis?: string | null }) {
  const derived = basis?.startsWith('Derived')
  return (
    <span title={basis ?? undefined} className={`${base} capitalize ${SEVERITY_STYLES[severity]}`}>
      {severity}
      {derived && <span className="ml-1 font-normal opacity-70">(derived)</span>}
    </span>
  )
}

export function CategoryBadge({ category }: { category: ThreatCategory }) {
  return <span className={`${base} bg-slate-500/10 text-slate-300 ring-slate-500/30`}>{CATEGORY_LABELS[category]}</span>
}

export function AnalystBadge({ status }: { status: AnalystStatus }) {
  const style = ANALYST_STATUSES.find((s) => s.value === status)
  return style ? <span className={`${base} ${style.tone}`}>{style.label}</span> : null
}

export function EntityChips({ items, tone, max = 6 }: { items: string[]; tone: string; max?: number }) {
  if (items.length === 0) return null
  return (
    <>
      {items.slice(0, max).map((item) => (
        <span key={item} className={`rounded px-1.5 py-0.5 font-mono text-[11px] ring-1 ${tone}`}>
          {item}
        </span>
      ))}
      {items.length > max && <span className="text-[11px] text-slate-500">+{items.length - max}</span>}
    </>
  )
}
