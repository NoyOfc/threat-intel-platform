import type { IocType, NetworkScope } from '../lib/api'
import { IOC_TYPE_LABELS, SCOPE_LABELS } from '../lib/ioc'

const badge = 'inline-flex items-center rounded px-2 py-0.5 font-mono text-xs font-medium ring-1'

export function TypeBadge({ type }: { type: IocType }) {
  return <span className={`${badge} bg-accent/10 text-accent ring-accent/30`}>{IOC_TYPE_LABELS[type]}</span>
}

export function ScopeBadge({ scope }: { scope: NetworkScope }) {
  const tone =
    scope === 'public'
      ? 'bg-slate-500/10 text-slate-300 ring-slate-500/30'
      : 'bg-amber-500/10 text-amber-300 ring-amber-500/30'
  return <span className={`${badge} ${tone}`}>{SCOPE_LABELS[scope]}</span>
}

export function StatusBadge({ valid }: { valid: boolean }) {
  return valid ? (
    <span className={`${badge} bg-emerald-500/10 text-emerald-300 ring-emerald-500/30`}>Valid</span>
  ) : (
    <span className={`${badge} bg-rose-500/10 text-rose-300 ring-rose-500/30`}>Invalid</span>
  )
}
