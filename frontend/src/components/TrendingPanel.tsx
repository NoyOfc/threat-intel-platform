import type { FacetValue, Trending } from '../lib/api'

type Filter = 'cve' | 'malware' | 'threat_actor' | 'technique' | 'q'

const SECTIONS: { key: keyof Trending; label: string; filter: Filter }[] = [
  { key: 'cves', label: 'CVEs', filter: 'cve' },
  { key: 'malware_families', label: 'Malware', filter: 'malware' },
  { key: 'threat_actors', label: 'Threat actors', filter: 'threat_actor' },
  { key: 'attack_techniques', label: 'ATT&CK techniques', filter: 'technique' },
  { key: 'affected_products', label: 'Affected products', filter: 'q' },
]

export default function TrendingPanel({
  trending,
  onSelect,
}: {
  trending: Trending | null
  onSelect: (filter: Filter, value: string) => void
}) {
  return (
    <section className="rounded-lg border border-surface-700 bg-surface-900 p-4">
      <h2 className="text-sm font-semibold text-slate-200">Trending in collected intelligence</h2>
      <p className="mt-1 text-[11px] leading-snug text-slate-500">
        {trending
          ? `Based on ${trending.events_considered} event(s) collected by this instance. Not a measure of global activity.`
          : 'Loading…'}
      </p>
      {trending &&
        SECTIONS.map(({ key, label, filter }) => {
          const values = (trending[key] as FacetValue[]).slice(0, 5)
          if (values.length === 0) return null
          return (
            <div key={key} className="mt-4">
              <h3 className="text-[11px] font-semibold tracking-wider text-slate-500 uppercase">{label}</h3>
              <ul className="mt-1 space-y-0.5">
                {values.map((item) => (
                  <li key={item.value}>
                    <button
                      type="button"
                      onClick={() => onSelect(filter, item.value)}
                      className="flex w-full items-center justify-between gap-2 rounded px-1.5 py-1 text-left text-xs text-slate-300 hover:bg-surface-800"
                    >
                      <span className="truncate font-mono">{item.value}</span>
                      <span className="font-mono text-slate-500">{item.count}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
    </section>
  )
}
