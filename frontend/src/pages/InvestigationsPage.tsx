import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { TypeBadge } from '../components/IocBadges'
import SimulatedBadge from '../components/SimulatedBadge'
import { getInvestigations, type InvestigationSummary, type IocType, type RiskLevel } from '../lib/api'
import { formatDateTime } from '../lib/feed'
import { IOC_TYPE_LABELS } from '../lib/ioc'
import { RISK_LEVELS } from '../lib/risk'

const PAGE_SIZE = 50
const SELECT =
  'rounded-md border border-surface-700 bg-surface-900 px-2.5 py-1.5 text-sm text-slate-200 focus:border-accent focus:outline-none'

type Loaded = { key: string; total?: number; items?: InvestigationSummary[]; error?: string }

export default function InvestigationsPage() {
  const [params, setParams] = useSearchParams()
  const queryKey = params.toString()
  const [state, setState] = useState<Loaded>({ key: '' })
  const [search, setSearch] = useState(params.get('q') ?? '')
  const offset = Number(params.get('offset') ?? 0) || 0

  useEffect(() => {
    const controller = new AbortController()
    const query = new URLSearchParams(queryKey)
    query.set('limit', String(PAGE_SIZE))
    getInvestigations(query, controller.signal)
      .then((data) => setState({ key: queryKey, ...data }))
      .catch(() => {
        if (!controller.signal.aborted) setState({ key: queryKey, error: 'Could not load investigations.' })
      })
    return () => controller.abort()
  }, [queryKey])

  function setFilter(name: string, value: string | null) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    next.delete('offset')
    setParams(next)
  }

  function handleSearch(event: FormEvent) {
    event.preventDefault()
    setFilter('q', search.trim() || null)
  }

  const loading = state.key !== queryKey
  const total = state.total ?? 0

  return (
    <section className="space-y-5">
      <header>
        <h1 className="text-2xl font-semibold text-slate-100">Investigations</h1>
        <p className="mt-1 text-sm text-slate-400">
          Every investigation is saved. Reopen one to see the results exactly as recorded.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        <form onSubmit={handleSearch} className="flex min-w-0 flex-1 basis-72 gap-2">
          <input
            aria-label="Search IOC value"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            maxLength={200}
            placeholder="Search IOC value…"
            className="min-w-0 flex-1 rounded-md border border-surface-700 bg-surface-900 px-3 py-1.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-accent focus:outline-none"
          />
          <button type="submit" className="rounded-md px-3 py-1.5 text-sm text-slate-200 ring-1 ring-surface-700 hover:bg-surface-800">
            Search
          </button>
        </form>
        <select
          aria-label="IOC type"
          value={params.get('ioc_type') ?? ''}
          onChange={(e) => setFilter('ioc_type', e.target.value || null)}
          className={SELECT}
        >
          <option value="">All types</option>
          {(Object.keys(IOC_TYPE_LABELS) as IocType[]).map((type) => (
            <option key={type} value={type}>
              {IOC_TYPE_LABELS[type]}
            </option>
          ))}
        </select>
        <select
          aria-label="Risk level"
          value={params.get('risk') ?? ''}
          onChange={(e) => setFilter('risk', e.target.value || null)}
          className={SELECT}
        >
          <option value="">Any risk</option>
          {(Object.keys(RISK_LEVELS) as RiskLevel[]).map((level) => (
            <option key={level} value={level}>
              {RISK_LEVELS[level].label}
            </option>
          ))}
        </select>
        <select
          aria-label="Sort"
          value={params.get('sort') ?? 'newest'}
          onChange={(e) => setFilter('sort', e.target.value === 'newest' ? null : e.target.value)}
          className={SELECT}
        >
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
        </select>
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-rose-300">
          {state.error}
        </p>
      )}
      {state.items && (
        <p className="text-xs text-slate-500">
          {total} investigation{total === 1 ? '' : 's'}
        </p>
      )}

      <div className={`overflow-x-auto rounded-lg border border-surface-700 ${loading ? 'opacity-50' : ''}`}>
        <table className="w-full text-left text-sm">
          <thead className="bg-surface-900 text-xs tracking-wider text-slate-500 uppercase">
            <tr>
              <th className="px-4 py-2 font-medium">Date</th>
              <th className="px-4 py-2 font-medium">IOC</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Risk</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-700">
            {state.items?.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-sm text-slate-500">
                  No investigations match. Run one from the Investigate page.
                </td>
              </tr>
            )}
            {state.items?.map((item) => {
              const risk = RISK_LEVELS[item.risk_level]
              return (
                <tr key={item.id} className="hover:bg-surface-900/60">
                  <td className="px-4 py-2 text-xs whitespace-nowrap text-slate-400">{formatDateTime(item.created_at)}</td>
                  {/* IOC values are plain text, never links to the indicator itself. */}
                  <td className="max-w-md px-4 py-2 font-mono text-xs break-all text-slate-200">{item.ioc_value}</td>
                  <td className="px-4 py-2">
                    <TypeBadge type={item.ioc_type} />
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap">
                    <span className={`text-xs font-medium ${risk.text}`}>
                      {risk.label}
                      {item.risk_score !== null && ` · ${item.risk_score}`}
                    </span>
                    {item.simulated && (
                      <span className="ml-2">
                        <SimulatedBadge />
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <Link
                      to={`/investigations/${item.id}`}
                      className="rounded px-2 py-1 text-xs text-accent ring-1 ring-accent/40 hover:bg-accent/10"
                    >
                      Reopen
                    </Link>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setFilter('offset', offset - PAGE_SIZE > 0 ? String(offset - PAGE_SIZE) : null)}
            className="rounded px-2 py-1 ring-1 ring-surface-700 disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => {
              const next = new URLSearchParams(params)
              next.set('offset', String(offset + PAGE_SIZE))
              setParams(next)
            }}
            className="rounded px-2 py-1 ring-1 ring-surface-700 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </section>
  )
}
