import { useEffect, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router'
import FeedCard from '../components/FeedCard'
import TrendingPanel from '../components/TrendingPanel'
import {
  ApiError,
  getFeed,
  getFeedSources,
  getTrending,
  refreshFeed,
  type FacetValue,
  type FeedList,
  type FeedSourceInfo,
  type FeedWindow,
  type RefreshResult,
  type Trending,
} from '../lib/api'
import { CATEGORY_LABELS, WINDOWS, formatDateTime } from '../lib/feed'

const TEXT_FILTERS = ['q', 'cve', 'technique'] as const
const SELECT_CLASS =
  'rounded-md border border-surface-700 bg-surface-900 px-2.5 py-1.5 text-sm text-slate-200 focus:border-accent focus:outline-none'

// Results are stored with the request key they belong to, so "loading" is derived
// instead of being set synchronously inside effects.
type Loaded<T> = { key: string; data?: T; error?: string }

export default function ThreatFeedPage() {
  const [params, setParams] = useSearchParams()
  const timeWindow = (params.get('window') as FeedWindow) || '7d'
  const queryKey = params.toString()

  const [feed, setFeed] = useState<Loaded<FeedList>>({ key: '' })
  const [trending, setTrending] = useState<Loaded<Trending>>({ key: '' })
  const [sources, setSources] = useState<FeedSourceInfo[]>([])
  const [reloadKey, setReloadKey] = useState(0)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshResult, setRefreshResult] = useState<RefreshResult | null>(null)
  const [refreshError, setRefreshError] = useState<string | null>(null)

  const requestKey = `${queryKey}#${reloadKey}`
  useEffect(() => {
    const controller = new AbortController()
    const query = new URLSearchParams(queryKey)
    if (!query.get('window')) query.set('window', '7d')
    getFeed(query, controller.signal)
      .then((data) => setFeed({ key: requestKey, data }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setFeed({ key: requestKey, error: error instanceof ApiError ? error.message : 'Could not load the feed.' })
        }
      })
    return () => controller.abort()
  }, [queryKey, requestKey])

  const trendingKey = `${timeWindow}#${reloadKey}`
  useEffect(() => {
    const controller = new AbortController()
    getTrending(timeWindow, controller.signal)
      .then((data) => setTrending({ key: trendingKey, data }))
      .catch(() => undefined)
    getFeedSources(controller.signal)
      .then(setSources)
      .catch(() => undefined)
    return () => controller.abort()
  }, [timeWindow, trendingKey])

  function setFilter(name: string, value: string | null) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    setParams(next)
  }

  async function handleRefresh() {
    setRefreshing(true)
    setRefreshError(null)
    try {
      setRefreshResult(await refreshFeed())
      setReloadKey((key) => key + 1)
    } catch (error) {
      setRefreshError(error instanceof ApiError ? error.message : 'Refresh failed.')
    } finally {
      setRefreshing(false)
    }
  }

  const loading = feed.key !== requestKey
  const facets = feed.data?.facets
  const activeFilters = [...params.keys()].filter((key) => key !== 'window')

  return (
    <section className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Threat Feed</h1>
          <p className="mt-1 text-sm text-slate-400">
            Defensive intelligence from official sources. Content is treated as untrusted and shown as plain text.
          </p>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={refreshing}
          className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-surface-950 transition hover:bg-cyan-300 disabled:opacity-50"
        >
          {refreshing ? 'Refreshing…' : 'Refresh Intelligence'}
        </button>
      </header>

      {refreshError && (
        <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-200">
          {refreshError}
        </div>
      )}
      {refreshResult && <RefreshSummary result={refreshResult} />}

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex overflow-hidden rounded-md ring-1 ring-surface-700" role="group" aria-label="Time window">
          {WINDOWS.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={timeWindow === option.value}
              onClick={() => setFilter('window', option.value === '7d' ? null : option.value)}
              className={`px-3 py-1.5 text-sm ${
                timeWindow === option.value ? 'bg-accent/15 text-accent' : 'bg-surface-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
        <FacetSelect label="Severity" name="severity" values={facets?.severities} params={params} onChange={setFilter} />
        <FacetSelect
          label="Category"
          name="category"
          values={facets?.categories}
          params={params}
          onChange={setFilter}
          format={(v) => CATEGORY_LABELS[v as keyof typeof CATEGORY_LABELS] ?? v}
        />
        <FacetSelect
          label="Source"
          name="source"
          values={facets?.sources}
          params={params}
          onChange={setFilter}
          format={(v) => sources.find((s) => s.name === v)?.display_name ?? v}
        />
        <FacetSelect label="Threat actor" name="threat_actor" values={facets?.threat_actors} params={params} onChange={setFilter} />
        <FacetSelect label="Malware" name="malware" values={facets?.malware_families} params={params} onChange={setFilter} />
        <select
          aria-label="Analyst status"
          value={params.get('analyst_status') ?? ''}
          onChange={(event) => setFilter('analyst_status', event.target.value || null)}
          className={SELECT_CLASS}
        >
          <option value="">Any status</option>
          <option value="relevant">Relevant</option>
          <option value="monitoring">Monitoring</option>
          <option value="not_relevant">Not Relevant</option>
        </select>
      </div>

      <TextFilters key={queryKey} params={params} onApply={setParams} />

      {activeFilters.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {activeFilters.map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setFilter(key, null)}
              className="rounded-full bg-surface-800 px-2.5 py-1 text-slate-300 ring-1 ring-surface-700 hover:text-rose-300"
            >
              {key.replace('_', ' ')}: <span className="font-mono">{params.get(key)}</span> ✕
            </button>
          ))}
          <button type="button" onClick={() => setParams(timeWindow === '7d' ? {} : { window: timeWindow })} className="text-slate-500 hover:text-slate-300">
            Clear all
          </button>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[1fr_20rem]">
        <div className="min-w-0 space-y-3">
          {feed.error && (
            <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-200">
              {feed.error}
            </div>
          )}
          {feed.data && (
            <p className={`text-xs text-slate-500 ${loading ? 'opacity-50' : ''}`}>
              {feed.data.total} event{feed.data.total === 1 ? '' : 's'}
              {feed.data.total > feed.data.items.length && ` (showing ${feed.data.items.length})`}
            </p>
          )}
          {!feed.data && loading && <p className="text-sm text-slate-500">Loading feed…</p>}
          {feed.data && feed.data.items.length === 0 && (
            <div className="rounded-lg border border-dashed border-surface-700 p-10 text-center text-sm text-slate-500">
              {sources.every((s) => !s.last_success_at)
                ? 'No intelligence collected yet. Click "Refresh Intelligence" to fetch from the configured sources.'
                : 'No events match these filters in this time window.'}
            </div>
          )}
          <div className={`space-y-3 ${loading ? 'opacity-50' : ''}`}>
            {feed.data?.items.map((event) => (
              <FeedCard key={event.id} event={event} />
            ))}
          </div>
        </div>

        <aside className="space-y-4">
          <TrendingPanel trending={trending.data ?? null} onSelect={(filter, value) => setFilter(filter, value)} />
          <SourcesPanel sources={sources} />
        </aside>
      </div>
    </section>
  )
}

function FacetSelect({
  label,
  name,
  values = [],
  params,
  onChange,
  format = (value) => value,
}: {
  label: string
  name: string
  values?: FacetValue[]
  params: URLSearchParams
  onChange: (name: string, value: string | null) => void
  format?: (value: string) => string
}) {
  const current = params.get(name) ?? ''
  const options = current && !values.some((v) => v.value === current) ? [{ value: current, count: 0 }, ...values] : values
  return (
    <select
      aria-label={label}
      value={current}
      onChange={(event) => onChange(name, event.target.value || null)}
      className={SELECT_CLASS}
    >
      <option value="">{label}: any</option>
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {format(option.value)} ({option.count})
        </option>
      ))}
    </select>
  )
}

function TextFilters({ params, onApply }: { params: URLSearchParams; onApply: (next: URLSearchParams) => void }) {
  const [values, setValues] = useState(() => Object.fromEntries(TEXT_FILTERS.map((k) => [k, params.get(k) ?? ''])))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    const next = new URLSearchParams(params)
    for (const key of TEXT_FILTERS) {
      const value = values[key].trim()
      if (value) next.set(key, value)
      else next.delete(key)
    }
    onApply(next)
  }

  const input =
    'rounded-md border border-surface-700 bg-surface-900 px-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-accent focus:outline-none'
  return (
    <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
      <input
        aria-label="Search"
        placeholder="Search titles, summaries, entities…"
        maxLength={200}
        value={values.q}
        onChange={(e) => setValues({ ...values, q: e.target.value })}
        className={`${input} min-w-0 flex-1 basis-64`}
      />
      <input
        aria-label="CVE"
        placeholder="CVE-2026-1234"
        maxLength={20}
        value={values.cve}
        onChange={(e) => setValues({ ...values, cve: e.target.value })}
        className={`${input} w-40 font-mono`}
      />
      <input
        aria-label="MITRE ATT&CK technique"
        placeholder="T1059"
        maxLength={12}
        value={values.technique}
        onChange={(e) => setValues({ ...values, technique: e.target.value })}
        className={`${input} w-28 font-mono`}
      />
      <button type="submit" className="rounded-md px-4 py-1.5 text-sm text-slate-200 ring-1 ring-surface-700 hover:bg-surface-800">
        Apply
      </button>
    </form>
  )
}

function RefreshSummary({ result }: { result: RefreshResult }) {
  const tone = (status: string) =>
    status === 'planned'
      ? 'text-slate-500'
      : status === 'updated' || status === 'not_modified' || status === 'fresh'
        ? 'text-emerald-300'
        : 'text-rose-300'
  return (
    <div className="rounded-lg border border-surface-700 bg-surface-900 p-3 text-xs">
      <p className="text-slate-400">Refresh finished {formatDateTime(result.finished_at)}</p>
      <ul className="mt-2 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
        {result.sources.map((s) => (
          <li key={s.source} className="flex justify-between gap-2 rounded bg-surface-800/60 px-2 py-1">
            <span className="text-slate-300">{s.source_name}</span>
            <span className={`font-mono ${tone(s.status)}`} title={s.message ?? undefined}>
              {s.status === 'updated' ? `+${s.new} new · ${s.updated} upd` : s.status.replace('_', ' ')}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function SourcesPanel({ sources }: { sources: FeedSourceInfo[] }) {
  return (
    <section className="rounded-lg border border-surface-700 bg-surface-900 p-4">
      <h2 className="text-sm font-semibold text-slate-200">Sources</h2>
      <ul className="mt-2 space-y-2">
        {sources.map((source) => (
          <li key={source.name} className="text-xs">
            <div className="flex justify-between gap-2">
              <span className="text-slate-300">{source.display_name}</span>
              <span className="font-mono text-slate-500">{source.event_count}</span>
            </div>
            {source.planned_reason ? (
              <p className="text-slate-500">
                <span className="mr-1 rounded bg-surface-800 px-1 font-mono text-[10px] text-slate-400 uppercase">
                  Planned
                </span>
                {source.planned_reason}
              </p>
            ) : (
              <p className={source.last_error ? 'text-rose-300/80' : 'text-slate-500'}>
                {source.last_error ??
                  (source.last_success_at ? `Updated ${formatDateTime(source.last_success_at)}` : 'Not collected yet')}
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}
