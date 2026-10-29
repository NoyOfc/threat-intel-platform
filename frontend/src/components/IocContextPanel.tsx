import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import {
  ApiError,
  addIocTag,
  addRelationship,
  addToWatchlist,
  deleteRelationship,
  getIocContext,
  removeIocTag,
  type IocContext,
  type RelationType,
} from '../lib/api'
import { formatDateTime } from '../lib/feed'
import { RISK_LEVELS } from '../lib/risk'
import { RELATIONS, originLabel, relationLabel, watchlistStatus } from '../lib/workflow'

type Loaded = { key: string; data?: IocContext; error?: string }

/**
 * Everything stored about one IOC: watchlist state, tags, relationships, feed
 * mentions, and past investigations. Relationships come only from live provider
 * data or the analyst; nothing here resolves or fetches anything.
 */
export default function IocContextPanel({ iocId, showWatchlist = true }: { iocId: number; showWatchlist?: boolean }) {
  const [reloadKey, setReloadKey] = useState(0)
  const [state, setState] = useState<Loaded>({ key: '' })
  const [actionError, setActionError] = useState<string | null>(null)
  const requestKey = `${iocId}#${reloadKey}`

  useEffect(() => {
    const controller = new AbortController()
    getIocContext(iocId, controller.signal)
      .then((data) => setState({ key: requestKey, data }))
      .catch(() => {
        if (!controller.signal.aborted) setState({ key: requestKey, error: 'Could not load IOC context.' })
      })
    return () => controller.abort()
  }, [iocId, requestKey])

  async function mutate(action: () => Promise<IocContext | null>) {
    setActionError(null)
    try {
      const updated = await action()
      if (updated) setState({ key: requestKey, data: updated })
      else setReloadKey((k) => k + 1)
    } catch (error) {
      setActionError(error instanceof ApiError ? error.message : 'Action failed.')
    }
  }

  const ctx = state.data
  if (!ctx) {
    return <p className="text-xs text-slate-500">{state.error ?? 'Loading context…'}</p>
  }

  return (
    <div className="space-y-4 text-sm">
      {actionError && (
        <p role="alert" className="text-xs text-rose-300">
          {actionError}
        </p>
      )}

      {showWatchlist && (
        <section className="flex flex-wrap items-center gap-2">
          <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Watchlist</h3>
          {ctx.watchlist ? (
            <Link
              to="/watchlist"
              className={`rounded px-2 py-0.5 text-xs ring-1 ${watchlistStatus(ctx.watchlist.status).tone}`}
            >
              {watchlistStatus(ctx.watchlist.status).label}
            </Link>
          ) : (
            <button
              type="button"
              onClick={() =>
                void mutate(async () => {
                  await addToWatchlist({ ioc: ctx.ioc.value })
                  return null
                })
              }
              className="rounded-md px-2.5 py-1 text-xs text-accent ring-1 ring-accent/40 hover:bg-accent/10"
            >
              + Add to watchlist
            </button>
          )}
        </section>
      )}

      <TagsSection ctx={ctx} onMutate={mutate} />
      <RelationshipsSection ctx={ctx} onMutate={mutate} />

      {ctx.threat_events.length > 0 && (
        <section>
          <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">
            Mentioned in collected intelligence
          </h3>
          <ul className="mt-1 space-y-1">
            {ctx.threat_events.map((event) => (
              <li key={event.id} className="text-xs">
                <Link to={`/feed/${event.id}`} className="text-slate-200 hover:text-accent">
                  {event.title}
                </Link>
                <span className="text-slate-500"> · {event.source_name}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {ctx.investigations.length > 0 && (
        <section>
          <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Investigation history</h3>
          <ul className="mt-1 space-y-1">
            {ctx.investigations.slice(0, 5).map((item) => (
              <li key={item.id} className="flex items-center gap-2 text-xs">
                <Link to={`/investigations/${item.id}`} className="text-slate-300 hover:text-accent">
                  {formatDateTime(item.created_at)}
                </Link>
                <span className={RISK_LEVELS[item.risk_level].text}>
                  {RISK_LEVELS[item.risk_level].label}
                  {item.risk_score !== null && ` (${item.risk_score})`}
                </span>
                {item.simulated && <span className="text-fuchsia-300/80">simulated</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}

type Mutate = (action: () => Promise<IocContext | null>) => Promise<void>

function TagsSection({ ctx, onMutate }: { ctx: IocContext; onMutate: Mutate }) {
  const [draft, setDraft] = useState('')
  const iocId = ctx.ioc.id!

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!draft.trim()) return
    void onMutate(() => addIocTag(iocId, draft)).then(() => setDraft(''))
  }

  return (
    <section>
      <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Tags</h3>
      <div className="mt-1 flex flex-wrap items-center gap-1">
        {ctx.tags.length === 0 && <span className="text-xs text-slate-600">None</span>}
        {ctx.tags.map((tag) => (
          <span
            key={`${tag.origin}:${tag.name}`}
            title={tag.origin === 'analyst' ? 'Added by analyst' : `From ${tag.origin} provider data`}
            className="inline-flex items-center gap-1 rounded bg-slate-500/10 px-1.5 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-slate-500/30"
          >
            {tag.name}
            {tag.origin === 'analyst' ? (
              <button
                type="button"
                aria-label={`Remove tag ${tag.name}`}
                onClick={() => void onMutate(async () => {
                    await removeIocTag(iocId, tag.name)
                    return null
                  })}
                className="text-slate-500 hover:text-rose-300"
              >
                ×
              </button>
            ) : (
              <span className="text-slate-500">· {tag.origin}</span>
            )}
          </span>
        ))}
        <form onSubmit={handleSubmit} className="inline-flex">
          <input
            aria-label="New tag"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            maxLength={64}
            placeholder="+ tag"
            className="w-24 rounded border border-surface-700 bg-surface-950 px-1.5 py-0.5 text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-accent focus:outline-none"
          />
        </form>
      </div>
    </section>
  )
}

function RelationshipsSection({ ctx, onMutate }: { ctx: IocContext; onMutate: Mutate }) {
  const iocId = ctx.ioc.id!
  const options = RELATIONS.filter((r) => r.from.includes('*') || r.from.includes(ctx.ioc.type))
  const [relation, setRelation] = useState<RelationType>(options[0].value)
  const [target, setTarget] = useState('')
  const placeholder = options.find((o) => o.value === relation)?.placeholder

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!target.trim()) return
    void onMutate(() => addRelationship(iocId, relation, target)).then(() => setTarget(''))
  }

  return (
    <section>
      <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Relationships</h3>
      {ctx.relationships.length === 0 ? (
        <p className="mt-1 text-xs text-slate-600">
          None recorded. Relationships come only from live provider data or analyst entry.
        </p>
      ) : (
        <ul className="mt-1 space-y-1">
          {ctx.relationships.map((rel) => (
            <li key={rel.id} className="flex flex-wrap items-center gap-x-2 text-xs">
              {rel.direction === 'incoming' ? (
                <span className="text-slate-400">
                  ← <span className="font-mono text-slate-200">{rel.ioc_value}</span> {relationLabel(rel.relation).toLowerCase()}
                </span>
              ) : (
                <span className="text-slate-400">
                  → {relationLabel(rel.relation)}: <span className="font-mono text-slate-200">{rel.target_value}</span>
                  {rel.label && <span className="text-slate-500"> ({rel.label})</span>}
                </span>
              )}
              <span className="text-slate-500" title={rel.evidence ?? undefined}>
                {originLabel(rel.origin)}
              </span>
              {rel.origin === 'analyst' && rel.direction === 'outgoing' && (
                <button
                  type="button"
                  onClick={() => void onMutate(async () => {
                    await deleteRelationship(iocId, rel.id)
                    return null
                  })}
                  className="text-slate-500 hover:text-rose-300"
                >
                  remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={handleSubmit} className="mt-2 flex flex-wrap gap-1.5">
        <select
          aria-label="Relationship type"
          value={relation}
          onChange={(e) => setRelation(e.target.value as RelationType)}
          className="rounded border border-surface-700 bg-surface-950 px-1.5 py-1 text-xs text-slate-200"
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <input
          aria-label="Relationship target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          maxLength={200}
          placeholder={placeholder}
          className="min-w-0 flex-1 rounded border border-surface-700 bg-surface-950 px-2 py-1 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={!target.trim()}
          className="rounded bg-surface-800 px-2.5 py-1 text-xs text-slate-200 ring-1 ring-surface-700 hover:bg-surface-700 disabled:opacity-40"
        >
          Add
        </button>
      </form>
    </section>
  )
}
