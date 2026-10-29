import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { TypeBadge } from '../components/IocBadges'
import IocContextPanel from '../components/IocContextPanel'
import NotesPanel from '../components/NotesPanel'
import {
  ApiError,
  addToWatchlist,
  addWatchlistNote,
  deleteWatchlistNote,
  getWatchlist,
  removeFromWatchlist,
  updateWatchlistStatus,
  type WatchlistEntry,
  type WatchlistStatus,
} from '../lib/api'
import { formatDateTime } from '../lib/feed'
import { RISK_LEVELS } from '../lib/risk'
import { WATCHLIST_STATUSES, watchlistStatus } from '../lib/workflow'

type Loaded = { key: string; total?: number; items?: WatchlistEntry[]; error?: string }

export default function WatchlistPage() {
  const [params, setParams] = useSearchParams()
  const [reloadKey, setReloadKey] = useState(0)
  const [state, setState] = useState<Loaded>({ key: '' })
  const requestKey = `${params.toString()}#${reloadKey}`

  useEffect(() => {
    const controller = new AbortController()
    getWatchlist(new URLSearchParams(requestKey.split('#')[0]), controller.signal)
      .then((data) => setState({ key: requestKey, ...data }))
      .catch(() => {
        if (!controller.signal.aborted) setState({ key: requestKey, error: 'Could not load the watchlist.' })
      })
    return () => controller.abort()
  }, [requestKey])

  const reload = () => setReloadKey((k) => k + 1)
  const replaceEntry = (updated: WatchlistEntry) =>
    setState((prev) => ({ ...prev, items: prev.items?.map((e) => (e.id === updated.id ? updated : e)) }))

  function setFilter(name: string, value: string | null) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    setParams(next)
  }

  return (
    <section className="space-y-5">
      <header>
        <h1 className="text-2xl font-semibold text-slate-100">Watchlist</h1>
        <p className="mt-1 text-sm text-slate-400">
          Indicators you are tracking. Adding an IOC never investigates or contacts it.
        </p>
      </header>

      <AddForm onAdded={reload} />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by status">
        <FilterChip label="All" active={!params.get('status')} onClick={() => setFilter('status', null)} />
        {WATCHLIST_STATUSES.map((s) => (
          <FilterChip
            key={s.value}
            label={s.label}
            active={params.get('status') === s.value}
            onClick={() => setFilter('status', s.value)}
          />
        ))}
      </div>

      {state.error && (
        <p role="alert" className="text-sm text-rose-300">
          {state.error}
        </p>
      )}
      {state.items?.length === 0 && (
        <div className="rounded-lg border border-dashed border-surface-700 p-10 text-center text-sm text-slate-500">
          Nothing here yet. Add an IOC above, or use “Add to watchlist” on an investigation.
        </div>
      )}
      <ul className="space-y-3">
        {state.items?.map((entry) => (
          <EntryCard key={entry.id} entry={entry} onChange={replaceEntry} onRemoved={reload} />
        ))}
      </ul>
    </section>
  )
}

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs ring-1 ${
        active ? 'bg-accent/15 text-accent ring-accent/40' : 'text-slate-400 ring-surface-700 hover:text-slate-200'
      }`}
    >
      {label}
    </button>
  )
}

function AddForm({ onAdded }: { onAdded: () => void }) {
  const [ioc, setIoc] = useState('')
  const [status, setStatus] = useState<WatchlistStatus>('monitoring')
  const [tags, setTags] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await addToWatchlist({
        ioc,
        status,
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      })
      setIoc('')
      setTags('')
      onAdded()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not add.')
    } finally {
      setBusy(false)
    }
  }

  const input =
    'rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-accent focus:outline-none'
  return (
    <form onSubmit={handleSubmit} className="rounded-lg border border-surface-700 bg-surface-900 p-4">
      <div className="flex flex-wrap gap-2">
        <input
          aria-label="IOC to watch"
          value={ioc}
          onChange={(e) => setIoc(e.target.value)}
          maxLength={2048}
          placeholder="IP, domain, URL, or hash (defanged OK)"
          autoComplete="off"
          spellCheck={false}
          className={`${input} min-w-0 flex-1 basis-72 font-mono`}
        />
        <select aria-label="Initial status" value={status} onChange={(e) => setStatus(e.target.value as WatchlistStatus)} className={input}>
          {WATCHLIST_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
        <input
          aria-label="Tags, comma separated"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          placeholder="tags, comma separated"
          className={`${input} w-56`}
        />
        <button
          type="submit"
          disabled={busy || !ioc.trim()}
          className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-cyan-300 disabled:opacity-40"
        >
          Add to watchlist
        </button>
      </div>
      {error && (
        <p role="alert" className="mt-2 text-xs text-rose-300">
          {error}
        </p>
      )}
    </form>
  )
}

function EntryCard({
  entry,
  onChange,
  onRemoved,
}: {
  entry: WatchlistEntry
  onChange: (entry: WatchlistEntry) => void
  onRemoved: () => void
}) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const status = watchlistStatus(entry.status)
  const latest = entry.latest_investigation

  async function guard(action: () => Promise<void>) {
    setError(null)
    try {
      await action()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Action failed.')
    }
  }

  return (
    <li className="rounded-lg border border-surface-700 bg-surface-900 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <TypeBadge type={entry.ioc.type} />
        {/* IOC values are plain text, never links to the indicator. */}
        <span className="min-w-0 flex-1 font-mono text-sm break-all text-slate-100">{entry.ioc.value}</span>
        <select
          aria-label="Status"
          value={entry.status}
          onChange={(e) => void guard(async () => onChange(await updateWatchlistStatus(entry.id, e.target.value as WatchlistStatus)))}
          className={`rounded px-2 py-1 text-xs ring-1 ${status.tone} bg-surface-950`}
        >
          {WATCHLIST_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
        <span>Updated {formatDateTime(entry.updated_at)}</span>
        {latest ? (
          <Link to={`/investigations/${latest.id}`} className="hover:text-accent">
            Last investigated {formatDateTime(latest.created_at)} ·{' '}
            <span className={RISK_LEVELS[latest.risk_level].text}>{RISK_LEVELS[latest.risk_level].label}</span>
            {latest.simulated && ' (simulated)'}
          </Link>
        ) : (
          <span>Not investigated yet</span>
        )}
        {entry.tags.length > 0 && <span>Tags: {entry.tags.map((t) => t.name).join(', ')}</span>}
        <span>
          {entry.notes.length} note{entry.notes.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="rounded px-2.5 py-1 text-slate-300 ring-1 ring-surface-700 hover:bg-surface-800"
        >
          {expanded ? 'Hide details' : 'Notes, tags & relationships'}
        </button>
        <button
          type="button"
          onClick={() => navigate('/investigate', { state: { ioc: entry.ioc.value } })}
          className="rounded px-2.5 py-1 text-accent ring-1 ring-accent/40 hover:bg-accent/10"
        >
          Investigate
        </button>
        {confirmRemove ? (
          <span className="inline-flex items-center gap-2">
            <span className="text-slate-400">Remove from watchlist? Notes on this entry are deleted.</span>
            <button
              type="button"
              onClick={() =>
                void guard(async () => {
                  await removeFromWatchlist(entry.id)
                  onRemoved()
                })
              }
              className="rounded px-2.5 py-1 text-rose-200 ring-1 ring-rose-500/50 hover:bg-rose-500/10"
            >
              Remove
            </button>
            <button type="button" onClick={() => setConfirmRemove(false)} className="text-slate-400 hover:text-slate-200">
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            onClick={() => setConfirmRemove(true)}
            className="rounded px-2.5 py-1 text-slate-400 ring-1 ring-surface-700 hover:text-rose-300"
          >
            Remove
          </button>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-2 text-xs text-rose-300">
          {error}
        </p>
      )}

      {expanded && entry.ioc.id !== null && (
        <div className="mt-4 grid gap-5 border-t border-surface-700 pt-4 lg:grid-cols-2">
          <div>
            <h3 className="mb-2 text-xs font-semibold tracking-wider text-slate-500 uppercase">Notes</h3>
            <NotesPanel
              notes={entry.notes}
              onAdd={async (body) => onChange(await addWatchlistNote(entry.id, body))}
              onDelete={async (noteId) => {
                await deleteWatchlistNote(entry.id, noteId)
                onChange({ ...entry, notes: entry.notes.filter((n) => n.id !== noteId) })
              }}
            />
          </div>
          {/* Keyed so tag/relationship changes refresh with the entry. */}
          <IocContextPanel key={entry.updated_at} iocId={entry.ioc.id} showWatchlist={false} />
        </div>
      )}
    </li>
  )
}
