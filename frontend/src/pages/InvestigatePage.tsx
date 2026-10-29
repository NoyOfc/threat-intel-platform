import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { ScopeBadge, TypeBadge } from '../components/IocBadges'
import ProviderResultCard from '../components/ProviderResultCard'
import RiskPanel from '../components/RiskPanel'
import { ApiError, investigate, type Investigation } from '../lib/api'
import { IOC_TYPE_LABELS, MAX_IOC_LENGTH } from '../lib/ioc'

type State =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'done'; investigation: Investigation }
  | { kind: 'error'; error: ApiError }

function toError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError(0, 'network_error', 'Could not reach the API.')
}

export default function InvestigatePage() {
  // "Investigate IOC" from the Threat Feed hands one value over via router state (not the URL),
  // so external links can't trigger investigations and a reload doesn't repeat one.
  const location = useLocation()
  const navigate = useNavigate()
  const handoff = (location.state as { ioc?: unknown } | null)?.ioc
  const handedOff = typeof handoff === 'string' ? handoff.slice(0, MAX_IOC_LENGTH) : null
  const started = useRef(false)

  const [value, setValue] = useState(handedOff ?? '')
  const [state, setState] = useState<State>(handedOff ? { kind: 'loading' } : { kind: 'idle' })

  useEffect(() => {
    if (!handedOff || started.current) return
    started.current = true
    navigate('.', { replace: true, state: null })
    investigate(handedOff)
      .then((investigation) => setState({ kind: 'done', investigation }))
      .catch((error: unknown) => setState({ kind: 'error', error: toError(error) }))
  }, [handedOff, navigate])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setState({ kind: 'loading' })
    try {
      setState({ kind: 'done', investigation: await investigate(value) })
    } catch (error) {
      setState({ kind: 'error', error: toError(error) })
    }
  }

  return (
    <section className="max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-100">Investigate</h1>
        <p className="mt-1 text-sm text-slate-400">
          Submit an IP, domain, URL, or file hash. The type is detected automatically. Defanged values such as{' '}
          <code className="font-mono text-slate-300">hxxp://evil[.]com</code> are accepted.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="ioc" className="sr-only">
          Indicator of compromise
        </label>
        <input
          id="ioc"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          maxLength={MAX_IOC_LENGTH}
          placeholder="8.8.8.8 · example.com · https://… · sha256"
          autoComplete="off"
          spellCheck={false}
          className="min-w-0 flex-1 rounded-md border border-surface-700 bg-surface-900 px-4 py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-accent focus:ring-1 focus:ring-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={state.kind === 'loading' || value.trim() === ''}
          className="rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-surface-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {state.kind === 'loading' ? 'Investigating…' : 'Investigate'}
        </button>
      </form>

      {state.kind === 'error' && <ErrorPanel error={state.error} />}
      {state.kind === 'done' && <Results investigation={state.investigation} />}
    </section>
  )
}

function ErrorPanel({ error }: { error: ApiError }) {
  const suspected = error.details?.suspected_type as keyof typeof IOC_TYPE_LABELS | undefined
  return (
    <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm">
      <p className="font-medium text-rose-200">{error.message}</p>
      {suspected && IOC_TYPE_LABELS[suspected] && (
        <p className="mt-1 text-rose-300/80">Looks like it may be a {IOC_TYPE_LABELS[suspected]}.</p>
      )}
      <p className="mt-1 font-mono text-xs text-rose-300/60">{error.code}</p>
    </div>
  )
}

function Results({ investigation }: { investigation: Investigation }) {
  const { ioc, enrichment } = investigation
  return (
    <div className="space-y-4">
      {enrichment.simulated && (
        <div
          role="note"
          className="rounded-lg border border-dashed border-fuchsia-400/50 bg-fuchsia-500/10 px-4 py-3 text-sm text-fuchsia-200"
        >
          <strong className="font-semibold">Demo mode.</strong> Provider results below are simulated, deterministic
          sample data. They are not real threat intelligence. Set <code className="font-mono">DEMO_MODE=false</code>{' '}
          and configure API keys for live results.
        </div>
      )}

      <RiskPanel risk={investigation.risk} />

      <div className="rounded-lg border border-surface-700 bg-surface-900 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <TypeBadge type={ioc.type} />
          {ioc.network_scope && <ScopeBadge scope={ioc.network_scope} />}
          <span className="ml-auto text-xs text-slate-500">Indicator</span>
        </div>
        {/* Rendered as plain text, never as a link: IOC URLs are data, not destinations. */}
        <p className="mt-3 font-mono text-lg break-all text-slate-100">{ioc.value}</p>
        {ioc.refanged && (
          <p className="mt-1 text-xs text-slate-500">
            Refanged from <span className="font-mono break-all text-slate-400">{ioc.original}</span>
          </p>
        )}
        {ioc.is_internal && (
          <p className="mt-3 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            Non-public address or hostname. It is valid as indicator data and is recorded only. It was not sent to
            any third-party provider, and submitted indicators are never connected to.
          </p>
        )}
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
          <dt className="text-slate-500">Investigation ID</dt>
          <dd className="font-mono break-all text-slate-400">{investigation.id}</dd>
          <dt className="text-slate-500">Created</dt>
          <dd className="font-mono text-slate-400">{new Date(investigation.created_at).toLocaleString()}</dd>
        </dl>
      </div>

      <section>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-200">Provider results</h2>
          <span className="font-mono text-xs text-slate-500">enrichment: {enrichment.status.replace('_', ' ')}</span>
        </div>
        <div className="mt-2 grid gap-3 lg:grid-cols-3">
          {enrichment.results.map((result) => (
            <ProviderResultCard key={result.provider} result={result} />
          ))}
        </div>
      </section>
    </div>
  )
}
