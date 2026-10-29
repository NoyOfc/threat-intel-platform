import { useState, type FormEvent } from 'react'
import { ScopeBadge, TypeBadge } from '../components/IocBadges'
import { ApiError, investigate, type Investigation } from '../lib/api'
import { IOC_TYPE_LABELS, MAX_IOC_LENGTH } from '../lib/ioc'

type State =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'done'; investigation: Investigation }
  | { kind: 'error'; error: ApiError }

const PROVIDERS = ['VirusTotal', 'AbuseIPDB', 'AlienVault OTX']

export default function InvestigatePage() {
  const [value, setValue] = useState('')
  const [state, setState] = useState<State>({ kind: 'idle' })

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setState({ kind: 'loading' })
    try {
      setState({ kind: 'done', investigation: await investigate(value) })
    } catch (error) {
      setState({
        kind: 'error',
        error: error instanceof ApiError ? error : new ApiError(0, 'network_error', 'Could not reach the API.'),
      })
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
          {state.kind === 'loading' ? 'Validating…' : 'Investigate'}
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
  const { ioc } = investigation
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-surface-700 bg-surface-900 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <TypeBadge type={ioc.type} />
          {ioc.network_scope && <ScopeBadge scope={ioc.network_scope} />}
          <span className="ml-auto text-xs text-slate-500">Validated</span>
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
            Non-public address or hostname. It is valid as indicator data and is recorded only. ThreatScope never
            connects to submitted indicators.
          </p>
        )}
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
          <dt className="text-slate-500">Investigation ID</dt>
          <dd className="font-mono break-all text-slate-400">{investigation.id}</dd>
          <dt className="text-slate-500">Created</dt>
          <dd className="font-mono text-slate-400">{new Date(investigation.created_at).toLocaleString()}</dd>
        </dl>
      </div>

      <div className="rounded-lg border border-surface-700 bg-surface-900 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Intelligence enrichment</h2>
        <p className="mt-1 text-xs text-slate-500">
          No providers have been queried. Provider integrations arrive in a later phase.
        </p>
        <ul className="mt-4 divide-y divide-surface-700">
          {PROVIDERS.map((name) => (
            <li key={name} className="flex items-center justify-between py-2 text-sm">
              <span className="text-slate-300">{name}</span>
              <span className="font-mono text-xs text-slate-500">Not queried</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
