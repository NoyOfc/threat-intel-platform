import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import InvestigationResults from '../components/InvestigationResults'
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
      {state.kind === 'done' && <InvestigationResults investigation={state.investigation} />}
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
