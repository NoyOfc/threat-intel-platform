import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import InvestigationResults from '../components/InvestigationResults'
import { ApiError, getInvestigation, type Investigation } from '../lib/api'
import { formatDateTime } from '../lib/feed'

type Loaded = { key: string; data?: Investigation; error?: string }

/** Reopens a saved investigation exactly as recorded. No provider is queried again. */
export default function InvestigationDetailPage() {
  const { investigationId = '' } = useParams()
  const navigate = useNavigate()
  const [state, setState] = useState<Loaded>({ key: '' })

  useEffect(() => {
    const controller = new AbortController()
    getInvestigation(investigationId, controller.signal)
      .then((data) => setState({ key: investigationId, data }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setState({
            key: investigationId,
            error:
              error instanceof ApiError && error.status === 404
                ? 'Investigation not found.'
                : 'Could not load investigation.',
          })
        }
      })
    return () => controller.abort()
  }, [investigationId])

  const investigation = state.key === investigationId ? state.data : undefined

  return (
    <section className="max-w-4xl space-y-4">
      <Link to="/investigations" className="text-sm text-slate-400 hover:text-accent">
        ← Investigations
      </Link>
      {state.key !== investigationId && <p className="text-sm text-slate-500">Loading investigation…</p>}
      {state.key === investigationId && state.error && (
        <p role="alert" className="text-rose-300">
          {state.error}
        </p>
      )}
      {investigation && (
        <>
          <header className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-2xl font-semibold text-slate-100">Saved investigation</h1>
              <p className="mt-1 text-xs text-slate-500">
                Recorded {formatDateTime(investigation.created_at)}. Results are shown as they were at that time.
              </p>
            </div>
            <button
              type="button"
              onClick={() => navigate('/investigate', { state: { ioc: investigation.ioc.value } })}
              className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-cyan-300"
            >
              Investigate again
            </button>
          </header>
          <InvestigationResults investigation={investigation} />
        </>
      )}
    </section>
  )
}
