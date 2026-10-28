import { useEffect, useState } from 'react'
import { getHealth, type HealthResponse } from '../lib/api'

type State = { kind: 'loading' } | { kind: 'ready'; health: HealthResponse } | { kind: 'error' }

export default function ApiStatus() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    getHealth(controller.signal)
      .then((health) => setState({ kind: 'ready', health }))
      .catch(() => {
        if (!controller.signal.aborted) setState({ kind: 'error' })
      })
    return () => controller.abort()
  }, [])

  const healthy = state.kind === 'ready' && state.health.status === 'ok'
  const label =
    state.kind === 'loading' ? 'Checking API…' : healthy ? 'API online' : 'API unavailable'
  const dot =
    state.kind === 'loading' ? 'bg-slate-500' : healthy ? 'bg-emerald-400' : 'bg-rose-500'

  return (
    <div className="flex items-center gap-3 text-xs text-slate-400">
      {state.kind === 'ready' && state.health.demo_mode && (
        <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-amber-300">
          DEMO MODE
        </span>
      )}
      <span className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${dot}`} aria-hidden />
        {label}
      </span>
    </div>
  )
}
