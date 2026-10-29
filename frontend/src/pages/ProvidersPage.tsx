import { useEffect, useState } from 'react'
import { getProvidersStatus, type ProvidersStatus, type ProviderStatusInfo } from '../lib/api'
import { IOC_TYPE_LABELS } from '../lib/ioc'
import { PROVIDER_STATUS_LABELS } from '../lib/risk'

type State = { kind: 'loading' } | { kind: 'ready'; data: ProvidersStatus } | { kind: 'error' }

const STATUS_STYLES: Record<ProviderStatusInfo['status'], { label: string; tone: string }> = {
  configured: { label: 'Configured', tone: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30' },
  not_configured: { label: 'Not Configured', tone: 'bg-slate-500/10 text-slate-300 ring-slate-500/30' },
  unavailable: { label: 'Unavailable', tone: 'bg-rose-500/10 text-rose-300 ring-rose-500/30' },
}

export default function ProvidersPage() {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    getProvidersStatus(controller.signal)
      .then((data) => setState({ kind: 'ready', data }))
      .catch(() => {
        if (!controller.signal.aborted) setState({ kind: 'error' })
      })
    return () => controller.abort()
  }, [reloadKey])

  return (
    <section className="max-w-5xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Providers</h1>
          <p className="mt-1 text-sm text-slate-400">
            Threat intelligence sources and their configuration. API keys are held by the backend and never shown
            here.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setReloadKey((key) => key + 1)}
          className="rounded-md px-3 py-2 text-sm text-slate-400 ring-1 ring-surface-700 hover:bg-surface-800 hover:text-slate-200"
        >
          Refresh
        </button>
      </header>

      {state.kind === 'loading' && <p className="text-sm text-slate-500">Loading provider status…</p>}
      {state.kind === 'error' && (
        <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          Could not load provider status.
        </div>
      )}
      {state.kind === 'ready' && (
        <>
          {state.data.demo_mode && (
            <div
              role="note"
              className="rounded-lg border border-dashed border-fuchsia-400/50 bg-fuchsia-500/10 px-4 py-3 text-sm text-fuchsia-200"
            >
              <strong className="font-semibold">Demo mode is on.</strong> Investigations use simulated sample data and
              send no requests to any provider, whether or not keys are configured.
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-3">
            {state.data.providers.map((provider) => (
              <ProviderCard key={provider.name} provider={provider} />
            ))}
          </div>
        </>
      )}
    </section>
  )
}

function ProviderCard({ provider }: { provider: ProviderStatusInfo }) {
  const status = STATUS_STYLES[provider.status]
  return (
    <article className="flex flex-col rounded-lg border border-surface-700 bg-surface-900 p-5">
      <header className="flex items-start justify-between gap-2">
        <h2 className="font-semibold text-slate-100">{provider.display_name}</h2>
        <span className={`rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ${status.tone}`}>
          {status.label}
        </span>
      </header>
      <p className="mt-2 text-xs text-slate-400">{provider.detail}</p>

      <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-slate-500">Mode</dt>
        <dd className={`font-mono ${provider.mode === 'simulated' ? 'text-fuchsia-300' : 'text-slate-300'}`}>
          {provider.mode}
        </dd>
        <dt className="text-slate-500">API host</dt>
        <dd className="font-mono break-all text-slate-300">{provider.api_host}</dd>
        <dt className="text-slate-500">Credential</dt>
        <dd className="font-mono break-all text-slate-300">{provider.api_key_env}</dd>
        <dt className="text-slate-500">Last result</dt>
        <dd className="font-mono text-slate-300">
          {provider.last_result ? PROVIDER_STATUS_LABELS[provider.last_result] : '—'}
          {provider.last_checked_at && (
            <span className="block text-slate-500">{new Date(provider.last_checked_at).toLocaleString()}</span>
          )}
        </dd>
      </dl>

      <div className="mt-4 flex flex-wrap gap-1">
        {provider.supported_types.map((type) => (
          <span key={type} className="rounded bg-accent/10 px-1.5 py-0.5 font-mono text-xs text-accent ring-1 ring-accent/30">
            {IOC_TYPE_LABELS[type]}
          </span>
        ))}
      </div>
    </article>
  )
}
