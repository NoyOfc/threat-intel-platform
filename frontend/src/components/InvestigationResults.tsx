import IocContextPanel from './IocContextPanel'
import { ScopeBadge, TypeBadge } from './IocBadges'
import ProviderResultCard from './ProviderResultCard'
import RiskPanel from './RiskPanel'
import type { Investigation } from '../lib/api'

/** Saved or fresh investigation results. Provider data is untrusted and rendered as text. */
export default function InvestigationResults({ investigation }: { investigation: Investigation }) {
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

      {ioc.id !== null && (
        <section className="rounded-lg border border-surface-700 bg-surface-900 p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Analyst workflow</h2>
          <IocContextPanel iocId={ioc.id} />
        </section>
      )}
    </div>
  )
}
