import type { ProviderResult } from '../lib/api'
import { FAILED_STATUSES, PROVIDER_STATUS_LABELS, REPUTATION_STYLES, formatDate } from '../lib/risk'
import SimulatedBadge from './SimulatedBadge'

function Field({ label, value }: { label: string; value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="font-mono break-all text-slate-300">{value}</dd>
    </>
  )
}

function Chips({ label, items, tone }: { label: string; items: string[]; tone: string }) {
  if (items.length === 0) return null
  return (
    <div className="mt-3">
      <p className="text-xs text-slate-500">{label}</p>
      <div className="mt-1 flex flex-wrap gap-1">
        {items.map((item) => (
          <span key={item} className={`rounded px-1.5 py-0.5 font-mono text-xs ring-1 ${tone}`}>
            {item}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function ProviderResultCard({ result }: { result: ProviderResult }) {
  const responded = result.status === 'ok'
  const failed = FAILED_STATUSES.has(result.status)
  const statusTone = responded
    ? 'text-emerald-300'
    : failed
      ? 'text-rose-300'
      : 'text-slate-500'
  const metadata = Object.entries(result.raw_metadata_safe_subset).filter(([, value]) => value !== null)

  return (
    <article
      className={`rounded-lg border bg-surface-900 p-4 ${
        result.simulated ? 'border-dashed border-fuchsia-400/40' : 'border-surface-700'
      }`}
    >
      <header className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold text-slate-100">{result.display_name}</h3>
        {result.simulated && <SimulatedBadge />}
        <span className={`ml-auto font-mono text-xs ${statusTone}`}>{PROVIDER_STATUS_LABELS[result.status]}</span>
      </header>
      {result.message && <p className="mt-1 text-xs text-slate-500">{result.message}</p>}

      {responded && (
        <>
          <p className={`mt-3 text-sm font-medium capitalize ${REPUTATION_STYLES[result.reputation]}`}>
            {result.reputation}
          </p>
          {/* All provider data is untrusted; it is rendered as escaped text only. */}
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <Field label="Malicious" value={result.malicious_count} />
            <Field label="Suspicious" value={result.suspicious_count} />
            <Field label="Abuse confidence" value={result.confidence !== null ? `${result.confidence}%` : null} />
            <Field label="Reports" value={result.report_count} />
            <Field label="Pulses" value={result.pulse_count} />
            <Field label="Country" value={result.country} />
            <Field label="ASN" value={result.asn !== null ? `AS${result.asn}` : null} />
            <Field label="Organization" value={result.organization} />
            <Field label="First seen" value={formatDate(result.first_seen)} />
            <Field label="Last seen" value={formatDate(result.last_seen)} />
          </dl>
          <Chips label="Tags" items={result.tags} tone="bg-slate-500/10 text-slate-300 ring-slate-500/30" />
          <Chips
            label="Malware families"
            items={result.malware_families}
            tone="bg-rose-500/10 text-rose-300 ring-rose-500/30"
          />
          <Chips
            label="Threat actors"
            items={result.threat_actors}
            tone="bg-orange-500/10 text-orange-300 ring-orange-500/30"
          />
          {metadata.length > 0 && (
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-slate-500 hover:text-slate-300">Metadata</summary>
              <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                {metadata.map(([key, value]) => (
                  <Field key={key} label={key.replaceAll('_', ' ')} value={String(value)} />
                ))}
              </dl>
            </details>
          )}
        </>
      )}
    </article>
  )
}
