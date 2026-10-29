import { useEffect, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { CategoryBadge, EntityChips, KnownExploitedBadge, SeverityBadge } from '../components/FeedBadges'
import { TypeBadge } from '../components/IocBadges'
import {
  ApiError,
  getThreatEvent,
  updateAnalyst,
  type AnalystStatus,
  type ThreatEvent,
  type ThreatEventDetail,
} from '../lib/api'
import { ANALYST_STATUSES, ENTITY_TONES, formatDateTime, hostOf } from '../lib/feed'

type Loaded = { key: string; data?: ThreatEventDetail; error?: string }

export default function ThreatEventPage() {
  const { eventId = '' } = useParams()
  const [state, setState] = useState<Loaded>({ key: '' })

  useEffect(() => {
    const controller = new AbortController()
    getThreatEvent(eventId, controller.signal)
      .then((data) => setState({ key: eventId, data }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setState({
            key: eventId,
            error: error instanceof ApiError && error.status === 404 ? 'Threat event not found.' : 'Could not load event.',
          })
        }
      })
    return () => controller.abort()
  }, [eventId])

  if (state.key !== eventId) return <p className="text-sm text-slate-500">Loading event…</p>
  if (state.error || !state.data) {
    return (
      <section className="space-y-3">
        <BackLink />
        <p role="alert" className="text-rose-300">
          {state.error}
        </p>
      </section>
    )
  }
  return <EventDetail event={state.data} />
}

function BackLink() {
  return (
    <Link to="/feed" className="text-sm text-slate-400 hover:text-accent">
      ← Threat Feed
    </Link>
  )
}

function EventDetail({ event }: { event: ThreatEventDetail }) {
  const host = event.source_url ? hostOf(event.source_url) : null
  return (
    <article className="max-w-5xl space-y-5">
      <BackLink />
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {event.known_exploited && <KnownExploitedBadge />}
          {event.severity && <SeverityBadge severity={event.severity} basis={event.severity_basis} />}
          <CategoryBadge category={event.category} />
        </div>
        <h1 className="text-2xl leading-tight font-semibold text-slate-100">{event.title}</h1>
        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500">
          <Meta label="Source" value={event.source_name} />
          <Meta label="Published" value={formatDateTime(event.published_at) ?? 'Not provided'} />
          <Meta label="Collected" value={formatDateTime(event.collected_at)} />
        </dl>
        {event.severity_basis && <p className="text-xs text-slate-500">Severity basis: {event.severity_basis}</p>}
        {event.source_url && host && (
          <p className="text-sm">
            {/* Opens only on click, in a new tab, with no referrer or opener access. */}
            <a
              href={event.source_url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              referrerPolicy="no-referrer"
              className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-accent ring-1 ring-accent/40 hover:bg-accent/10"
            >
              Open original report on {host} ↗
            </a>
            <span className="ml-2 text-xs text-slate-500">External link · opens a new tab</span>
          </p>
        )}
      </header>

      <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
        <div className="min-w-0 space-y-5">
          <Section title="Summary">
            <p className="text-sm leading-relaxed whitespace-pre-line text-slate-300">
              {event.summary ?? 'The source did not provide a summary.'}
            </p>
          </Section>

          {event.kev && <KevSection event={event} />}

          <Section title="Intelligence">
            <dl className="space-y-3 text-sm">
              <EntityRow label="Threat actors" items={event.threat_actors} tone={ENTITY_TONES.actor} />
              <EntityRow label="Malware" items={event.malware_families} tone={ENTITY_TONES.malware} />
              <div>
                <dt className="text-xs text-slate-500">CVEs</dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {event.cves.length === 0 && <span className="text-xs text-slate-600">None identified</span>}
                  {event.cves.map((cve) => (
                    <span key={cve} className={`rounded px-1.5 py-0.5 font-mono text-[11px] ring-1 ${ENTITY_TONES.cve}`}>
                      {cve}
                      {event.kev_cves.includes(cve) && (
                        <span className="ml-1 font-bold text-rose-300" title="Confirmed in the CISA KEV catalog">
                          · KEV
                        </span>
                      )}
                    </span>
                  ))}
                </dd>
              </div>
              <EntityRow label="Affected products" items={event.affected_products} tone={ENTITY_TONES.product} />
              <EntityRow label="MITRE ATT&CK" items={event.attack_techniques} tone={ENTITY_TONES.technique} />
              {event.campaigns.length > 0 && <EntityRow label="Campaigns" items={event.campaigns} tone={ENTITY_TONES.tag} />}
              {event.industries.length > 0 && <EntityRow label="Industries" items={event.industries} tone={ENTITY_TONES.tag} />}
              {event.countries.length > 0 && <EntityRow label="Countries" items={event.countries} tone={ENTITY_TONES.tag} />}
              {event.tags.length > 0 && <EntityRow label="Tags" items={event.tags} tone={ENTITY_TONES.tag} />}
            </dl>
            <p className="mt-3 text-[11px] text-slate-600">
              Entities are extracted only when literally present in the source; empty means not identified, not
              absent.
            </p>
          </Section>

          <IocSection event={event} />
        </div>

        <aside className="space-y-5">
          <AnalystPanel key={event.id} event={event} />
          <Section title="Related intelligence">
            {event.related.length === 0 ? (
              <p className="text-xs text-slate-500">No collected events share CVEs, actors, malware, or techniques.</p>
            ) : (
              <ul className="space-y-2">
                {event.related.map((item) => (
                  <li key={item.id} className="text-xs">
                    <Link to={`/feed/${item.id}`} className="text-slate-200 hover:text-accent">
                      {item.title}
                    </Link>
                    <p className="text-slate-500">
                      {item.source_name} · shares {item.shared.slice(0, 3).join(', ')}
                      {item.shared.length > 3 && ` +${item.shared.length - 3}`}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </aside>
      </div>
    </article>
  )
}

function Meta({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-1">
      <dt>{label}:</dt>
      <dd className="text-slate-300">{value}</dd>
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-surface-700 bg-surface-900 p-4">
      <h2 className="mb-2 text-xs font-semibold tracking-wider text-slate-500 uppercase">{title}</h2>
      {children}
    </section>
  )
}

function EntityRow({ label, items, tone }: { label: string; items: string[]; tone: string }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-1 flex flex-wrap gap-1">
        {items.length === 0 ? (
          <span className="text-xs text-slate-600">None identified</span>
        ) : (
          <EntityChips items={items} tone={tone} max={50} />
        )}
      </dd>
    </div>
  )
}

function KevSection({ event }: { event: ThreatEventDetail }) {
  const kev = event.kev!
  const rows: [string, string | null][] = [
    ['CVE', kev.cve],
    ['Vendor', kev.vendor],
    ['Product', kev.product],
    ['Vulnerability', kev.vulnerability_name],
    ['Date added', kev.date_added],
    ['Due date', kev.due_date],
    ['Known ransomware use', kev.known_ransomware_campaign_use],
    ['CWEs', kev.cwes.join(', ') || null],
  ]
  return (
    <section className="rounded-lg border border-rose-500/40 bg-rose-500/5 p-4">
      <div className="mb-3 flex items-center gap-2">
        <KnownExploitedBadge />
        <span className="text-xs text-slate-400">CISA Known Exploited Vulnerabilities catalog</span>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
        {rows
          .filter(([, value]) => value)
          .map(([label, value]) => (
            <div key={label} className="contents">
              <dt className="text-slate-500">{label}</dt>
              <dd className="font-mono break-words text-slate-200">{value}</dd>
            </div>
          ))}
      </dl>
      {kev.required_action && (
        <div className="mt-3">
          <p className="text-xs text-slate-500">Required action</p>
          <p className="mt-1 text-sm text-slate-200">{kev.required_action}</p>
        </div>
      )}
      {kev.notes && (
        <div className="mt-3">
          <p className="text-xs text-slate-500">Notes (as published; links shown as text)</p>
          <p className="mt-1 text-xs break-all text-slate-400">{kev.notes}</p>
        </div>
      )}
    </section>
  )
}

function IocSection({ event }: { event: ThreatEvent }) {
  const navigate = useNavigate()
  return (
    <Section title={`Extracted IOCs (${event.iocs.length})`}>
      {event.iocs.length === 0 ? (
        <p className="text-xs text-slate-500">The source did not explicitly provide indicators.</p>
      ) : (
        <>
          <p className="mb-2 text-[11px] text-slate-500">
            Indicators the report marks explicitly (defanged values and file hashes), shown as text only. Nothing is
            investigated until you choose to.
          </p>
          <div className="max-h-96 overflow-auto rounded border border-surface-700">
            <table className="w-full text-left text-xs">
              <tbody className="divide-y divide-surface-700">
                {event.iocs.map((ioc) => (
                  <tr key={ioc.value}>
                    <td className="px-2 py-1.5">
                      <TypeBadge type={ioc.type} />
                    </td>
                    {/* Plain text: IOC URLs are data, never links. */}
                    <td className="px-2 py-1.5 font-mono break-all text-slate-200">{ioc.value}</td>
                    <td className="px-2 py-1.5 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => navigate('/investigate', { state: { ioc: ioc.value } })}
                        className="rounded px-2 py-1 text-accent ring-1 ring-accent/40 hover:bg-accent/10"
                      >
                        Investigate IOC
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Section>
  )
}

function AnalystPanel({ event }: { event: ThreatEvent }) {
  const [status, setStatus] = useState<AnalystStatus | null>(event.analyst_status)
  const [notes, setNotes] = useState(event.analyst_notes ?? '')
  const [saved, setSaved] = useState<{ at: string | null; error?: string }>({ at: event.analyst_updated_at })
  const [saving, setSaving] = useState(false)

  async function save(next: { status?: AnalystStatus | null; notes?: string }) {
    setSaving(true)
    try {
      const updated = await updateAnalyst(event.id, next)
      setStatus(updated.analyst_status)
      setSaved({ at: updated.analyst_updated_at })
    } catch (error) {
      setSaved((prev) => ({ ...prev, error: error instanceof ApiError ? error.message : 'Could not save.' }))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Section title="Analyst">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Analyst status">
        {ANALYST_STATUSES.map((option) => (
          <button
            key={option.value}
            type="button"
            disabled={saving}
            aria-pressed={status === option.value}
            onClick={() => save({ status: status === option.value ? null : option.value })}
            className={`rounded px-2.5 py-1 text-xs ring-1 ${
              status === option.value ? option.tone : 'text-slate-400 ring-surface-700 hover:text-slate-200'
            }`}
          >
            {option.label}
          </button>
        ))}
      </div>
      <label htmlFor="analyst-notes" className="mt-4 block text-xs text-slate-500">
        Notes
      </label>
      <textarea
        id="analyst-notes"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        maxLength={5000}
        rows={5}
        className="mt-1 w-full rounded-md border border-surface-700 bg-surface-950 px-3 py-2 text-sm text-slate-200 focus:border-accent focus:outline-none"
      />
      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="text-[11px] text-slate-500">
          {saved.error ? (
            <span className="text-rose-300">{saved.error}</span>
          ) : saved.at ? (
            `Saved ${formatDateTime(saved.at)}`
          ) : (
            'Not reviewed'
          )}
        </span>
        <button
          type="button"
          disabled={saving}
          onClick={() => save({ notes })}
          className="rounded-md bg-surface-800 px-3 py-1.5 text-xs text-slate-200 ring-1 ring-surface-700 hover:bg-surface-700 disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save notes'}
        </button>
      </div>
    </Section>
  )
}
