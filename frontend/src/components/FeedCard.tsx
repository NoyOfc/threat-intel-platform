import { Link } from 'react-router'
import type { ThreatEvent } from '../lib/api'
import { ENTITY_TONES, timeAgo } from '../lib/feed'
import { AnalystBadge, CategoryBadge, EntityChips, KnownExploitedBadge, SeverityBadge } from './FeedBadges'

export default function FeedCard({ event }: { event: ThreatEvent }) {
  const published = timeAgo(event.published_at)
  return (
    <article className="rounded-lg border border-surface-700 bg-surface-900 p-4 transition hover:border-slate-600">
      <div className="flex flex-wrap items-center gap-1.5">
        {event.known_exploited && <KnownExploitedBadge />}
        {event.severity && <SeverityBadge severity={event.severity} basis={event.severity_basis} />}
        <CategoryBadge category={event.category} />
        {event.analyst_status && <AnalystBadge status={event.analyst_status} />}
      </div>

      <h2 className="mt-2 text-base leading-snug font-semibold text-slate-100">
        <Link to={`/feed/${event.id}`} className="hover:text-accent">
          {event.title}
        </Link>
      </h2>
      {/* Summaries are plain text produced server-side; React escapes them again here. */}
      {event.summary && <p className="mt-1 line-clamp-3 text-sm text-slate-400">{event.summary}</p>}

      <div className="mt-3 flex flex-wrap gap-1">
        <EntityChips items={event.cves} tone={ENTITY_TONES.cve} max={4} />
        <EntityChips items={event.threat_actors} tone={ENTITY_TONES.actor} max={3} />
        <EntityChips items={event.malware_families} tone={ENTITY_TONES.malware} max={3} />
        <EntityChips items={event.attack_techniques} tone={ENTITY_TONES.technique} max={4} />
      </div>

      <footer className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
        <span className="font-medium text-slate-400">{event.source_name}</span>
        {published && <time dateTime={event.published_at ?? undefined}>{published}</time>}
        {event.affected_products.length > 0 && <span>{event.affected_products.join(', ')}</span>}
        {event.iocs.length > 0 && <span>{event.iocs.length} IOC{event.iocs.length === 1 ? '' : 's'}</span>}
      </footer>
    </article>
  )
}
