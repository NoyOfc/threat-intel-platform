import type { RiskAssessment } from '../lib/api'
import { RISK_LEVELS } from '../lib/risk'
import SimulatedBadge from './SimulatedBadge'

export default function RiskPanel({ risk }: { risk: RiskAssessment }) {
  const style = RISK_LEVELS[risk.level]
  return (
    <div className="rounded-lg border border-surface-700 bg-surface-900 p-5">
      <div className="flex flex-wrap items-start gap-5">
        <div className={`flex h-24 w-24 shrink-0 flex-col items-center justify-center rounded-xl ring-1 ${style.ring}`}>
          <span className={`font-mono text-3xl font-bold ${style.text}`}>{risk.score ?? '—'}</span>
          <span className="text-[10px] tracking-widest text-slate-500 uppercase">/ 100</span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className={`text-lg font-semibold ${style.text}`}>{style.label} risk</h2>
            {risk.simulated && <SimulatedBadge />}
          </div>
          <p className="mt-1 text-sm text-slate-400">{risk.summary}</p>
          {risk.score !== null && (
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-700" aria-hidden>
              <div className={`h-full ${style.bar}`} style={{ width: `${risk.score}%` }} />
            </div>
          )}
          {risk.simulated && (
            <p className="mt-3 text-xs text-fuchsia-300/80">
              This score is computed from simulated demo data, not real threat intelligence.
            </p>
          )}
        </div>
      </div>

      {risk.factors.length > 0 && (
        <div className="mt-5">
          <h3 className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Contributing factors</h3>
          <ul className="mt-2 divide-y divide-surface-700">
            {risk.factors.map((factor) => (
              <li key={factor.signal} className="flex items-start gap-3 py-2 text-sm">
                <span
                  className={`w-12 shrink-0 text-right font-mono font-semibold ${
                    factor.points >= 0 ? 'text-rose-300' : 'text-emerald-300'
                  }`}
                >
                  {factor.points >= 0 ? `+${factor.points}` : factor.points}
                </span>
                <span className="min-w-0">
                  <span className="text-slate-200">{factor.signal}</span>
                  <span className="block text-xs text-slate-500">
                    {factor.detail}
                    {factor.providers.length > 0 && ` · ${factor.providers.join(', ')}`}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
