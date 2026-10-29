import { useMemo, useState, type FormEvent } from 'react'
import { ScopeBadge, StatusBadge, TypeBadge } from '../components/IocBadges'
import { ApiError, investigateBulk, type BulkResponse, type IocType } from '../lib/api'
import { IOC_TYPE_LABELS, MAX_BULK_IOCS, splitIocLines } from '../lib/ioc'

type State =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'done'; result: BulkResponse }
  | { kind: 'error'; message: string }

export default function BulkAnalysisPage() {
  const [text, setText] = useState('')
  const [state, setState] = useState<State>({ kind: 'idle' })
  const iocs = useMemo(() => splitIocLines(text), [text])
  const overLimit = iocs.length > MAX_BULK_IOCS

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setState({ kind: 'loading' })
    try {
      setState({ kind: 'done', result: await investigateBulk(iocs) })
    } catch (error) {
      setState({ kind: 'error', message: error instanceof ApiError ? error.message : 'Could not reach the API.' })
    }
  }

  return (
    <section className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-100">Bulk Analysis</h1>
        <p className="mt-1 text-sm text-slate-400">
          Paste up to {MAX_BULK_IOCS} indicators, one per line. Each is validated and typed independently.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="max-w-4xl space-y-3">
        <label htmlFor="bulk-iocs" className="sr-only">
          Indicators, one per line
        </label>
        <textarea
          id="bulk-iocs"
          value={text}
          onChange={(event) => setText(event.target.value)}
          rows={10}
          placeholder={'8.8.8.8\nhxxp://evil[.]example.com/payload\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
          spellCheck={false}
          autoComplete="off"
          className="w-full rounded-md border border-surface-700 bg-surface-900 px-4 py-3 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-accent focus:ring-1 focus:ring-accent focus:outline-none"
        />
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={state.kind === 'loading' || iocs.length === 0 || overLimit}
            className="rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-surface-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {state.kind === 'loading' ? 'Analyzing…' : 'Analyze'}
          </button>
          <button
            type="button"
            onClick={() => {
              setText('')
              setState({ kind: 'idle' })
            }}
            className="rounded-md px-4 py-2.5 text-sm text-slate-400 hover:bg-surface-800 hover:text-slate-200"
          >
            Clear
          </button>
          <span className={`text-xs ${overLimit ? 'text-rose-300' : 'text-slate-500'}`}>
            {iocs.length} / {MAX_BULK_IOCS} indicators
            {overLimit && ' (too many; remove some lines)'}
          </span>
        </div>
      </form>

      {state.kind === 'error' && (
        <div role="alert" className="max-w-4xl rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
          {state.message}
        </div>
      )}
      {state.kind === 'done' && <BulkResults result={state.result} />}
    </section>
  )
}

function BulkResults({ result }: { result: BulkResponse }) {
  const { summary } = result
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 text-xs">
        <Stat label="Total" value={summary.total} />
        <Stat label="Valid" value={summary.valid} tone="text-emerald-300" />
        <Stat label="Invalid" value={summary.invalid} tone="text-rose-300" />
        {Object.entries(summary.by_type).map(([type, count]) => (
          <Stat key={type} label={IOC_TYPE_LABELS[type as IocType]} value={count ?? 0} />
        ))}
      </div>

      <div className="overflow-x-auto rounded-lg border border-surface-700">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface-900 text-xs tracking-wider text-slate-500 uppercase">
            <tr>
              <th className="px-4 py-2 font-medium">#</th>
              <th className="px-4 py-2 font-medium">IOC</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Validation status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-700">
            {result.items.map((item) => (
              <tr key={item.index} className="align-top hover:bg-surface-900/60">
                <td className="px-4 py-2 font-mono text-xs text-slate-500">{item.index + 1}</td>
                {/* Plain text only: IOC values are never rendered as links or HTML. */}
                <td className="max-w-md px-4 py-2 font-mono text-xs break-all text-slate-200">
                  {item.ioc?.value ?? item.input}
                  {item.ioc?.refanged && <span className="ml-2 text-slate-500">(refanged)</span>}
                </td>
                <td className="px-4 py-2 whitespace-nowrap">
                  {item.ioc ? (
                    <span className="flex flex-wrap gap-1">
                      <TypeBadge type={item.ioc.type} />
                      {item.ioc.network_scope && item.ioc.is_internal && <ScopeBadge scope={item.ioc.network_scope} />}
                    </span>
                  ) : (
                    <span className="text-xs text-slate-600">
                      {item.error?.suspected_type ? `${IOC_TYPE_LABELS[item.error.suspected_type]}?` : 'Unknown'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2">
                  <StatusBadge valid={item.valid} />
                  {item.error && <p className="mt-1 text-xs text-rose-300/80">{item.error.message}</p>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Stat({ label, value, tone = 'text-slate-200' }: { label: string; value: number; tone?: string }) {
  return (
    <span className="rounded-md border border-surface-700 bg-surface-900 px-3 py-1.5">
      <span className="text-slate-500">{label}</span> <span className={`font-mono font-semibold ${tone}`}>{value}</span>
    </span>
  )
}
