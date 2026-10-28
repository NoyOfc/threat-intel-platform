interface Props {
  title: string
  description: string
}

export default function PlaceholderPage({ title, description }: Props) {
  return (
    <section>
      <h1 className="text-2xl font-semibold text-slate-100">{title}</h1>
      <p className="mt-1 text-sm text-slate-400">{description}</p>
      <div className="mt-6 rounded-lg border border-dashed border-surface-700 bg-surface-900 p-10 text-center font-mono text-sm text-slate-500">
        Not implemented yet
      </div>
    </section>
  )
}
