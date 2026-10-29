import { useId, useState, type FormEvent } from 'react'
import type { Note } from '../lib/api'
import { formatDateTime } from '../lib/feed'

/** Timestamped analyst notes. Bodies are rendered as escaped plain text. */
export default function NotesPanel({
  notes,
  onAdd,
  onDelete,
}: {
  notes: Note[]
  onAdd: (body: string) => Promise<void>
  onDelete: (noteId: number) => Promise<void>
}) {
  const fieldId = useId()
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await action()
    } catch {
      setError('Could not save. Try again.')
    } finally {
      setBusy(false)
    }
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!draft.trim()) return
    void run(async () => {
      await onAdd(draft)
      setDraft('')
    })
  }

  return (
    <div className="space-y-2">
      {notes.length === 0 && <p className="text-xs text-slate-600">No notes yet.</p>}
      <ul className="space-y-2">
        {notes.map((note) => (
          <li key={note.id} className="group rounded-md bg-surface-950/60 px-3 py-2 ring-1 ring-surface-700">
            <p className="text-sm whitespace-pre-wrap text-slate-200">{note.body}</p>
            <div className="mt-1 flex items-center justify-between text-[11px] text-slate-500">
              <time dateTime={note.created_at}>{formatDateTime(note.created_at)}</time>
              <button
                type="button"
                disabled={busy}
                onClick={() => void run(() => onDelete(note.id))}
                className="text-slate-500 hover:text-rose-300"
              >
                Delete
              </button>
            </div>
          </li>
        ))}
      </ul>
      <form onSubmit={handleSubmit} className="space-y-2">
        <label className="sr-only" htmlFor={fieldId}>
          Add a note
        </label>
        <textarea
          id={fieldId}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          maxLength={5000}
          rows={3}
          placeholder="Add a note…"
          className="w-full rounded-md border border-surface-700 bg-surface-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-accent focus:outline-none"
        />
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-rose-300">{error}</span>
          <button
            type="submit"
            disabled={busy || !draft.trim()}
            className="rounded-md bg-surface-800 px-3 py-1.5 text-xs text-slate-200 ring-1 ring-surface-700 hover:bg-surface-700 disabled:opacity-40"
          >
            Add note
          </button>
        </div>
      </form>
    </div>
  )
}
