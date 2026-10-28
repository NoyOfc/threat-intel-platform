import { Link } from 'react-router'

export default function NotFound() {
  return (
    <section>
      <h1 className="text-2xl font-semibold text-slate-100">Page not found</h1>
      <Link to="/" className="mt-2 inline-block text-sm text-accent hover:underline">
        Back to Dashboard
      </Link>
    </section>
  )
}
