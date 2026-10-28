import { NavLink, Outlet } from 'react-router'
import { NAV_ITEMS } from '../navigation'
import ApiStatus from './ApiStatus'

export default function Layout() {
  return (
    <div className="flex h-full flex-col md:flex-row">
      <aside className="border-b border-surface-700 bg-surface-900 md:w-60 md:shrink-0 md:border-r md:border-b-0">
        <div className="flex items-center gap-2 px-5 py-4">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <span className="font-mono text-lg font-semibold tracking-wide text-slate-100">
            Threat<span className="text-accent">Scope</span>
          </span>
        </div>
        <nav aria-label="Primary" className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:pb-0">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent ring-1 ring-accent/30'
                    : 'text-slate-400 hover:bg-surface-800 hover:text-slate-200'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-surface-700 bg-surface-900/60 px-6 py-3">
          <span className="font-mono text-xs uppercase tracking-widest text-slate-500">
            Passive threat intelligence
          </span>
          <ApiStatus />
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
