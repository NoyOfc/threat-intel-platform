import type { ReactNode } from 'react'
import { createBrowserRouter } from 'react-router'
import Layout from './components/Layout'
import { NAV_ITEMS } from './navigation'
import BulkAnalysisPage from './pages/BulkAnalysisPage'
import InvestigatePage from './pages/InvestigatePage'
import InvestigationDetailPage from './pages/InvestigationDetailPage'
import InvestigationsPage from './pages/InvestigationsPage'
import NotFound from './pages/NotFound'
import PlaceholderPage from './pages/PlaceholderPage'
import ProvidersPage from './pages/ProvidersPage'
import ThreatEventPage from './pages/ThreatEventPage'
import ThreatFeedPage from './pages/ThreatFeedPage'
import WatchlistPage from './pages/WatchlistPage'

// Sections with a real page; every other nav item renders a placeholder.
const PAGES: Record<string, ReactNode> = {
  '/feed': <ThreatFeedPage />,
  '/investigate': <InvestigatePage />,
  '/bulk': <BulkAnalysisPage />,
  '/investigations': <InvestigationsPage />,
  '/watchlist': <WatchlistPage />,
  '/providers': <ProvidersPage />,
}

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      ...NAV_ITEMS.map((item) => ({
        ...(item.path === '/' ? { index: true } : { path: item.path.slice(1) }),
        element: PAGES[item.path] ?? <PlaceholderPage title={item.label} description={item.description} />,
      })),
      { path: 'feed/:eventId', element: <ThreatEventPage /> },
      { path: 'investigations/:investigationId', element: <InvestigationDetailPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])
