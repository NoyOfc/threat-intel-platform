import type { ReactNode } from 'react'
import { createBrowserRouter } from 'react-router'
import Layout from './components/Layout'
import { NAV_ITEMS } from './navigation'
import BulkAnalysisPage from './pages/BulkAnalysisPage'
import InvestigatePage from './pages/InvestigatePage'
import NotFound from './pages/NotFound'
import PlaceholderPage from './pages/PlaceholderPage'
import ProvidersPage from './pages/ProvidersPage'

// Sections with a real page; every other nav item renders a placeholder.
const PAGES: Record<string, ReactNode> = {
  '/investigate': <InvestigatePage />,
  '/bulk': <BulkAnalysisPage />,
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
      { path: '*', element: <NotFound /> },
    ],
  },
])
