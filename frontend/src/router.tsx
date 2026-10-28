import { createBrowserRouter } from 'react-router'
import Layout from './components/Layout'
import { NAV_ITEMS } from './navigation'
import NotFound from './pages/NotFound'
import PlaceholderPage from './pages/PlaceholderPage'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      ...NAV_ITEMS.map((item) => ({
        ...(item.path === '/' ? { index: true } : { path: item.path.slice(1) }),
        element: <PlaceholderPage title={item.label} description={item.description} />,
      })),
      { path: '*', element: <NotFound /> },
    ],
  },
])
