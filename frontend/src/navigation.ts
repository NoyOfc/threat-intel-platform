export interface NavItem {
  path: string
  label: string
  description: string
}

export const NAV_ITEMS: NavItem[] = [
  { path: '/', label: 'Dashboard', description: 'Overview of recent activity and indicator verdicts.' },
  { path: '/feed', label: 'Threat Feed', description: 'Curated threat intelligence from trusted sources.' },
  { path: '/investigate', label: 'Investigate', description: 'Passively enrich a single indicator of compromise.' },
  { path: '/bulk', label: 'Bulk Analysis', description: 'Enrich a batch of indicators at once.' },
  { path: '/investigations', label: 'Investigations', description: 'Saved cases and their findings.' },
  { path: '/watchlist', label: 'Watchlist', description: 'Indicators you are tracking over time.' },
  { path: '/providers', label: 'Providers', description: 'Status of configured intelligence providers.' },
  { path: '/about', label: 'About', description: 'What ThreatScope is and how it stays safe.' },
]
