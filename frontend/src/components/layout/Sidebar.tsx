import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderGit2,
  Scan,
  Package,
  ShieldAlert,
  Crosshair,
  ShieldCheck,
  Ban,
  Database,
  Settings,
  ChevronLeft,
  ChevronRight,
  Boxes,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n, type MessageKey } from '@/i18n';

interface NavItem {
  labelKey: MessageKey;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { labelKey: 'nav.dashboard', to: '/', icon: LayoutDashboard },
  { labelKey: 'nav.projects', to: '/projects', icon: FolderGit2 },
  { labelKey: 'nav.scans', to: '/scans', icon: Scan },
  { labelKey: 'nav.images', to: '/images', icon: Boxes },
  { labelKey: 'nav.components', to: '/components', icon: Package },
  { labelKey: 'nav.vulnerabilities', to: '/vulnerabilities', icon: ShieldAlert },
  { labelKey: 'nav.matches', to: '/matches', icon: Crosshair },
  { labelKey: 'nav.policies', to: '/policies', icon: ShieldCheck },
  { labelKey: 'nav.suppressions', to: '/suppressions', icon: Ban },
  { labelKey: 'nav.sources', to: '/sources', icon: Database },
  { labelKey: 'nav.settings', to: '/settings', icon: Settings },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  const { t } = useI18n();

  return (
    <aside
      className={cn(
        'bg-soc-surface border-r border-soc-border flex flex-col justify-between transition-all duration-200 z-30 select-none',
        collapsed ? 'w-16' : 'w-56',
      )}
      aria-label={t('nav.sidebarLabel')}
    >
      <div>
        {/* Brand / Logo */}
        <div className="h-14 border-b border-soc-border flex items-center px-3">
          {collapsed ? (
            <img
              src="/brand/local-vuln-ai-icon.png"
              alt="Local Vuln AI"
              className="w-8 h-8 rounded object-cover mx-auto"
            />
          ) : (
            <img
              src="/brand/local-vuln-ai-logo-horizontal.png"
              alt="Local Vuln AI — SecOps Console"
              className="h-10 w-auto max-w-full object-contain object-left"
            />
          )}
        </div>

        {/* Navigation list */}
        <nav className="p-2 space-y-1" aria-label={t('nav.mainLabel')}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const label = t(item.labelKey);
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors',
                    isActive
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                      : 'text-soc-secondary hover:text-soc-primary hover:bg-soc-elevated/60',
                    collapsed && 'justify-center px-0',
                  )
                }
                title={collapsed ? label : undefined}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {!collapsed && <span className="truncate">{label}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Collapse toggle at bottom */}
      <div className="p-2 border-t border-soc-border">
        <button
          onClick={onToggle}
          className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-md text-xs text-soc-secondary hover:text-soc-primary hover:bg-soc-elevated transition-colors"
          aria-label={collapsed ? t('nav.expandSidebar') : t('nav.collapseSidebar')}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <>
              <ChevronLeft className="w-4 h-4" />
              <span className="truncate font-mono text-[11px]">{t('nav.collapseView')}</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
