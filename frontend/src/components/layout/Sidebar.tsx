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
  Shield,
  Boxes,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItem {
  name: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { name: 'Dashboard', to: '/', icon: LayoutDashboard },
  { name: 'Projects', to: '/projects', icon: FolderGit2 },
  { name: 'Scans', to: '/scans', icon: Scan },
  { name: 'Images', to: '/images', icon: Boxes },
  { name: 'Components', to: '/components', icon: Package },
  { name: 'Vulnerabilities', to: '/vulnerabilities', icon: ShieldAlert },
  { name: 'Matches', to: '/matches', icon: Crosshair },
  { name: 'Policies', to: '/policies', icon: ShieldCheck },
  { name: 'Suppressions', to: '/suppressions', icon: Ban },
  { name: 'Sources', to: '/sources', icon: Database },
  { name: 'Settings', to: '/settings', icon: Settings },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  return (
    <aside
      className={cn(
        'bg-soc-surface border-r border-soc-border flex flex-col justify-between transition-all duration-200 z-30 select-none',
        collapsed ? 'w-16' : 'w-56',
      )}
      aria-label="Sidebar Navigation"
    >
      <div>
        {/* Brand / Logo */}
        <div className="h-14 border-b border-soc-border flex items-center px-4 justify-between">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="w-8 h-8 rounded bg-blue-600/20 border border-blue-500/40 flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4 text-blue-400" />
            </div>
            {!collapsed && (
              <div className="truncate">
                <span className="font-semibold text-xs text-soc-primary tracking-wide block truncate">
                  Local Vuln AI
                </span>
                <span className="text-[10px] font-mono text-soc-muted uppercase tracking-wider block">
                  SecOps Console
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Navigation list */}
        <nav className="p-2 space-y-1" aria-label="Main Navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
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
                title={collapsed ? item.name : undefined}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {!collapsed && <span className="truncate">{item.name}</span>}
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
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <>
              <ChevronLeft className="w-4 h-4" />
              <span className="truncate font-mono text-[11px]">Collapse View</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
