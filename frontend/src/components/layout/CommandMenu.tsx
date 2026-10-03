import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  LayoutDashboard,
  FolderGit2,
  Scan,
  Package,
  ShieldAlert,
  Crosshair,
  Database,
  Settings,
  X,
  Boxes,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface CommandItem {
  id: string;
  name: string;
  category: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

const commands: CommandItem[] = [
  { id: 'dash', name: 'Go to Dashboard', category: 'Navigation', to: '/', icon: LayoutDashboard },
  { id: 'proj', name: 'Go to Projects', category: 'Navigation', to: '/projects', icon: FolderGit2 },
  { id: 'scan', name: 'Go to Scans', category: 'Navigation', to: '/scans', icon: Scan },
  { id: 'img', name: 'Go to Container Images', category: 'Navigation', to: '/images', icon: Boxes },
  {
    id: 'comp',
    name: 'Go to Components',
    category: 'Navigation',
    to: '/components',
    icon: Package,
  },
  {
    id: 'vuln',
    name: 'Go to Vulnerabilities',
    category: 'Navigation',
    to: '/vulnerabilities',
    icon: ShieldAlert,
  },
  { id: 'match', name: 'Go to Matches', category: 'Navigation', to: '/matches', icon: Crosshair },
  {
    id: 'src',
    name: 'Go to Sources Intelligence',
    category: 'Navigation',
    to: '/sources',
    icon: Database,
  },
  { id: 'sett', name: 'Go to Settings', category: 'Navigation', to: '/settings', icon: Settings },
];

interface CommandMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CommandMenu: React.FC<CommandMenuProps> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = commands.filter(
    (cmd) =>
      cmd.name.toLowerCase().includes(query.toLowerCase()) ||
      cmd.category.toLowerCase().includes(query.toLowerCase()),
  );

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  const handleSelect = (to: string) => {
    navigate(to);
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filtered.length) % (filtered.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filtered[selectedIndex]) {
        handleSelect(filtered[selectedIndex].to);
      }
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command Palette"
    >
      <div
        className="w-full max-w-lg bg-soc-surface border border-soc-border rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <div className="flex items-center px-4 border-b border-soc-border">
          <Search className="w-4 h-4 text-soc-muted shrink-0 mr-3" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command or navigate... (e.g. Scans, Vulnerabilities)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            className="w-full bg-transparent py-3 text-sm text-soc-primary placeholder:text-soc-muted focus:outline-none"
          />
          <button
            onClick={onClose}
            className="text-soc-muted hover:text-soc-primary p-1"
            aria-label="Close Command Palette"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="max-h-72 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="py-6 text-center text-xs text-soc-muted">
              No commands found matching "{query}"
            </div>
          ) : (
            filtered.map((cmd, idx) => {
              const Icon = cmd.icon;
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={cmd.id}
                  onClick={() => handleSelect(cmd.to)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={cn(
                    'flex items-center justify-between px-3 py-2 rounded-md text-xs cursor-pointer transition-colors',
                    isSelected
                      ? 'bg-blue-600/20 text-blue-300'
                      : 'text-soc-secondary hover:bg-soc-elevated',
                  )}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4 text-soc-muted" />
                    <span className="font-medium text-soc-primary">{cmd.name}</span>
                  </div>
                  <span className="text-[10px] font-mono text-soc-muted">{cmd.category}</span>
                </div>
              );
            })
          )}
        </div>

        <div className="px-4 py-2 border-t border-soc-border bg-soc-elevated/40 flex items-center justify-between text-[11px] font-mono text-soc-muted">
          <span>Navigation Shortcuts</span>
          <div className="flex gap-2">
            <span>↑↓ to navigate</span>
            <span>↵ to select</span>
            <span>esc to close</span>
          </div>
        </div>
      </div>
    </div>
  );
};
