import React from 'react';
import { LayoutGrid, Radar, Layers, Eye, Siren, Menu } from 'lucide-react';

export default function MobileBottomNav({ active, onNavigate, counts = {}, onOpenSidebar }) {
  const tabs = [
    { id: 'dashboard', label: 'Overview', icon: LayoutGrid },
    { id: 'pre-execution', label: 'Scanner', icon: Radar },
    { id: '7d-engine', label: '7D Engine', icon: Layers },
    { id: 'watchlist', label: 'Watchlist', icon: Eye, countKey: 'watchlist' },
    { id: 'investigations', label: 'Triage', icon: Siren, countKey: 'investigations' }
  ];

  return (
    <nav
      className="no-print fixed inset-x-0 bottom-0 z-40 border-t border-ink-600/70 bg-ink-950/90 pb-[max(0.5rem,env(safe-area-inset-bottom))] pt-1.5 backdrop-blur-xl lg:hidden"
      aria-label="Mobile Navigation"
    >
      <div className="mx-auto flex max-w-md items-center justify-around px-2">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = active === tab.id;
          const count = tab.countKey ? counts[tab.countKey] : undefined;

          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onNavigate(tab.id)}
              className={`relative flex flex-1 flex-col items-center justify-center py-1 text-center transition-colors ${
                isActive ? 'text-signal-300' : 'text-fog-400 hover:text-fog-200'
              }`}
            >
              <div className="relative">
                <Icon className={`h-5 w-5 ${isActive ? 'text-signal-300 scale-110 transition-transform' : ''}`} />
                {count > 0 && (
                  <span className="num absolute -right-2.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-risk-critical px-1 text-[10px] font-bold text-white shadow-sm">
                    {count > 9 ? '9+' : count}
                  </span>
                )}
              </div>
              <span className={`mt-1 text-[10.5px] font-medium leading-none ${isActive ? 'font-semibold text-white' : ''}`}>
                {tab.label}
              </span>
              {isActive && (
                <span className="absolute -bottom-1 h-1 w-5 rounded-full bg-signal-400 shadow-[0_0_8px_rgba(34,211,238,0.7)]" />
              )}
            </button>
          );
        })}

        <button
          type="button"
          onClick={onOpenSidebar}
          className="flex flex-1 flex-col items-center justify-center py-1 text-center text-fog-400 transition-colors hover:text-fog-200"
          aria-label="More navigation options"
        >
          <Menu className="h-5 w-5" />
          <span className="mt-1 text-[10.5px] font-medium leading-none">More</span>
        </button>
      </div>
    </nav>
  );
}
