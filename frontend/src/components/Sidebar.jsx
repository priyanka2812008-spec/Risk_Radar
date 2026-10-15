import React from 'react';
import { LayoutGrid, Radar, FileSearch, History, Siren, Eye, BarChart3, KeyRound, X, Layers } from 'lucide-react';

const SECTIONS = [
  {
    label: 'Scan',
    items: [
      { id: 'dashboard', label: 'Overview', icon: LayoutGrid },
      { id: 'pre-execution', label: 'Pre-execution scan', icon: Radar },
      { id: 'report', label: 'Risk report', icon: FileSearch },
      { id: 'history', label: 'Scan history', icon: History }
    ]
  },
  {
    label: 'Respond',
    items: [
      { id: 'investigations', label: 'Investigations', icon: Siren, countKey: 'investigations' },
      { id: 'watchlist', label: 'Watchlist', icon: Eye, countKey: 'watchlist' }
    ]
  },
  {
    label: 'Intelligence',
    items: [
      { id: '7d-engine', label: '7D Classification', icon: Layers },
      { id: 'intelligence', label: 'Threat analytics', icon: BarChart3 },
      { id: 'settings', label: 'API & settings', icon: KeyRound }
    ]
  }
];

function EngineStatus({ health }) {
  const online = health.status === 'online';
  const checking = health.status === 'checking';
  const dot = online ? 'bg-risk-low' : checking ? 'bg-risk-medium' : 'bg-risk-critical';
  return (
    <div className="rounded-xl border border-ink-600/60 bg-ink-900/70 p-3.5">
      <div className="flex items-center gap-2 text-[13px] font-medium text-fog-100">
        <span className="relative flex h-2 w-2">
          {online && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${dot} opacity-60`} />}
          <span className={`relative inline-flex h-2 w-2 rounded-full ${dot}`} />
        </span>
        {online ? 'Engine online' : checking ? 'Connecting…' : 'Engine offline'}
      </div>
      <p className="mt-1 text-[12px] leading-snug text-fog-400">
        {online
          ? `v${health.version || '4.2'} · ${health.database === 'mongodb' ? 'MongoDB storage' : 'In-memory storage'}`
          : checking
          ? 'Checking the scanning backend'
          : 'Start the backend on port 5000'}
      </p>
    </div>
  );
}

export default function Sidebar({ active, onNavigate, counts = {}, health, open, onClose }) {
  return (
    <>
      {open && <div className="fixed inset-0 z-40 bg-ink-950/70 backdrop-blur-sm lg:hidden" onClick={onClose} aria-hidden />}
      <aside
        className={`no-print fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-ink-600/60 bg-ink-900/95 backdrop-blur-xl transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Main navigation"
      >
        <div className="flex items-center justify-between px-5 pb-6 pt-5">
          <button type="button" onClick={() => onNavigate('dashboard')} className="flex items-center gap-3 text-left">
            {/* The shield mark cropped from the full brand artwork */}
            <span
              className="block h-10 w-10 shrink-0 rounded-xl bg-ink-950 ring-1 ring-brand-400/40"
              style={{ backgroundImage: 'url(/risk-radar-logo.jpg)', backgroundSize: 'auto 165%', backgroundPosition: '50% 19%' }}
              aria-hidden
            />
            <span>
              <span className="block font-display text-[19px] font-semibold leading-none tracking-wide text-white">
                Risk <span className="text-brand-400">Radar</span>
              </span>
              <span className="mt-1 block text-[11px] text-fog-400">Detect, analyze, prevent</span>
            </span>
          </button>
          <button type="button" onClick={onClose} className="icon-btn lg:hidden" aria-label="Close navigation">
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto px-3">
          {SECTIONS.map((section) => (
            <div key={section.label}>
              <div className="px-3 pb-1.5 text-[12px] font-medium text-fog-500">{section.label}</div>
              <ul className="space-y-0.5">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = active === item.id;
                  const count = item.countKey ? counts[item.countKey] : undefined;
                  return (
                    <li key={item.id}>
                      <button
                        type="button"
                        onClick={() => onNavigate(item.id)}
                        aria-current={isActive ? 'page' : undefined}
                        className={`group relative flex w-full items-center gap-3 rounded-[10px] px-3 py-2 text-[14px] transition-colors ${
                          isActive ? 'bg-brand-500/15 text-white' : 'text-fog-300 hover:bg-ink-700/50 hover:text-white'
                        }`}
                      >
                        {isActive && <span className="absolute -left-3 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-brand-400" />}
                        <Icon className={`h-[18px] w-[18px] ${isActive ? 'text-brand-300' : 'text-fog-400 group-hover:text-fog-200'}`} aria-hidden />
                        <span className="flex-1 text-left">{item.label}</span>
                        {count > 0 && (
                          <span className={`num rounded-md px-1.5 text-[12px] ${isActive ? 'bg-brand-500/30 text-white' : 'bg-ink-700 text-fog-300'}`}>
                            {count}
                          </span>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="p-4">
          <EngineStatus health={health} />
        </div>
      </aside>
    </>
  );
}
