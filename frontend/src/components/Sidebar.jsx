import React from 'react';
import {
  LayoutGrid, Radar, FileSearch, History, Siren, Eye, BarChart3,
  KeyRound, X, Layers, Globe, ShieldCheck, Activity
} from 'lucide-react';

const SECTIONS = [
  {
    label: 'Scan & Monitor',
    items: [
      { id: 'dashboard', label: 'Overview', icon: LayoutGrid },
      { id: 'threat-globe', label: '3D Threat Globe', icon: Globe, badge: '3D LIVE' },
      { id: 'pre-execution', label: 'Pre-execution scan', icon: Radar },
      { id: 'report', label: 'Risk report', icon: FileSearch },
      { id: 'history', label: 'Scan history', icon: History }
    ]
  },
  {
    label: 'Respond & Guard',
    items: [
      { id: 'investigations', label: 'Investigations', icon: Siren, countKey: 'investigations' },
      { id: 'watchlist', label: 'Watchlist', icon: Eye, countKey: 'watchlist' }
    ]
  },
  {
    label: 'Threat Intelligence',
    items: [
      { id: '7d-engine', label: '7D Classification', icon: Layers },
      { id: 'intelligence', label: 'Threat analytics', icon: BarChart3 },
      { id: 'settings', label: 'API & settings', icon: KeyRound }
    ]
  }
];

function EngineStatus({ health }) {
  const online = health.status === 'online';
  const checking = health.status === 'checking' || health.retrying;
  const dot = online ? 'bg-emerald-400' : checking ? 'bg-amber-400' : 'bg-rose-500';

  return (
    <div className="rounded-xl border border-cyan-500/25 bg-[#050c1e]/90 p-3.5 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-display font-bold tracking-wider text-white">
          <span className="relative flex h-2 w-2">
            {online && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${dot} opacity-75`} />}
            <span className={`relative inline-flex h-2 w-2 rounded-full ${dot}`} />
          </span>
          <span>{online ? 'SYSTEM ONLINE' : checking ? 'CONNECTING...' : 'SYSTEM OFFLINE'}</span>
        </div>
        <span className="font-mono text-[10px] text-cyan-400/90 font-semibold">v{health.version || '4.2'}</span>
      </div>
      <p className="mt-1.5 font-mono text-[11px] text-fog-400 leading-snug">
        {online
          ? 'Threat database synchronized & active'
          : checking
          ? 'Connecting to threat telemetry...'
          : 'Scanning backend offline'}
      </p>
    </div>
  );
}

export default function Sidebar({ active, onNavigate, counts = {}, health, open, onClose }) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden"
          onClick={onClose}
          aria-hidden
        />
      )}
      <aside
        className={`no-print fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-cyan-500/20 bg-[#030714]/95 backdrop-blur-xl transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Main navigation"
      >
        {/* Brand Header matching reference UI */}
        <div className="flex items-center justify-between px-5 pb-5 pt-5 border-b border-cyan-500/15">
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="flex items-center gap-3 text-left group"
          >
            <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/50 bg-cyan-950/60 shadow-[0_0_15px_rgba(34,211,238,0.3)] group-hover:border-cyan-300 transition-all">
              <Radar className="h-5 w-5 text-cyan-300 animate-spin" style={{ animationDuration: '10s' }} />
              <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-cyan-400 animate-ping opacity-75" />
            </div>
            <div>
              <div className="font-display text-[17px] font-bold tracking-wider text-white flex items-center gap-1.5">
                <span>RISK</span>
                <span className="text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.6)]">RADAR</span>
              </div>
              <div className="font-mono text-[9.5px] text-cyan-400/80 tracking-tight">
                Know the risk before you trust the site.
              </div>
            </div>
          </button>
          <button
            type="button"
            onClick={onClose}
            className="icon-btn lg:hidden text-fog-400 hover:text-white"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Navigation Sections with Electric Cyan Cyber styling */}
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {SECTIONS.map((section) => (
            <div key={section.label}>
              <div className="px-3 pb-1.5 font-display text-[10px] font-bold tracking-widest text-cyan-400/70 uppercase">
                {section.label}
              </div>
              <ul className="space-y-1">
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
                        className={`group relative flex w-full items-center gap-3 rounded-xl px-3 py-2 text-[13px] font-medium transition-all ${
                          isActive
                            ? 'border border-cyan-400/40 bg-gradient-to-r from-cyan-950/80 to-[#07132e]/60 text-white shadow-[0_0_15px_rgba(34,211,238,0.22)]'
                            : 'border border-transparent text-fog-300 hover:bg-cyan-950/30 hover:border-cyan-500/20 hover:text-white'
                        }`}
                      >
                        {/* Active left indicator light */}
                        {isActive && (
                          <span className="absolute -left-3 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
                        )}

                        <Icon
                          className={`h-[18px] w-[18px] shrink-0 transition-transform group-hover:scale-110 ${
                            isActive ? 'text-cyan-300 drop-shadow-[0_0_6px_rgba(34,211,238,0.7)]' : 'text-fog-400 group-hover:text-cyan-400'
                          }`}
                          aria-hidden
                        />

                        <span className="flex-1 text-left font-sans">{item.label}</span>

                        {item.badge && (
                          <span className="rounded bg-cyan-950 border border-cyan-400/50 px-1.5 py-0.5 text-[9px] font-mono font-bold text-cyan-300 shadow-[0_0_8px_rgba(34,211,238,0.3)] animate-pulse">
                            {item.badge}
                          </span>
                        )}

                        {count > 0 && (
                          <span
                            className={`rounded-full px-2 py-0.5 font-mono text-[11px] font-bold ${
                              isActive
                                ? 'bg-cyan-400 text-ink-950 shadow-[0_0_8px_#22d3ee]'
                                : 'bg-cyan-950/80 border border-cyan-500/40 text-cyan-300'
                            }`}
                          >
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

        {/* Engine status footer */}
        <div className="p-3 border-t border-cyan-500/15">
          <EngineStatus health={health} />
        </div>
      </aside>
    </>
  );
}
