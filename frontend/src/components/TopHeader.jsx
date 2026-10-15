import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Search, Bell, Loader2, X, Menu, CornerDownLeft, Siren, Eye, KeyRound, ArrowUpRight } from 'lucide-react';
import { RiskBadge } from './ui';
import { timeAgo } from '../lib/risk';

const READ_KEY = 'rr.readAlerts';

const loadRead = () => {
  try {
    return new Set(JSON.parse(localStorage.getItem(READ_KEY) || '[]'));
  } catch {
    return new Set();
  }
};

const saveRead = (set) => {
  try {
    localStorage.setItem(READ_KEY, JSON.stringify([...set].slice(-200)));
  } catch {
    /* storage unavailable — alerts simply stay unread */
  }
};

export default function TopHeader({ recentScans = [], queue = [], watchlist = [], scanning, onSearch, onSelectScan, onNavigate, onOpenNav }) {
  const [value, setValue] = useState('');
  const [focused, setFocused] = useState(false);
  const [highlight, setHighlight] = useState(-1);
  const [panel, setPanel] = useState(null); // 'alerts' | 'profile'
  const [readIds, setReadIds] = useState(loadRead);
  const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.platform || '');

  const inputRef = useRef(null);
  const searchRef = useRef(null);
  const menusRef = useRef(null);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
      if (e.key === 'Escape') {
        setPanel(null);
        setFocused(false);
        inputRef.current?.blur();
      }
    };
    const onClick = (e) => {
      if (searchRef.current && !searchRef.current.contains(e.target)) setFocused(false);
      if (menusRef.current && !menusRef.current.contains(e.target)) setPanel(null);
    };
    window.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onClick);
    return () => {
      window.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onClick);
    };
  }, []);

  const query = value.trim().toLowerCase();
  const matches = useMemo(() => {
    if (!query) return [];
    const seen = new Set();
    return recentScans
      .filter((s) => {
        if (seen.has(s.domain)) return false;
        const hit = (s.domain || '').toLowerCase().includes(query) || (s.url || '').toLowerCase().includes(query);
        if (hit) seen.add(s.domain);
        return hit;
      })
      .slice(0, 5);
  }, [query, recentScans]);

  // Alerts come from real state: new high-risk incidents and watchlist score jumps
  const alerts = useMemo(() => {
    const fromQueue = queue
      .filter((q) => q.status === 'New' && q.score >= 50)
      .map((q) => ({
        id: `inc:${q.id}:${q.score}`,
        icon: Siren,
        title: `${q.risk === 'CRITICAL' ? 'Critical' : 'High'}-risk site needs triage`,
        body: `${q.domain} scored ${q.score}/100 — ${q.detectedPattern || 'suspicious pattern'}.`,
        time: q.lastUpdated,
        level: q.risk,
        onOpen: () => onNavigate('investigations')
      }));
    const fromWatch = watchlist
      .filter((w) => w.monitoring_state === 'Alerting' || (w.score_change || 0) >= 10)
      .map((w) => ({
        id: `wl:${w.id}:${w.current_score}`,
        icon: Eye,
        title: 'Watchlist score jumped',
        body: `${w.domain} moved ${w.score_change > 0 ? '+' : ''}${w.score_change} to ${w.current_score}/100.`,
        time: w.last_scan,
        level: w.risk_level,
        onOpen: () => onNavigate('watchlist')
      }));
    return [...fromQueue, ...fromWatch].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 12);
  }, [queue, watchlist, onNavigate]);

  const unread = alerts.filter((a) => !readIds.has(a.id)).length;

  const markRead = (ids) => {
    const next = new Set(readIds);
    ids.forEach((id) => next.add(id));
    setReadIds(next);
    saveRead(next);
  };

  const submit = (e) => {
    e?.preventDefault();
    if (highlight >= 0 && matches[highlight]) {
      onSelectScan(matches[highlight]);
    } else if (value.trim()) {
      onSearch(value.trim());
    } else {
      return;
    }
    setValue('');
    setFocused(false);
    setHighlight(-1);
    inputRef.current?.blur();
  };

  const onInputKey = (e) => {
    if (!matches.length) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlight((h) => (h >= matches.length - 1 ? -1 : h + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlight((h) => (h <= -1 ? matches.length - 1 : h - 1));
    }
  };

  return (
    <header className="no-print sticky top-0 z-30 border-b border-ink-600/50 bg-ink-950/80 backdrop-blur-xl">
      <div className="mx-auto flex h-15 sm:h-16 max-w-[1320px] items-center gap-2 sm:gap-3 px-3 sm:px-6 lg:px-8">
        <button type="button" className="icon-btn lg:hidden shrink-0" onClick={onOpenNav} aria-label="Open navigation">
          <Menu className="h-5 w-5" />
        </button>

        <button
          type="button"
          onClick={() => onNavigate('dashboard')}
          className="flex items-center gap-2 lg:hidden shrink-0"
          aria-label="Risk Radar home"
        >
          <span
            className="block h-8 w-8 shrink-0 rounded-lg bg-ink-950 ring-1 ring-brand-400/40"
            style={{ backgroundImage: 'url(/risk-radar-logo.jpg)', backgroundSize: 'auto 165%', backgroundPosition: '50% 19%' }}
            aria-hidden
          />
        </button>

        <div ref={searchRef} className="relative max-w-xl flex-1 min-w-0">
          <form onSubmit={submit} role="search">
            <label htmlFor="global-search" className="sr-only">
              Search scanned domains or scan a new URL
            </label>
            <div className={`flex items-center rounded-[10px] border transition-colors ${focused ? 'border-brand-400/70 bg-ink-850' : 'border-ink-600/70 bg-ink-850/70 hover:border-ink-500'}`}>
              <span className="pl-2.5 sm:pl-3 text-fog-400 shrink-0">{scanning ? <Loader2 className="h-4 w-4 animate-spin text-signal-400" /> : <Search className="h-4 w-4" />}</span>
              <input
                id="global-search"
                ref={inputRef}
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  setHighlight(-1);
                }}
                onFocus={() => setFocused(true)}
                onKeyDown={onInputKey}
                placeholder="Search or scan URL…"
                autoComplete="off"
                className="w-full min-w-0 bg-transparent px-2.5 sm:px-3 py-2 text-[13px] sm:text-[14px] text-fog-50 placeholder:text-fog-500 focus:outline-none"
              />
              {value ? (
                <button type="button" className="mr-2 shrink-0 rounded p-1 text-fog-400 hover:text-white" onClick={() => setValue('')} aria-label="Clear search">
                  <X className="h-3.5 w-3.5" />
                </button>
              ) : (
                <span className="kbd mr-2 hidden sm:inline-flex shrink-0">{isMac ? '⌘' : 'Ctrl'} K</span>
              )}
            </div>
          </form>

          {focused && query && (
            <div className="panel absolute inset-x-0 top-full z-40 mt-2 overflow-hidden bg-ink-850 animate-fade-in">
              {matches.length > 0 && (
                <ul className="py-1.5">
                  {matches.map((s, i) => (
                    <li key={s.id}>
                      <button
                        type="button"
                        onMouseEnter={() => setHighlight(i)}
                        onClick={() => {
                          onSelectScan(s);
                          setValue('');
                          setFocused(false);
                        }}
                        className={`flex w-full items-center justify-between gap-3 px-4 py-2 text-left ${highlight === i ? 'bg-ink-700/70' : ''}`}
                      >
                        <span className="min-w-0">
                          <span className="domain block truncate">{s.domain}</span>
                          <span className="block truncate text-[12px] text-fog-400">
                            {s.primaryPattern} · {timeAgo(s.timestamp)}
                          </span>
                        </span>
                        <RiskBadge level={s.risk_level} score={s.score} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <button
                type="button"
                onClick={submit}
                className={`flex w-full items-center justify-between gap-3 border-t border-ink-600/60 px-4 py-2.5 text-left text-[13px] ${highlight === -1 ? 'bg-brand-500/10 text-white' : 'text-fog-200'}`}
              >
                <span className="truncate">
                  {matches.some((m) => m.domain === query) ? 'Open report for ' : 'Scan '}
                  <span className="font-mono text-signal-300">{value.trim()}</span>
                </span>
                <CornerDownLeft className="h-3.5 w-3.5 shrink-0 text-fog-400" />
              </button>
            </div>
          )}
        </div>

        <div ref={menusRef} className="ml-auto flex items-center gap-1.5">
          <div className="relative">
            <button
              type="button"
              onClick={() => setPanel(panel === 'alerts' ? null : 'alerts')}
              className={`icon-btn relative ${panel === 'alerts' ? 'bg-ink-700/70 text-white' : ''}`}
              aria-label={`Alerts${unread ? `, ${unread} unread` : ''}`}
              aria-expanded={panel === 'alerts'}
            >
              <Bell className="h-[18px] w-[18px]" />
              {unread > 0 && (
                <span className="num absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-risk-critical px-1 text-[10px] font-semibold text-white">
                  {unread > 9 ? '9+' : unread}
                </span>
              )}
            </button>

            {panel === 'alerts' && (
              <div className="panel absolute right-0 top-full mt-2 w-[min(92vw,380px)] overflow-hidden bg-ink-850 animate-fade-in">
                <div className="flex items-center justify-between border-b border-ink-600/60 px-4 py-3">
                  <span className="font-display text-[15px] font-semibold text-white">Alerts</span>
                  {unread > 0 && (
                    <button type="button" className="text-[12px] font-medium text-signal-300 hover:text-signal-400" onClick={() => markRead(alerts.map((a) => a.id))}>
                      Mark all read
                    </button>
                  )}
                </div>
                {alerts.length === 0 ? (
                  <p className="px-4 py-8 text-center text-[13px] text-fog-400">No new alerts. High-risk scans and watchlist jumps will show up here.</p>
                ) : (
                  <ul className="max-h-[360px] divide-y divide-ink-700/70 overflow-y-auto">
                    {alerts.map((a) => {
                      const Icon = a.icon;
                      const isUnread = !readIds.has(a.id);
                      return (
                        <li key={a.id}>
                          <button
                            type="button"
                            onClick={() => {
                              markRead([a.id]);
                              setPanel(null);
                              a.onOpen();
                            }}
                            className="flex w-full gap-3 px-4 py-3 text-left hover:bg-ink-700/40"
                          >
                            <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${a.level === 'CRITICAL' ? 'text-risk-critical' : 'text-risk-high'}`} />
                            <span className="min-w-0 flex-1">
                              <span className={`block text-[13px] ${isUnread ? 'font-semibold text-white' : 'text-fog-200'}`}>{a.title}</span>
                              <span className="mt-0.5 block text-[12px] leading-snug text-fog-400">{a.body}</span>
                              <span className="mt-1 block text-[11px] text-fog-500">{timeAgo(a.time)}</span>
                            </span>
                            {isUnread && <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-signal-400" />}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            )}
          </div>

          <div className="relative">
            <button
              type="button"
              onClick={() => setPanel(panel === 'profile' ? null : 'profile')}
              className="ml-1 flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-brand-500 to-signal-500 font-display text-[14px] font-semibold text-white ring-2 ring-ink-950 transition hover:ring-brand-400/60"
              aria-label="Account menu"
              aria-expanded={panel === 'profile'}
            >
              P
            </button>
            {panel === 'profile' && (
              <div className="panel absolute right-0 top-full mt-2 w-[min(90vw,260px)] overflow-hidden bg-ink-850 animate-fade-in shadow-2xl">
                <div className="border-b border-ink-600/60 px-4 py-3">
                  <div className="text-[14px] font-semibold text-white">Priyanka</div>
                  <div className="text-[12px] text-fog-400">SOC lead · Risk Radar workspace</div>
                </div>
                <div className="p-1.5">
                  {[
                    { label: 'Investigations', icon: Siren, tab: 'investigations' },
                    { label: 'Watchlist', icon: Eye, tab: 'watchlist' },
                    { label: 'API keys', icon: KeyRound, tab: 'settings' }
                  ].map((item) => (
                    <button
                      key={item.tab}
                      type="button"
                      onClick={() => {
                        setPanel(null);
                        onNavigate(item.tab);
                      }}
                      className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] text-fog-200 hover:bg-ink-700/60 hover:text-white"
                    >
                      <item.icon className="h-4 w-4 text-fog-400" />
                      <span className="flex-1 text-left">{item.label}</span>
                      <ArrowUpRight className="h-3.5 w-3.5 text-fog-500" />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
