import React, { useMemo, useState } from 'react';
import { Eye, Plus, RotateCw, Trash2, Search, TrendingUp, TrendingDown } from 'lucide-react';
import { PageHeader, Panel, RiskBadge, EmptyState, Modal, Sparkline } from './ui';
import { scoreColor, timeAgo } from '../lib/risk';

function AddModal({ open, onClose, onAdd }) {
  const [url, setUrl] = useState('');
  const [frequency, setFrequency] = useState('Daily');
  const [notes, setNotes] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setBusy(true);
    const ok = await onAdd({ url: url.trim(), frequency, alert_notes: notes.trim() || undefined });
    setBusy(false);
    if (ok) {
      setUrl('');
      setNotes('');
      onClose();
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Watch a website"
      subtitle="We scan it now for a baseline, then track how its risk changes."
      footer={
        <>
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="watch-form" className="btn-primary" disabled={busy || !url.trim()}>
            {busy ? 'Scanning…' : 'Start watching'}
          </button>
        </>
      }
    >
      <form id="watch-form" onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="watch-url" className="label">
            Website
          </label>
          <input id="watch-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="defi-staking-pool.xyz" className="input font-mono" autoComplete="off" />
        </div>
        <div>
          <label htmlFor="watch-freq" className="label">
            Check every
          </label>
          <select id="watch-freq" value={frequency} onChange={(e) => setFrequency(e.target.value)} className="input">
            <option value="Hourly">Hour</option>
            <option value="Daily">Day</option>
            <option value="Weekly">Week</option>
          </select>
        </div>
        <div>
          <label htmlFor="watch-notes" className="label">
            Note <span className="font-normal text-fog-500">(optional)</span>
          </label>
          <input id="watch-notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Reported by a customer on 14 Oct" className="input" />
        </div>
      </form>
    </Modal>
  );
}

export default function WatchlistManager({ watchlist = [], onAdd, onRemove, onRescan, onInspect }) {
  const [query, setQuery] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return watchlist.filter((w) => !q || w.domain?.toLowerCase().includes(q) || (w.alert_notes || '').toLowerCase().includes(q));
  }, [watchlist, query]);

  const rescan = async (item) => {
    setBusyId(item.id);
    await onRescan(item);
    setBusyId(null);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Watchlist"
        description="Sites you want to keep an eye on. Scam operators change content, hosts and payment rails — re-scans show when risk drifts."
        actions={
          <button type="button" className="btn-primary" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4" /> Watch a website
          </button>
        }
      />

      <Panel bodyClassName="p-0">
        <div className="border-b border-ink-600/60 p-4">
          <div className="relative max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fog-400" />
            <label htmlFor="watch-filter" className="sr-only">
              Filter watchlist
            </label>
            <input id="watch-filter" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter watched sites" className="input pl-9" />
          </div>
        </div>

        {rows.length === 0 ? (
          <EmptyState
            icon={Eye}
            title={watchlist.length ? 'No watched sites match' : 'You’re not watching any sites yet'}
            action={!watchlist.length && <button type="button" className="btn-primary" onClick={() => setAddOpen(true)}><Plus className="h-4 w-4" /> Watch a website</button>}
          >
            {watchlist.length ? 'Try a different filter.' : 'Add a site from any report, or paste one here.'}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Risk</th>
                  <th>Change</th>
                  <th className="hidden md:table-cell">Trend</th>
                  <th className="hidden lg:table-cell">Checks</th>
                  <th className="hidden sm:table-cell">Last scan</th>
                  <th className="text-right">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  const drift = item.score_change || 0;
                  const history = (item.history || []).map((h) => h.score);
                  return (
                    <tr key={item.id}>
                      <td className="max-w-[260px]">
                        <button type="button" onClick={() => onInspect(item.url)} className="domain block max-w-full truncate text-left hover:text-signal-300">
                          {item.domain}
                        </button>
                        <span className="block truncate text-[12px] text-fog-400">{item.alert_notes}</span>
                      </td>
                      <td>
                        <RiskBadge level={item.risk_level} score={item.current_score} />
                      </td>
                      <td className="whitespace-nowrap">
                        {drift > 0 ? (
                          <span className="inline-flex items-center gap-1 text-rose-300">
                            <TrendingUp className="h-3.5 w-3.5" /> <span className="num">+{drift}</span>
                          </span>
                        ) : drift < 0 ? (
                          <span className="inline-flex items-center gap-1 text-emerald-300">
                            <TrendingDown className="h-3.5 w-3.5" /> <span className="num">{drift}</span>
                          </span>
                        ) : (
                          <span className="text-fog-500">Stable</span>
                        )}
                      </td>
                      <td className="hidden md:table-cell">
                        <Sparkline values={[...history, item.current_score].slice(-12)} color={scoreColor(item.current_score)} />
                      </td>
                      <td className="hidden text-fog-300 lg:table-cell">{item.frequency}</td>
                      <td className="hidden whitespace-nowrap text-fog-400 sm:table-cell">{timeAgo(item.last_scan)}</td>
                      <td className="whitespace-nowrap text-right">
                        <button type="button" className="icon-btn" onClick={() => rescan(item)} disabled={busyId === item.id} aria-label={`Re-scan ${item.domain}`} title="Re-scan now">
                          <RotateCw className={`h-4 w-4 ${busyId === item.id ? 'animate-spin' : ''}`} />
                        </button>
                        <button type="button" className="icon-btn hover:text-rose-300" onClick={() => setConfirm(item)} aria-label={`Stop watching ${item.domain}`} title="Stop watching">
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <AddModal open={addOpen} onClose={() => setAddOpen(false)} onAdd={onAdd} />

      <Modal
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        title="Stop watching this site?"
        footer={
          <>
            <button type="button" className="btn-ghost" onClick={() => setConfirm(null)}>
              Keep watching
            </button>
            <button
              type="button"
              className="btn-danger"
              onClick={() => {
                onRemove(confirm);
                setConfirm(null);
              }}
            >
              Stop watching
            </button>
          </>
        }
      >
        <p className="text-[14px] text-fog-200">
          <span className="font-mono text-white">{confirm?.domain}</span> will no longer be tracked. Its past scans stay in your history.
        </p>
      </Modal>
    </div>
  );
}
