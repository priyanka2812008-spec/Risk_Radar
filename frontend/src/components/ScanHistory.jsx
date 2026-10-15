import React, { useMemo, useState } from 'react';
import { History, Search, ListPlus, ArrowRight } from 'lucide-react';
import { PageHeader, Panel, RiskBadge, EmptyState, Segmented, Modal } from './ui';
import { formatDateTime, latestPerDomain } from '../lib/risk';
import { errorMessage } from '../services/api';

const LEVELS = [
  { id: 'ALL', label: 'All' },
  { id: 'CRITICAL', label: 'Critical' },
  { id: 'HIGH', label: 'High' },
  { id: 'MEDIUM', label: 'Medium' },
  { id: 'LOW', label: 'Low' }
];

function BulkScanModal({ open, onClose, onBulkScan, onOpenScan }) {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const urls = text.split(/[\s,]+/).map((u) => u.trim()).filter(Boolean);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResults(await onBulkScan(urls.slice(0, 15)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    setText('');
    setResults(null);
    setError(null);
    onClose();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Scan a list of websites"
      subtitle="Paste up to 15 links, one per line or separated by commas."
      width="max-w-xl"
      footer={
        results ? (
          <button type="button" className="btn-primary" onClick={close}>
            Done
          </button>
        ) : (
          <>
            <button type="button" className="btn-ghost" onClick={close}>
              Cancel
            </button>
            <button type="button" className="btn-primary" disabled={busy || urls.length === 0} onClick={run}>
              {busy ? 'Scanning…' : `Scan ${Math.min(urls.length, 15) || ''} site${urls.length === 1 ? '' : 's'}`}
            </button>
          </>
        )
      }
    >
      {!results ? (
        <>
          <label htmlFor="bulk-urls" className="label">
            Websites
          </label>
          <textarea
            id="bulk-urls"
            rows={7}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={'quick-loan-approval.xyz\nbet777-instant-win.online\nstripe.com'}
            className="input resize-y font-mono text-[13px]"
          />
          {urls.length > 15 && <p className="mt-2 text-[12px] text-risk-medium">Only the first 15 will be scanned.</p>}
          {error && <p className="mt-2 text-[13px] text-rose-300">{error}</p>}
        </>
      ) : (
        <ul className="divide-y divide-ink-700/70">
          {results.map((r, i) => (
            <li key={r.id || `${r.url}-${i}`} className="flex items-center justify-between gap-3 py-2.5">
              {r.error ? (
                <>
                  <span className="min-w-0">
                    <span className="domain block truncate">{r.url}</span>
                    <span className="block text-[12px] text-rose-300">{r.error}</span>
                  </span>
                </>
              ) : (
                <>
                  <button type="button" className="domain truncate text-left hover:text-signal-300" onClick={() => { close(); onOpenScan(r); }}>
                    {r.domain}
                  </button>
                  <RiskBadge level={r.risk_level} score={r.score} />
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </Modal>
  );
}

export default function ScanHistory({ scans = [], onOpenScan, onBulkScan }) {
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('ALL');
  const [uniqueOnly, setUniqueOnly] = useState(true);
  const [bulkOpen, setBulkOpen] = useState(false);

  const rows = useMemo(() => {
    const base = uniqueOnly ? latestPerDomain(scans) : scans;
    const q = query.trim().toLowerCase();
    return base.filter(
      (s) =>
        (level === 'ALL' || s.risk_level === level) &&
        (!q || s.domain?.toLowerCase().includes(q) || (s.classification?.primary || '').toLowerCase().includes(q) || (s.primaryPattern || '').toLowerCase().includes(q))
    );
  }, [scans, query, level, uniqueOnly]);

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Scan history"
        description="Every website Risk Radar has assessed. Open any row for the full report and evidence."
        actions={
          <button type="button" className="btn-secondary" onClick={() => setBulkOpen(true)}>
            <ListPlus className="h-4 w-4" /> Scan a list
          </button>
        }
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-col gap-3 border-b border-ink-600/60 p-4 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fog-400" />
            <label htmlFor="history-filter" className="sr-only">
              Filter scans
            </label>
            <input id="history-filter" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by domain or category" className="input pl-9" />
          </div>
          <Segmented options={LEVELS} value={level} onChange={setLevel} />
          <label className="inline-flex cursor-pointer items-center gap-2 text-[13px] text-fog-300">
            <input type="checkbox" checked={uniqueOnly} onChange={(e) => setUniqueOnly(e.target.checked)} className="h-4 w-4 accent-brand-500" />
            Latest per domain
          </label>
        </div>

        {rows.length === 0 ? (
          <EmptyState icon={History} title={scans.length ? 'No scans match these filters' : 'No scans yet'}>
            {scans.length ? 'Clear the filter or pick another risk level.' : 'Scan a website from the overview to start your history.'}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Website</th>
                  <th className="hidden md:table-cell">Looks like</th>
                  <th>Risk</th>
                  <th className="hidden lg:table-cell">Recommended</th>
                  <th className="hidden sm:table-cell">Scanned</th>
                  <th className="w-10" />
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 200).map((s) => (
                  <tr key={s.id} className="cursor-pointer" onClick={() => onOpenScan(s)}>
                    <td className="max-w-[260px]">
                      <span className="domain block truncate">{s.domain}</span>
                      {s.unknownSuspicious && <span className="text-[12px] text-signal-300">Unknown but suspicious</span>}
                    </td>
                    <td className="hidden max-w-[240px] truncate text-fog-300 md:table-cell">{s.classification?.primary || s.primaryPattern}</td>
                    <td>
                      <RiskBadge level={s.risk_level} score={s.score} />
                    </td>
                    <td className="hidden text-fog-200 lg:table-cell">{s.recommendedAction?.action || '—'}</td>
                    <td className="hidden whitespace-nowrap text-fog-400 sm:table-cell">{formatDateTime(s.timestamp)}</td>
                    <td className="text-right">
                      <ArrowRight className="ml-auto h-4 w-4 text-fog-500" aria-hidden />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="border-t border-ink-600/60 px-4 py-3 text-[12px] text-fog-400">
          Showing {Math.min(rows.length, 200)} of {rows.length} {uniqueOnly ? 'domains' : 'scans'}
        </div>
      </Panel>

      <BulkScanModal open={bulkOpen} onClose={() => setBulkOpen(false)} onBulkScan={onBulkScan} onOpenScan={onOpenScan} />
    </div>
  );
}
