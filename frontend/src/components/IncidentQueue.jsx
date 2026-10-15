import React, { useMemo, useState } from 'react';
import { Siren } from 'lucide-react';
import { PageHeader, Panel, EmptyState, Segmented } from './ui';
import { riskMeta, timeAgo } from '../lib/risk';

const ANALYSTS = ['Unassigned', 'Sarah K. (Lead SOC)', 'Marcus Vance (Tier-2)', 'Alex Chen (Forensics)', 'Priyanka'];
const STATUSES = ['New', 'Investigating', 'Blocked', 'Reviewed', 'Allowed'];

const FILTERS = {
  open: (q) => !['Reviewed', 'Allowed'].includes(q.status),
  New: (q) => q.status === 'New',
  Investigating: (q) => q.status === 'Investigating',
  Blocked: (q) => q.status === 'Blocked',
  resolved: (q) => ['Reviewed', 'Allowed'].includes(q.status),
  all: () => true
};

const STATUS_TONE = {
  New: 'text-signal-300',
  Investigating: 'text-brand-300',
  Blocked: 'text-rose-300',
  Reviewed: 'text-emerald-300',
  Allowed: 'text-emerald-300'
};

export default function IncidentQueue({ queue = [], onUpdate, onInspect }) {
  const [filter, setFilter] = useState('open');

  const counts = useMemo(() => Object.fromEntries(Object.entries(FILTERS).map(([k, fn]) => [k, queue.filter(fn).length])), [queue]);
  const rows = useMemo(() => queue.filter(FILTERS[filter]).sort((a, b) => b.score - a.score), [queue, filter]);

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Investigations"
        description="Every scan that scores 50 or more opens an incident here. Assign an analyst, then block, allow or close it."
      />

      <Panel bodyClassName="p-0">
        <div className="overflow-x-auto border-b border-ink-600/60 p-4">
          <Segmented
            value={filter}
            onChange={setFilter}
            options={[
              { id: 'open', label: `Open ${counts.open}` },
              { id: 'New', label: `New ${counts.New}` },
              { id: 'Investigating', label: `Investigating ${counts.Investigating}` },
              { id: 'Blocked', label: `Blocked ${counts.Blocked}` },
              { id: 'resolved', label: `Resolved ${counts.resolved}` },
              { id: 'all', label: `All ${counts.all}` }
            ]}
          />
        </div>

        {rows.length === 0 ? (
          <EmptyState icon={Siren} title={queue.length ? 'Nothing in this view' : 'No incidents'}>
            {queue.length ? 'Pick another filter to see more incidents.' : 'High-risk scans will appear here automatically.'}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-14">Score</th>
                  <th>Website</th>
                  <th className="min-w-[170px]">Analyst</th>
                  <th className="min-w-[150px]">Status</th>
                  <th className="hidden text-right md:table-cell">Updated</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  const meta = riskMeta(item.risk);
                  const assignee = item.assignedTo || 'Unassigned';
                  return (
                    <tr key={item.id}>
                      <td>
                        <span className="num text-[20px] font-semibold" style={{ color: meta.color }}>
                          {item.score}
                        </span>
                      </td>
                      <td className="max-w-[360px]">
                        <button type="button" onClick={() => onInspect(item.url)} className="domain block max-w-full truncate text-left hover:text-signal-300">
                          {item.domain}
                        </button>
                        <span className="block truncate text-[12px] text-fog-400">
                          {item.detectedPattern} · <span className="font-mono">{item.id}</span>
                        </span>
                      </td>
                      <td>
                        <label className="sr-only" htmlFor={`as-${item.id}`}>
                          Analyst for {item.domain}
                        </label>
                        <select id={`as-${item.id}`} value={assignee} onChange={(e) => onUpdate(item.id, { assignedTo: e.target.value })} className="input py-1.5 text-[13px]">
                          {[...new Set([assignee, ...ANALYSTS])].map((a) => (
                            <option key={a} value={a}>
                              {a}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <label className="sr-only" htmlFor={`st-${item.id}`}>
                          Status for {item.domain}
                        </label>
                        <select id={`st-${item.id}`} value={item.status} onChange={(e) => onUpdate(item.id, { status: e.target.value })} className={`input py-1.5 text-[13px] font-medium ${STATUS_TONE[item.status] || ''}`}>
                          {STATUSES.map((s) => (
                            <option key={s} value={s}>
                              {s}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="hidden whitespace-nowrap text-right text-fog-400 md:table-cell">{timeAgo(item.lastUpdated)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
