import React, { useMemo } from 'react';
import { BarChart3 } from 'lucide-react';
import { PageHeader, Panel, EmptyState, RiskBadge } from './ui';
import { RISK } from '../lib/risk';

function Donut({ segments, total }) {
  const r = 70;
  const c = 2 * Math.PI * r;
  const offsets = segments.reduce((acc, s, i) => [...acc, (acc[i] || 0) + (total ? (s.value / total) * c : 0)], [0]);
  return (
    <svg viewBox="0 0 180 180" className="h-44 w-44 shrink-0 -rotate-90" role="img" aria-label="Severity distribution">
      <circle cx="90" cy="90" r={r} fill="none" stroke="#1C2148" strokeWidth="18" />
      {segments.map((s, i) => {
        const len = total ? (s.value / total) * c : 0;
        return <circle key={s.label} cx="90" cy="90" r={r} fill="none" stroke={s.color} strokeWidth="18" strokeDasharray={`${Math.max(0, len - 2)} ${c}`} strokeDashoffset={-offsets[i]} />;
      })}
    </svg>
  );
}

function BarList({ entries, color = '#A78BFA' }) {
  const max = entries[0]?.[1] || 1;
  return (
    <ul className="space-y-3">
      {entries.map(([name, n]) => (
        <li key={name}>
          <div className="flex items-baseline justify-between gap-4 text-[13px]">
            <span className="min-w-0 truncate text-fog-100">{name}</span>
            <span className="num shrink-0 text-fog-300">{n}</span>
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-ink-700">
            <div className="h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: typeof color === 'function' ? color(name) : color }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function ThreatAnalytics({ stats, onOpenScan }) {
  const patterns = useMemo(() => Object.entries(stats?.patternDistribution || {}).sort((a, b) => b[1] - a[1]).slice(0, 10), [stats]);
  const classes = useMemo(() => Object.entries(stats?.classificationDistribution || {}).sort((a, b) => b[1] - a[1]).slice(0, 10), [stats]);

  if (!stats) {
    return (
      <div className="panel">
        <EmptyState icon={BarChart3} title="Loading analytics…" />
      </div>
    );
  }

  const segments = [
    { label: 'Critical', value: stats.criticalCount, color: RISK.CRITICAL.color },
    { label: 'High', value: stats.highCount, color: RISK.HIGH.color },
    { label: 'Medium', value: stats.mediumCount, color: RISK.MEDIUM.color },
    { label: 'Low', value: stats.lowCount, color: RISK.LOW.color }
  ];
  const total = stats.totalScans || 0;
  const pct = (v) => (total ? Math.round((v / total) * 100) : 0);

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader title="Threat analytics" description="What Risk Radar has seen across every scan — severity, the scam patterns behind it, and which sites matter most." />

      <section className="panel grid grid-cols-2 divide-ink-600/60 lg:grid-cols-4 lg:divide-x [&>*:nth-child(-n+2)]:border-b [&>*:nth-child(-n+2)]:border-ink-600/60 lg:[&>*:nth-child(-n+2)]:border-b-0">
        {[
          ['Total scans', stats.totalScans, `${stats.uniqueDomains} unique domains`],
          ['Average risk score', stats.averageScore, 'Across all scans'],
          ['Unknown but suspicious', stats.unknownSuspiciousCount, 'Caught with no blacklist hit'],
          ['Watched sites', stats.watchlistCount, `${stats.activeIncidents} open investigations`]
        ].map(([label, value, detail]) => (
          <div key={label} className="px-5 py-4">
            <div className="text-[13px] text-fog-400">{label}</div>
            <div className="num mt-1 text-[30px] font-semibold leading-none text-white">{value}</div>
            <div className="mt-1.5 text-[12px] text-fog-400">{detail}</div>
          </div>
        ))}
      </section>

      <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
        <Panel title="Severity mix" subtitle="Share of all scans by risk level">
          <div className="flex flex-col items-center gap-6 sm:flex-row">
            <div className="relative">
              <Donut segments={segments} total={total} />
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="num text-[28px] font-semibold text-white">{total}</span>
                <span className="text-[12px] text-fog-400">scans</span>
              </div>
            </div>
            <ul className="w-full space-y-2.5">
              {segments.map((s) => (
                <li key={s.label} className="flex items-center gap-3 text-[14px]">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
                  <span className="flex-1 text-fog-100">{s.label}</span>
                  <span className="num text-white">{s.value}</span>
                  <span className="num w-10 text-right text-fog-400">{pct(s.value)}%</span>
                </li>
              ))}
            </ul>
          </div>
        </Panel>

        <Panel title="Highest-risk sites right now" subtitle="Latest result per domain" bodyClassName="p-0">
          {stats.topThreats?.length ? (
            <table className="data-table">
              <tbody>
                {stats.topThreats.map((t) => (
                  <tr key={t.id} className="cursor-pointer" onClick={() => onOpenScan(t)}>
                    <td className="max-w-[240px]">
                      <span className="domain block truncate">{t.domain}</span>
                      <span className="block truncate text-[12px] text-fog-400">{t.primaryPattern}</span>
                    </td>
                    <td className="text-right">
                      <RiskBadge level={t.risk_level} score={t.score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="p-5 text-[13px] text-fog-400">No high-risk sites yet.</p>
          )}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Scam patterns detected" subtitle="Primary pattern per scan">
          {patterns.length ? <BarList entries={patterns} color={(name) => (/verified|enterprise/i.test(name) ? RISK.LOW.color : '#A78BFA')} /> : <p className="text-[13px] text-fog-400">No data yet.</p>}
        </Panel>
        <Panel title="Website categories" subtitle="How each scanned site was classified">
          {classes.length ? <BarList entries={classes} color={(name) => (/legit|low-risk/i.test(name) ? RISK.LOW.color : /unknown|unclassified/i.test(name) ? '#8188BA' : '#22D3EE')} /> : <p className="text-[13px] text-fog-400">No data yet.</p>}
        </Panel>
      </div>
    </div>
  );
}
