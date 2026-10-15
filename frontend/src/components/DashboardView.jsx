import React, { useMemo, useState } from 'react';
import { Radar, Zap, ArrowRight, ShieldAlert, Link2, Loader2, X, Layers } from 'lucide-react';
import RadarScope from './RadarScope';
import { Panel, RiskBadge, EmptyState } from './ui';
import { RISK, latestPerDomain, timeAgo } from '../lib/risk';

const EXAMPLES = [
  { label: 'Ponzi yield site', url: 'daily-crypto-roi-1000.top/invest' },
  { label: 'Bank KYC phish', url: 'sbi-kyc-update.online/login' },
  { label: 'New betting app', url: 'bet777-instant-win.online' },
  { label: 'Known good', url: 'github.com' }
];

function ActivityChart({ trend = [] }) {
  const W = 640;
  const H = 200;
  const pad = { l: 28, r: 32, t: 12, b: 26 };
  const innerW = W - pad.l - pad.r;
  const innerH = H - pad.t - pad.b;
  const maxScans = Math.max(4, ...trend.map((d) => d.scans));
  const band = innerW / Math.max(1, trend.length);
  const barW = Math.min(22, band * 0.56);
  const yScans = (v) => pad.t + innerH - (v / maxScans) * innerH;
  const yScore = (v) => pad.t + innerH - (v / 100) * innerH;
  const scorePts = trend.map((d, i) => (d.avgScore === null ? null : [pad.l + band * i + band / 2, yScore(d.avgScore)])).filter(Boolean);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Scans per day for the last 14 days with average risk score">
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={pad.l} x2={W - pad.r} y1={pad.t + innerH * (1 - f)} y2={pad.t + innerH * (1 - f)} stroke="#1C2148" />
          <text x={pad.l - 8} y={pad.t + innerH * (1 - f) + 4} textAnchor="end" fontSize="10.5" fill="#606795" fontFamily="IBM Plex Sans">
            {Math.round(maxScans * f)}
          </text>
          <text x={W - pad.r + 8} y={pad.t + innerH * (1 - f) + 4} fontSize="10.5" fill="#22D3EE" fillOpacity="0.7" fontFamily="IBM Plex Sans">
            {Math.round(100 * f)}
          </text>
        </g>
      ))}
      {trend.map((d, i) => {
        const x = pad.l + band * i + (band - barW) / 2;
        const safe = d.scans - d.highRisk;
        return (
          <g key={d.date}>
            <title>{`${d.date}: ${d.scans} scans, ${d.highRisk} high risk${d.avgScore !== null ? `, avg score ${d.avgScore}` : ''}`}</title>
            {safe > 0 && <rect x={x} y={yScans(d.scans)} width={barW} height={yScans(d.highRisk) - yScans(d.scans)} rx="3" fill="#7C3AED" fillOpacity="0.75" />}
            {d.highRisk > 0 && <rect x={x} y={yScans(d.highRisk)} width={barW} height={pad.t + innerH - yScans(d.highRisk)} rx="3" fill="#F43F5E" fillOpacity="0.85" />}
            {(i % 2 === 0 || i === trend.length - 1) && (
              <text x={x + barW / 2} y={H - 8} textAnchor="middle" fontSize="10.5" fill="#606795" fontFamily="IBM Plex Sans">
                {new Date(`${d.date}T00:00:00Z`).toLocaleDateString([], { day: 'numeric', month: 'short', timeZone: 'UTC' })}
              </text>
            )}
          </g>
        );
      })}
      {scorePts.length > 1 && (
        <polyline points={scorePts.map((p) => p.join(',')).join(' ')} fill="none" stroke="#22D3EE" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      )}
      {scorePts.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r="3" fill="#07081A" stroke="#22D3EE" strokeWidth="1.75" />
      ))}
    </svg>
  );
}

function Kpi({ label, value, detail, accent }) {
  return (
    <div className="p-3 sm:px-5 sm:py-4">
      <div className="text-[11.5px] sm:text-[13px] text-fog-400">{label}</div>
      <div className="num mt-1 text-[22px] sm:text-[28px] lg:text-[30px] font-semibold leading-none" style={{ color: accent || '#fff' }}>
        {value ?? '—'}
      </div>
      <div className="mt-1.5 text-[11px] sm:text-[12px] text-fog-400 leading-snug line-clamp-2">{detail}</div>
    </div>
  );
}

export default function DashboardView({ stats, recentScans = [], queue = [], scanning, onScan, onPreExecution, onOpenScan, onNavigate }) {
  const [url, setUrl] = useState('');
  const latest = useMemo(() => latestPerDomain(recentScans), [recentScans]);

  const levelCounts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    latest.forEach((s) => (c[s.risk_level] = (c[s.risk_level] || 0) + 1));
    return c;
  }, [latest]);

  const classes = useMemo(
    () =>
      Object.entries(stats?.classificationDistribution || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6),
    [stats]
  );
  const maxClass = classes[0]?.[1] || 1;

  const openIncidents = queue.filter((q) => !['Reviewed', 'Allowed'].includes(q.status));

  const submit = (e) => {
    e.preventDefault();
    if (url.trim()) onScan(url.trim());
  };

  return (
    <div className="space-y-5 sm:space-y-6 animate-fade-in">
      {/* Hero: scan input + live radar */}
      <section className="panel relative overflow-hidden">
        <div className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-brand-600/20 blur-3xl" aria-hidden />
        <div className="relative grid gap-6 p-4 sm:p-6 lg:p-8 lg:grid-cols-[1.15fr_1fr] lg:items-center">
          <div>
            <h1 className="font-display text-[26px] sm:text-[36px] lg:text-[44px] font-semibold leading-[1.1] tracking-wide text-white">
              Check a website
              <br />
              before you trust it.
            </h1>
            <p className="mt-3 sm:mt-4 max-w-lg text-[13.5px] sm:text-[15px] leading-relaxed text-fog-300">
              Risk Radar reads a site’s domain age, hosting neighbours, contact details and page promises — and flags scams,
              betting traps and phishing even when no blacklist has seen them yet.
            </p>

            <form onSubmit={submit} className="mt-5 sm:mt-7">
              <label htmlFor="hero-url" className="sr-only">
                Website to scan
              </label>
              <div className="flex flex-col gap-2 rounded-2xl border border-ink-500/60 bg-ink-900/80 p-2 focus-within:border-brand-400/70 focus-within:ring-4 focus-within:ring-brand-500/15 sm:flex-row sm:items-center">
                <div className="flex min-w-0 flex-1 items-center">
                  <Link2 className="ml-2 h-4 w-4 shrink-0 text-fog-400" aria-hidden />
                  <input
                    id="hero-url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="Paste a link, e.g. daily-crypto-roi-1000.top"
                    autoComplete="off"
                    spellCheck="false"
                    className="w-full min-w-0 bg-transparent px-2.5 sm:px-3 py-2 sm:py-2.5 font-mono text-[13px] sm:text-[14px] text-white placeholder:font-sans placeholder:text-fog-500 focus:outline-none"
                  />
                  {url && (
                    <button
                      type="button"
                      onClick={() => setUrl('')}
                      className="mr-2 shrink-0 rounded p-1 text-fog-400 hover:text-white"
                      aria-label="Clear URL"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
                <button type="submit" disabled={scanning || !url.trim()} className="btn-primary w-full sm:w-auto shrink-0 px-4 sm:px-5 py-2.5 sm:py-3 text-[13px] sm:text-[14px]">
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Zap className="h-4 w-4" aria-hidden />}
                  {scanning ? 'Scanning…' : 'Scan website'}
                </button>
              </div>
            </form>

            <div className="mt-4 flex flex-wrap items-center gap-2 text-[13px]">
              <span className="text-fog-400">Try</span>
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.url}
                  type="button"
                  onClick={() => {
                    setUrl(ex.url);
                    onScan(ex.url);
                  }}
                  disabled={scanning}
                  className="rounded-full border border-ink-500/70 bg-ink-800/70 px-3 py-1 text-fog-200 transition-colors hover:border-brand-400/60 hover:text-white disabled:opacity-50"
                >
                  {ex.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => onPreExecution(url.trim())}
              className="mt-7 flex w-full max-w-lg items-center gap-4 rounded-xl border border-signal-400/25 bg-signal-400/[0.06] px-4 py-3 text-left transition-colors hover:border-signal-400/50 hover:bg-signal-400/10"
            >
              <Radar className="h-5 w-5 shrink-0 text-signal-400" aria-hidden />
              <span className="flex-1">
                <span className="block text-[14px] font-semibold text-white">Unknown isn’t safe</span>
                <span className="block text-[13px] leading-snug text-fog-300">
                  Run a pre-execution scan to see every intelligence source behind the score, without loading the site.
                </span>
              </span>
              <ArrowRight className="h-4 w-4 shrink-0 text-signal-300" aria-hidden />
            </button>

            <button
              type="button"
              onClick={() => onNavigate('7d-engine')}
              className="mt-3 flex w-full max-w-lg items-center gap-4 rounded-xl border border-brand-500/30 bg-brand-500/[0.08] px-4 py-3 text-left transition-colors hover:border-brand-400/60 hover:bg-brand-500/15"
            >
              <Layers className="h-5 w-5 shrink-0 text-brand-400" aria-hidden />
              <span className="flex-1">
                <span className="block text-[14px] font-semibold text-white">7D Multidimensional Risk Engine</span>
                <span className="block text-[13px] leading-snug text-fog-300">
                  Correlate Domain, Infrastructure, Content, Claims, Behavior, Identity & Threat Feeds.
                </span>
              </span>
              <ArrowRight className="h-4 w-4 shrink-0 text-brand-300" aria-hidden />
            </button>
          </div>

          <div>
            <RadarScope scans={recentScans} onSelect={onOpenScan} />
            <div className="mt-3 flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[12px] text-fog-400">
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((l) => (
                <span key={l} className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: RISK[l].color }} />
                  {RISK[l].label} <span className="num text-fog-200">{levelCounts[l]}</span>
                </span>
              ))}
              <span className="text-fog-500">· nearer the centre = riskier</span>
            </div>
          </div>
        </div>
      </section>

      {/* KPI strip */}
      <section className="panel grid grid-cols-2 divide-ink-600/60 lg:grid-cols-4 lg:divide-x [&>*:nth-child(-n+2)]:border-b [&>*:nth-child(-n+2)]:border-ink-600/60 lg:[&>*:nth-child(-n+2)]:border-b-0">
        <Kpi label="Sites scanned" value={stats?.totalScans} detail={stats ? `${stats.scansToday} today · ${stats.uniqueDomains} unique domains` : 'Loading…'} />
        <Kpi
          label="High or critical"
          value={stats ? stats.criticalCount + stats.highCount : undefined}
          accent={RISK.HIGH.color}
          detail={stats ? `${stats.criticalCount} critical across all scans` : ''}
        />
        <Kpi
          label="Unknown but suspicious"
          value={stats?.unknownSuspiciousCount}
          accent="#22D3EE"
          detail="No blacklist hit, yet risky signals"
        />
        <Kpi label="Open investigations" value={stats?.activeIncidents} accent={RISK.CRITICAL.color} detail={stats ? `${stats.blockedCount} blocked so far` : ''} />
      </section>

      {/* Activity + mix */}
      <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
        <Panel
          title="Scan activity"
          subtitle="Last 14 days"
          action={
            <div className="hidden items-center gap-3 text-[12px] text-fog-400 sm:flex">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-brand-600" />Scans</span>
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-risk-critical" />High risk</span>
              <span className="inline-flex items-center gap-1.5"><span className="h-0.5 w-3 rounded bg-signal-400" />Avg score</span>
            </div>
          }
        >
          {stats?.trend ? <ActivityChart trend={stats.trend} /> : <div className="h-48 animate-pulse rounded-xl bg-ink-800" />}
        </Panel>

        <Panel title="What we’re finding" subtitle="Website classification across all scans">
          {classes.length === 0 ? (
            <p className="text-[13px] text-fog-400">Run a scan to see the mix.</p>
          ) : (
            <ul className="space-y-3">
              {classes.map(([name, n]) => (
                <li key={name}>
                  <div className="flex items-baseline justify-between gap-3 text-[13px]">
                    <span className="truncate text-fog-100">{name}</span>
                    <span className="num text-fog-300">{n}</span>
                  </div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-ink-700">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${(n / maxClass) * 100}%`,
                        background: /legit|low-risk/i.test(name) ? RISK.LOW.color : /unknown|unclassified/i.test(name) ? '#8188BA' : '#A78BFA'
                      }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {/* Recent + needs attention */}
      <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
        <Panel
          title="Recent scans"
          subtitle="Latest result per domain"
          bodyClassName="p-0"
          action={
            <button type="button" className="btn-ghost btn-sm" onClick={() => onNavigate('history')}>
              All scans <ArrowRight className="h-3.5 w-3.5" />
            </button>
          }
        >
          {latest.length === 0 ? (
            <EmptyState icon={Radar} title="Nothing scanned yet">
              Paste a link above to run your first scan.
            </EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Website</th>
                    <th className="hidden md:table-cell">Looks like</th>
                    <th>Risk</th>
                    <th className="hidden text-right sm:table-cell">Scanned</th>
                  </tr>
                </thead>
                <tbody>
                  {latest.slice(0, 7).map((s) => (
                    <tr key={s.id} className="cursor-pointer" onClick={() => onOpenScan(s)}>
                      <td className="max-w-[220px]">
                        <button type="button" className="domain block max-w-full truncate text-left hover:text-signal-300" onClick={(e) => { e.stopPropagation(); onOpenScan(s); }}>
                          {s.domain}
                        </button>
                      </td>
                      <td className="hidden max-w-[220px] truncate text-fog-300 md:table-cell">{s.classification?.primary || s.primaryPattern}</td>
                      <td>
                        <RiskBadge level={s.risk_level} score={s.score} />
                      </td>
                      <td className="hidden whitespace-nowrap text-right text-fog-400 sm:table-cell">{timeAgo(s.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Needs attention"
          subtitle={`${openIncidents.length} open investigation${openIncidents.length === 1 ? '' : 's'}`}
          icon={ShieldAlert}
          action={
            <button type="button" className="btn-ghost btn-sm" onClick={() => onNavigate('investigations')}>
              Triage <ArrowRight className="h-3.5 w-3.5" />
            </button>
          }
        >
          {(stats?.topThreats || []).length === 0 ? (
            <p className="text-[13px] text-fog-400">No high-risk sites right now.</p>
          ) : (
            <ul className="-my-2 divide-y divide-ink-700/70">
              {stats.topThreats.map((t) => (
                <li key={t.id}>
                  <button type="button" onClick={() => onOpenScan(t)} className="group flex w-full items-center gap-3 py-2.5 text-left">
                    <span className="num w-9 shrink-0 text-[20px] font-semibold" style={{ color: RISK[t.risk_level]?.color }}>
                      {t.score}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="domain block truncate group-hover:text-signal-300">{t.domain}</span>
                      <span className="block truncate text-[12px] text-fog-400">{t.primaryPattern}</span>
                    </span>
                    <ArrowRight className="h-4 w-4 shrink-0 text-fog-500 group-hover:text-fog-200" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
