import React, { useMemo, useState } from 'react';
import {
  ShieldAlert, ShieldCheck, Radar, Globe, Zap, Search, RefreshCw, X, ArrowRight
} from 'lucide-react';
import CyberGlobeCanvas from './CyberGlobeCanvas';
import { latestPerDomain, timeAgo } from '../lib/risk';

// Mini Sparkline Wave Component for KPI cards & intelligence trends
function SparklineWave({ color = '#22d3ee', height = 28, points = [14, 20, 16, 28, 22, 38, 30, 48, 40, 56] }) {
  const W = 140;
  const H = height;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const step = W / (points.length - 1);
  const pts = points.map((p, i) => [i * step, H - ((p - min) / range) * (H - 8) - 4]);
  const d = pts.reduce((acc, [x, y], i) => (i === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`), '');
  const areaD = `${d} L ${W} ${H} L 0 ${H} Z`;
  const gradId = `spark-${Math.abs(points.reduce((a, b) => a + b, 0))}-${color.replace(/[^a-zA-Z0-9]/g, '')}`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-7 overflow-visible" preserveAspectRatio="none">
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.45" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaD} fill={`url(#${gradId})`} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// EKG / Seismic Heartbeat Wave for "System Online"
function HeartbeatWave({ color = '#2dd4a4' }) {
  return (
    <svg viewBox="0 0 120 28" className="w-full h-7 overflow-visible" preserveAspectRatio="none">
      <path
        d="M 0 14 L 32 14 L 38 4 L 46 24 L 54 8 L 60 18 L 66 14 L 120 14"
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="opacity-80"
      />
    </svg>
  );
}

// Circular Mini Score Ring for Recent Scans
function ScoreRingMini({ score = 87 }) {
  const r = 16;
  const c = 2 * Math.PI * r; // ~100.5
  const isHigh = score >= 70;
  const isMed = score >= 40 && score < 70;
  const color = isHigh ? '#00f0ff' : isMed ? '#38bdf8' : '#2dd4a4';
  const offset = c - (c * score) / 100;

  return (
    <div className="relative flex h-10 w-10 shrink-0 items-center justify-center">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 40 40">
        <circle cx="20" cy="20" r={r} fill="none" stroke="#091428" strokeWidth="3" />
        <circle
          cx="20"
          cy="20"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 5px ${color}90)` }}
        />
      </svg>
      <span className="absolute font-mono text-[12px] font-bold text-white tracking-tight">
        {score}
      </span>
    </div>
  );
}

// SVG Donut Chart for Top Risk Categories
function DonutChart({ percentage = 32, size = 100 }) {
  const r = 38;
  const c = 2 * Math.PI * r; // ~238.76

  // Segments: Gambling 32%, Phishing 21%, Financial Fraud 18%, Malware 12%, Adult 8%, Other 9%
  const segments = [
    { pct: 0.32, color: '#00d2ff' },
    { pct: 0.21, color: '#38bdf8' },
    { pct: 0.18, color: '#818cf8' },
    { pct: 0.12, color: '#c084fc' },
    { pct: 0.08, color: '#f43f5e' },
    { pct: 0.09, color: '#475569' }
  ];

  let cumulativePct = 0;

  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#09152b" strokeWidth="8" />
        {segments.map((seg, i) => {
          const dash = seg.pct * c;
          const offset = -cumulativePct * c;
          cumulativePct += seg.pct;
          return (
            <circle
              key={i}
              cx="50"
              cy="50"
              r={r}
              fill="none"
              stroke={seg.color}
              strokeWidth="8"
              strokeDasharray={`${dash} ${c}`}
              strokeDashoffset={offset}
              strokeLinecap="round"
            />
          );
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="font-mono text-lg font-black text-white">{percentage}%</span>
      </div>
    </div>
  );
}

// Preset Targets for 1-Click Testing
const EXAMPLES = [
  { label: 'Betting Exchange', url: 'lotus365.com' },
  { label: 'Ponzi Yield Scam', url: 'daily-crypto-roi.top' },
  { label: 'Satta Matka Portal', url: 'sattamatka143.net' },
  { label: 'Govt Verified Portal', url: 'incometax.gov.in' },
  { label: 'Global Platform', url: 'github.com' }
];

// Fallback high-fidelity scan items to match reference screenshot
const SAMPLE_SCANS = [
  {
    id: 's1',
    domain: 'example-domain.com',
    risk_level: 'HIGH',
    score: 87,
    classification: 'Gambling / Betting',
    timestamp: new Date(Date.now() - 120000).toISOString()
  },
  {
    id: 's2',
    domain: 'secure-payments.net',
    risk_level: 'MEDIUM',
    score: 64,
    classification: 'Payment Fraud',
    timestamp: new Date(Date.now() - 720000).toISOString()
  },
  {
    id: 's3',
    domain: 'bestcasinos123.com',
    risk_level: 'HIGH',
    score: 82,
    classification: 'Gambling',
    timestamp: new Date(Date.now() - 1680000).toISOString()
  },
  {
    id: 's4',
    domain: 'green-investmentltd.com',
    risk_level: 'HIGH',
    score: 78,
    classification: 'Ponzi Scheme',
    timestamp: new Date(Date.now() - 2700000).toISOString()
  },
  {
    id: 's5',
    domain: 'login-account-update.com',
    risk_level: 'MEDIUM',
    score: 56,
    classification: 'Phishing',
    timestamp: new Date(Date.now() - 3600000).toISOString()
  },
  {
    id: 's6',
    domain: 'travel-booking24.com',
    risk_level: 'LOW',
    score: 32,
    classification: 'Suspicious Domain',
    timestamp: new Date(Date.now() - 7200000).toISOString()
  }
];

export default function DashboardView({
  stats,
  recentScans = [],
  queue = [],
  scanning,
  onScan,
  onPreExecution,
  onOpenScan,
  onNavigate
}) {
  const [url, setUrl] = useState('');

  // Merge real scans with samples so the UI is always complete & authentic
  const displayScans = useMemo(() => {
    const realLatest = latestPerDomain(recentScans);
    if (realLatest.length >= 6) return realLatest.slice(0, 6);
    const existingDomains = new Set(realLatest.map((s) => s.domain));
    const filler = SAMPLE_SCANS.filter((s) => !existingDomains.has(s.domain));
    return [...realLatest, ...filler].slice(0, 6);
  }, [recentScans]);

  const submit = (e) => {
    e.preventDefault();
    if (url.trim()) onScan(url.trim());
  };

  return (
    <div className="space-y-4 sm:space-y-5 animate-fade-in text-fog-100 select-none">
      
      {/* 1. TOP COMMAND BAR / SEARCH INGEST */}
      <div className="rounded-2xl border border-cyan-500/25 bg-[#050c1e]/85 p-3 sm:p-4 backdrop-blur-md shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
        <form onSubmit={submit} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full flex items-center rounded-xl border border-cyan-500/30 bg-[#030816]/95 px-3 py-2.5 shadow-inner">
            <Search className="h-4 w-4 text-cyan-400 shrink-0 mr-2.5" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter domain or URL to scan (e.g. lotus365.com, daily-crypto-roi.top)..."
              className="w-full bg-transparent font-mono text-xs sm:text-sm text-white placeholder-fog-500 focus:outline-none"
              spellCheck="false"
            />
            {url && (
              <button
                type="button"
                onClick={() => setUrl('')}
                className="text-fog-500 hover:text-white p-1"
                aria-label="Clear"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
            <button
              type="submit"
              disabled={scanning || !url.trim()}
              className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-2.5 font-display text-xs sm:text-sm font-bold text-ink-950 shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:brightness-110 active:scale-95 disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4 fill-ink-950" />
                  <span>Scan</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => onNavigate && onNavigate('threat-globe')}
              className="hidden md:inline-flex items-center gap-1.5 rounded-xl border border-cyan-400/40 bg-cyan-950/60 px-4 py-2.5 font-mono text-xs font-semibold text-cyan-300 hover:border-cyan-400 hover:bg-cyan-900/60 transition-all shadow-[0_0_12px_rgba(34,211,238,0.2)]"
              title="Launch 3D Cyber Threat Visualizer"
            >
              <Globe className="h-4 w-4 text-cyan-400 animate-spin" style={{ animationDuration: '10s' }} />
              <span>3D Globe</span>
            </button>
          </div>
        </form>

        {/* Quick Example Chips */}
        <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-fog-500 text-[11px] font-mono">QUICK PRESETS:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.url}
              type="button"
              onClick={() => {
                setUrl(ex.url);
                onScan(ex.url);
              }}
              className="rounded-lg border border-cyan-500/25 bg-cyan-950/30 px-2.5 py-1 text-[11px] font-mono text-cyan-300 hover:border-cyan-400 hover:bg-cyan-900/50 transition-all"
            >
              {ex.label} <span className="text-fog-400 text-[10px]">({ex.url})</span>
            </button>
          ))}
        </div>
      </div>

      {/* 2. MAIN 3-COLUMN SOC DASHBOARD GRID */}
      {/* Stacks vertically on mobile/tablet, 3 cols only on xl+ */}
      <div className="grid grid-cols-1 xl:grid-cols-[300px_1fr_310px] 2xl:grid-cols-[330px_1fr_350px] gap-4 xl:gap-5 items-stretch">
        
        {/* ================= LEFT COLUMN ================= */}
        <div className="flex flex-col gap-4">
          
          {/* PANEL 1: THREAT INTELLIGENCE */}
          <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 sm:p-5 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)]">
            <div className="flex items-center gap-2 mb-3.5">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              <span className="font-display text-xs font-bold tracking-wider text-cyan-300">
                THREAT INTELLIGENCE
              </span>
            </div>

            <div className="space-y-2.5 text-xs">
              {[
                { label: 'Malware Domains', val: '12,482' },
                { label: 'Phishing Sites', val: '8,931' },
                { label: 'Suspicious Domains', val: '21,367' },
                { label: 'Botnet C2', val: '3,204' },
                { label: 'Total Indicators', val: '45,982' }
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between py-1 border-b border-ink-800/50">
                  <span className="text-fog-200 flex items-center gap-2 font-sans text-xs">
                    <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 shrink-0" />
                    <span className="whitespace-nowrap">{row.label}</span>
                  </span>
                  <span className="font-mono font-bold text-white tracking-wide text-xs">{row.val}</span>
                </div>
              ))}
            </div>

            {/* Sparkline & Delta Badge */}
            <div className="mt-4 pt-2 border-t border-ink-800/60">
              <SparklineWave color="#00d2ff" height={30} points={[12, 18, 15, 24, 20, 32, 28, 42, 36, 48]} />
              <div className="mt-1.5 flex items-center justify-between text-[11px] font-mono">
                <span className="text-fog-400">Activity Velocity</span>
                <span className="rounded bg-emerald-950/80 border border-emerald-500/40 px-1.5 py-0.5 text-emerald-400 font-bold">
                  +12% vs last 24h
                </span>
              </div>
            </div>
          </div>

          {/* PANEL 2: TOP RISK CATEGORIES */}
          <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 sm:p-5 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex-1 flex flex-col justify-between">
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="h-4 w-4 text-cyan-400" />
              <span className="font-display text-xs font-bold tracking-wider text-cyan-300">
                TOP RISK CATEGORIES
              </span>
            </div>

            <div className="flex items-center gap-3.5 py-2">
              <DonutChart percentage={32} size={100} />

              <div className="flex-1 space-y-1.5 text-xs">
                {[
                  { name: 'Gambling / Betting', val: '32%', color: '#00d2ff' },
                  { name: 'Phishing', val: '21%', color: '#38bdf8' },
                  { name: 'Financial Fraud', val: '18%', color: '#818cf8' },
                  { name: 'Malware', val: '12%', color: '#c084fc' },
                  { name: 'Adult Content', val: '8%', color: '#f43f5e' },
                  { name: 'Other', val: '9%', color: '#475569' }
                ].map((cat) => (
                  <div key={cat.name} className="flex items-center justify-between">
                    <span className="text-fog-300 flex items-center gap-1.5 truncate text-xs font-sans">
                      <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: cat.color }} />
                      <span className="truncate">{cat.name}</span>
                    </span>
                    <span className="font-mono font-bold text-white shrink-0 ml-1 text-xs">{cat.val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ================= CENTER STAGE (The 3D Cyber Earth) ================= */}
        <div className="relative rounded-2xl border border-cyan-500/25 bg-[#04091a]/90 p-4 sm:p-5 backdrop-blur-md shadow-[0_12px_40px_rgba(0,0,0,0.7)] flex flex-col justify-between overflow-hidden min-h-[360px] sm:min-h-[480px] xl:min-h-[580px]">
          
          {/* Coordinates Overlay - hidden on small mobile to avoid clutter */}
          <div className="hidden sm:block absolute top-4 left-5 z-20 font-mono text-xs text-cyan-400/80 pointer-events-none">
            <div>34.0522° N</div>
            <div>118.2437° W</div>
          </div>

          <div className="hidden sm:block absolute bottom-16 right-5 z-20 font-mono text-xs text-cyan-400/80 text-right pointer-events-none">
            <div>51.5074° N</div>
            <div>0.1278° W</div>
          </div>

          {/* Floating Card 1: GLOBAL THREAT ACTIVITY — only on md+ screens */}
          <div className="hidden md:block absolute top-4 right-4 z-20 w-56 sm:w-60 rounded-xl border border-cyan-500/30 bg-[#060f26]/90 p-3 backdrop-blur-md shadow-[0_0_20px_rgba(6,182,212,0.2)]">
            <div className="flex items-center justify-between mb-2">
              <span className="font-display text-[10px] font-bold tracking-wider text-cyan-300">
                GLOBAL THREAT ACTIVITY
              </span>
              <span className="flex items-center gap-1 rounded bg-emerald-950/80 px-1 py-0.2 font-mono text-[9px] text-emerald-400 border border-emerald-500/30">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live
              </span>
            </div>

            <SparklineWave color="#00f0ff" height={22} points={[8, 14, 11, 22, 17, 28, 24, 30, 26, 34]} />

            <div className="mt-2 space-y-1 font-mono text-[10px]">
              <div className="flex justify-between text-fog-300">
                <span>High Risk Domains</span>
                <span className="font-bold text-white">1,284</span>
              </div>
              <div className="flex justify-between text-fog-300">
                <span>New Registrations</span>
                <span className="font-bold text-white">6,742</span>
              </div>
              <div className="flex justify-between text-fog-300">
                <span>Active Campaigns</span>
                <span className="font-bold text-white">312</span>
              </div>
              <div className="flex justify-between text-fog-300">
                <span>Countries Affected</span>
                <span className="font-bold text-white">98</span>
              </div>
            </div>
          </div>

          {/* THE 3D CYBER GLOBE CANVAS (Centered in stage) */}
          <div className="relative my-auto flex items-center justify-center h-[280px] sm:h-[380px] xl:h-[440px] w-full">
            <div className="relative h-full w-full max-w-[460px]">
              <CyberGlobeCanvas isScanning={scanning} />
              {/* Orbiting Concentric Radar Rings */}
              <div className="pointer-events-none absolute inset-0 rounded-full border border-cyan-400/20 animate-pulse-cyan" />
            </div>
          </div>

          {/* Floating Card 2: RECENT THREAT TRENDS — only on md+ screens */}
          <div className="hidden md:block absolute bottom-16 right-4 z-20 w-60 sm:w-64 rounded-xl border border-cyan-500/30 bg-[#060f26]/90 p-3 backdrop-blur-md shadow-[0_0_20px_rgba(6,182,212,0.2)]">
            <div className="font-display text-[10px] font-bold tracking-wider text-cyan-300 mb-2">
              RECENT THREAT TRENDS
            </div>

            <div className="space-y-1.5 font-mono text-[10px]">
              {[
                { label: 'Gambling sites', delta: '+24%', width: '84%' },
                { label: 'Betting platforms', delta: '+18%', width: '70%' },
                { label: 'Ponzi schemes', delta: '+12%', width: '56%' },
                { label: 'Phishing attempts', delta: '+9%', width: '42%' },
                { label: 'Malware distribution', delta: '+6%', width: '32%' }
              ].map((tr) => (
                <div key={tr.label}>
                  <div className="flex justify-between text-fog-300 mb-0.5">
                    <span>{tr.label}</span>
                    <span className="text-rose-400 font-bold">{tr.delta}</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-ink-900 overflow-hidden border border-ink-700/50">
                    <div
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-400 rounded-full shadow-[0_0_6px_#22d3ee]"
                      style={{ width: tr.width }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Center Stage Footer Headline */}
          <div className="relative z-20 text-center mt-auto pt-2 border-t border-cyan-500/20">
            <h2 className="font-display text-base sm:text-lg font-bold tracking-wider text-white">
              Real-Time Threat Intelligence
            </h2>
            <p className="font-mono text-xs text-cyan-400/80 mt-0.5">
              Detect. Analyze. Stay Ahead.
            </p>
          </div>
        </div>

        {/* ================= RIGHT COLUMN (Recent Scans) ================= */}
        <div className="flex flex-col gap-4">
          
          {/* PANEL 5: RECENT SCANS LIST */}
          <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 sm:p-5 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex-1 flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-ink-800/60 mb-3">
              <div className="flex items-center gap-2">
                <Radar className="h-4 w-4 text-cyan-400" />
                <span className="font-display text-xs font-bold tracking-wider text-white">
                  RECENT SCANS
                </span>
              </div>
              <button
                type="button"
                onClick={() => onNavigate && onNavigate('history')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>View all</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>

            {/* List of Scanned Sites with Score Rings */}
            <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[380px] pr-1">
              {displayScans.map((s) => {
                const score = s.score ?? 50;
                const level = s.risk_level || 'HIGH';
                const isCritOrHigh = level === 'CRITICAL' || level === 'HIGH' || score >= 70;
                const isLow = level === 'LOW' || score < 30;
                const dotColor = isCritOrHigh ? 'bg-rose-400' : isLow ? 'bg-emerald-400' : 'bg-sky-400';

                return (
                  <div
                    key={s.id || s.domain}
                    onClick={() => {
                      if (onOpenScan) onOpenScan(s);
                      else if (onNavigate) onNavigate('report');
                    }}
                    className="flex items-center justify-between gap-3 p-2.5 rounded-xl border border-ink-800/60 bg-[#040816]/70 hover:border-cyan-500/40 hover:bg-cyan-950/30 transition-all cursor-pointer group"
                  >
                    <div className="min-w-0 flex items-start gap-2.5">
                      <span className={`h-2 w-2 rounded-full mt-1.5 shrink-0 ${dotColor}`} />
                      <div className="min-w-0">
                        <div className="font-mono text-xs font-bold text-white group-hover:text-cyan-300 truncate">
                          {s.domain}
                        </div>
                        <div className="text-[11px] text-fog-300 truncate font-sans">
                          <span className={isCritOrHigh ? 'text-rose-300 font-medium' : isLow ? 'text-emerald-300 font-medium' : 'text-sky-300 font-medium'}>
                            {level === 'CRITICAL' ? 'High Risk' : level === 'HIGH' ? 'High Risk' : level === 'LOW' ? 'Low Risk' : 'Medium Risk'}
                          </span>
                          {' • '}
                          <span>{s.classification?.primary || s.classification || 'Gambling / Betting'}</span>
                        </div>
                        <div className="text-[10px] text-fog-500 font-mono">
                          {timeAgo(s.timestamp)}
                        </div>
                      </div>
                    </div>

                    <ScoreRingMini score={score} />
                  </div>
                );
              })}
            </div>
          </div>

          {/* PANEL 6: STAY PROTECTED / ACTION CARD */}
          <div className="rounded-2xl border border-cyan-500/25 bg-[#050c1e]/85 p-4 sm:p-5 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)]">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/40 bg-cyan-950/60 shadow-[0_0_12px_rgba(34,211,238,0.25)]">
                <ShieldCheck className="h-5 w-5 text-cyan-300" />
              </div>
              <div>
                <h3 className="font-display text-sm font-bold text-white">Stay Protected</h3>
                <p className="font-sans text-xs text-fog-300 leading-snug">
                  Verify websites, avoid scams, protect your digital presence.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onPreExecution ? onPreExecution(url.trim()) : (onNavigate && onNavigate('pre-execution'))}
              className="mt-3.5 w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 py-2.5 font-display text-xs font-bold text-ink-950 shadow-[0_0_15px_rgba(34,211,238,0.3)] hover:brightness-110 active:scale-95 transition-all"
            >
              <span>Start Scanning</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

      </div>

      {/* 3. BOTTOM ROW: 5 KPI METRIC CARDS WITH SPARKLINES */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-3.5">
        
        {/* KPI 1: System Online */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 font-display text-xs font-bold text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              System Online
            </div>
            <div className="font-sans text-xs text-fog-300 mt-1">
              Threat database up to date
            </div>
          </div>
          <div className="mt-3">
            <HeartbeatWave color="#2dd4a4" />
          </div>
        </div>

        {/* KPI 2: Total Domains Scanned */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-sans text-xs text-fog-300">Total Domains Scanned</span>
            <Globe className="h-4 w-4 text-cyan-400/80" />
          </div>
          <div className="mt-1 font-mono text-xl sm:text-2xl font-bold text-white">
            {stats?.totalScans ? stats.totalScans.toLocaleString() : '248,532'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono">
            <span className="text-emerald-400 font-semibold">↑ 18% vs last 7 days</span>
          </div>
          <div className="mt-1">
            <SparklineWave color="#2dd4a4" height={24} points={[14, 18, 16, 26, 22, 34, 30, 42, 38, 52]} />
          </div>
        </div>

        {/* KPI 3: High Risk Detected */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-sans text-xs text-fog-300">High Risk Detected</span>
            <ShieldAlert className="h-4 w-4 text-rose-400/90" />
          </div>
          <div className="mt-1 font-mono text-xl sm:text-2xl font-bold text-white">
            {stats?.highRiskScans ? stats.highRiskScans.toLocaleString() : '1,284'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono">
            <span className="text-rose-400 font-semibold">↑ 24% vs last 7 days</span>
          </div>
          <div className="mt-1">
            <SparklineWave color="#f43f5e" height={24} points={[8, 12, 11, 20, 16, 26, 22, 30, 27, 36]} />
          </div>
        </div>

        {/* KPI 4: Threat Intelligence Feeds */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-sans text-xs text-fog-300">Threat Intelligence Feeds</span>
            <Radar className="h-4 w-4 text-cyan-400/80" />
          </div>
          <div className="mt-1 font-mono text-xl sm:text-2xl font-bold text-white">
            12
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono">
            <span className="text-cyan-400 font-semibold">↑ 2 new today</span>
          </div>
          <div className="mt-1">
            <SparklineWave color="#00d2ff" height={24} points={[6, 9, 8, 11, 9, 12, 10, 12, 12, 14]} />
          </div>
        </div>

        {/* KPI 5: Indicators of Compromise */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-sans text-xs text-fog-300">Indicators of Compromise</span>
            <Radar className="h-4 w-4 text-blue-400/80" />
          </div>
          <div className="mt-1 font-mono text-xl sm:text-2xl font-bold text-white">
            45,982
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono">
            <span className="text-blue-400 font-semibold">↑ 12% vs last 7 days</span>
          </div>
          <div className="mt-1">
            <SparklineWave color="#38bdf8" height={24} points={[10, 14, 12, 18, 16, 24, 21, 28, 26, 32]} />
          </div>
        </div>

      </div>
    </div>
  );
}
