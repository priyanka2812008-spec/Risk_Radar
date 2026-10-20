import React, { useMemo, useState, useEffect } from 'react';
import {
  BarChart3, ShieldAlert, AlertTriangle, Globe, Eye,
  Activity, ArrowRight, Zap, Radio, Layers
} from 'lucide-react';
import { RISK } from '../lib/risk';

// Mini Sparkline Wave Component for KPI cards
function SparklineWave({ color = '#22d3ee', height = 26, points = [14, 20, 16, 28, 22, 38, 30, 48, 40, 56] }) {
  const W = 140;
  const H = height;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const step = W / (points.length - 1);
  const pts = points.map((p, i) => [i * step, H - ((p - min) / range) * (H - 8) - 4]);
  const d = pts.reduce((acc, [x, y], i) => (i === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`), '');
  const areaD = `${d} L ${W} ${H} L 0 ${H} Z`;
  const gradId = `spark-threat-${Math.abs(points.reduce((a, b) => a + b, 0))}-${color.replace(/[^a-zA-Z0-9]/g, '')}`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-6 overflow-visible" preserveAspectRatio="none">
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaD} fill={`url(#${gradId})`} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// Circular Score Ring for Highest Risk Sites
function ScoreRingMini({ score = 87 }) {
  const r = 15;
  const c = 2 * Math.PI * r; // ~94.2
  const isHigh = score >= 70;
  const isMed = score >= 40 && score < 70;
  const color = isHigh ? '#f43f5e' : isMed ? '#fbbf24' : '#2dd4a4';
  const offset = c - (c * score) / 100;

  return (
    <div className="relative flex h-9 w-9 shrink-0 items-center justify-center">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r={r} fill="none" stroke="#091428" strokeWidth="2.5" />
        <circle
          cx="18"
          cy="18"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 5px ${color}80)` }}
        />
      </svg>
      <span className="absolute font-mono text-[11px] font-bold text-white tracking-tight">
        {score}
      </span>
    </div>
  );
}

// Fully Animated Interactive Cyber Severity Donut with Sweep & Hover Focus
function AnimatedSeverityMix({ segments, total }) {
  const [hovered, setHovered] = useState(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 120);
    return () => clearTimeout(t);
  }, []);

  const r = 62;
  const c = 2 * Math.PI * r; // ~389.55
  const pct = (v) => (total ? Math.round((v / total) * 100) : 0);
  const activeSegment = hovered ? segments.find((s) => s.label === hovered) : null;

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6 my-auto py-2">
      {/* Animated Donut Theater */}
      <div className="relative flex items-center justify-center shrink-0 h-48 w-48">
        {/* Outer Rotating Dashed Cyber Reticle */}
        <div
          className="absolute inset-0 rounded-full border border-dashed border-cyan-500/30 animate-spin pointer-events-none"
          style={{ animationDuration: '24s' }}
        />

        {/* Radar Sweep Beam Overlay */}
        <div className="absolute inset-2 rounded-full overflow-hidden pointer-events-none opacity-35">
          <div
            className="h-full w-full animate-radar-sweep-beam"
            style={{
              background: 'conic-gradient(from 0deg, transparent 0deg, transparent 280deg, rgba(34, 211, 238, 0.3) 360deg)'
            }}
          />
        </div>

        {/* SVG Donut */}
        <svg viewBox="0 0 160 160" className="h-44 w-44 -rotate-90 select-none overflow-visible">
          <circle cx="80" cy="80" r={r} fill="none" stroke="#081428" strokeWidth="16" />

          {(() => {
            let cumulative = 0;
            return segments.map((s) => {
              const len = total ? (s.value / total) * c : 0;
              const offset = -cumulative;
              cumulative += len;
              if (len <= 0) return null;
              const isSelected = hovered === s.label;
              const isOtherHovered = hovered && hovered !== s.label;

              return (
                <circle
                  key={s.label}
                  cx="80"
                  cy="80"
                  r={isSelected ? r + 3 : r}
                  fill="none"
                  stroke={s.color}
                  strokeWidth={isSelected ? 20 : 16}
                  strokeDasharray={`${Math.max(0, len - 3)} ${c}`}
                  strokeDashoffset={mounted ? offset : -c}
                  strokeLinecap="round"
                  onMouseEnter={() => setHovered(s.label)}
                  onMouseLeave={() => setHovered(null)}
                  className="cursor-pointer transition-all duration-500 ease-out"
                  style={{
                    opacity: isOtherHovered ? 0.35 : 1,
                    filter: isSelected
                      ? `drop-shadow(0 0 14px ${s.color}) drop-shadow(0 0 6px ${s.color})`
                      : `drop-shadow(0 0 6px ${s.color}70)`
                  }}
                />
              );
            });
          })()}
        </svg>

        {/* Dynamic Center Telemetry HUD */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none transition-all duration-300">
          {activeSegment ? (
            <>
              <span
                className="font-mono text-3xl font-black text-white"
                style={{ color: activeSegment.color, textShadow: `0 0 10px ${activeSegment.color}80` }}
              >
                {activeSegment.value}
              </span>
              <span className="font-mono text-xs font-bold text-white tracking-wider mt-0.5">
                {pct(activeSegment.value)}%
              </span>
              <span
                className="font-display text-[9.5px] uppercase font-bold tracking-wider mt-0.5"
                style={{ color: activeSegment.color }}
              >
                {activeSegment.label}
              </span>
            </>
          ) : (
            <>
              <span className="font-mono text-3xl font-black text-white tracking-tight">
                {total}
              </span>
              <span className="font-mono text-[10px] text-cyan-400 font-bold uppercase tracking-widest mt-0.5">
                SCANS
              </span>
            </>
          )}
        </div>
      </div>

      {/* Interactive Legend Cards with Animated Horizontal Meters */}
      <div className="w-full space-y-2 font-mono text-xs">
        {segments.map((s) => {
          const isSelected = hovered === s.label;
          const percentage = pct(s.value);

          return (
            <div
              key={s.label}
              onMouseEnter={() => setHovered(s.label)}
              onMouseLeave={() => setHovered(null)}
              className={`p-2.5 rounded-xl border transition-all cursor-pointer ${
                isSelected
                  ? 'border-cyan-400/60 bg-cyan-950/40 shadow-[0_0_15px_rgba(34,211,238,0.2)] scale-[1.02]'
                  : 'border-ink-800/60 bg-[#030816]/70 hover:border-cyan-500/30 hover:bg-cyan-950/20'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2.5">
                  <span className="relative flex h-2.5 w-2.5">
                    <span
                      className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60"
                      style={{ backgroundColor: s.color }}
                    />
                    <span
                      className="relative inline-flex h-2.5 w-2.5 rounded-full"
                      style={{ backgroundColor: s.color, boxShadow: `0 0 6px ${s.color}` }}
                    />
                  </span>
                  <span className={`font-sans font-medium transition-colors ${isSelected ? 'text-white' : 'text-fog-200'}`}>
                    {s.label}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <span className="font-bold text-white text-xs">{s.value}</span>
                  <span className="font-bold font-mono text-xs w-9 text-right" style={{ color: s.color }}>
                    {percentage}%
                  </span>
                </div>
              </div>

              {/* Animated Progress Meter */}
              <div className="mt-2 h-1.5 w-full rounded-full bg-ink-950 overflow-hidden border border-ink-800/80">
                <div
                  className="h-full rounded-full transition-all duration-700 ease-out"
                  style={{
                    width: mounted ? `${percentage}%` : '0%',
                    backgroundColor: s.color,
                    boxShadow: isSelected ? `0 0 8px ${s.color}` : 'none'
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Glowing Cyber Progress Bar List
function CyberBarList({ entries, isCategory = false }) {
  const max = entries[0]?.[1] || 1;

  return (
    <ul className="space-y-3 font-mono text-xs">
      {entries.map(([name, n]) => {
        const pct = Math.round((n / max) * 100);
        const isSafe = /legit|verified|enterprise|low-risk/i.test(name);
        const isCritical = /gambling|betting|satta|matka|ponzi|phish|malware/i.test(name);

        const gradient = isCritical
          ? 'from-rose-500 to-amber-500'
          : isSafe
          ? 'from-emerald-400 to-teal-500'
          : 'from-cyan-400 to-blue-500';

        const glowColor = isCritical ? '#f43f5e' : isSafe ? '#2dd4a4' : '#22d3ee';

        return (
          <li key={name} className="group">
            <div className="flex items-center justify-between gap-3 text-xs mb-1">
              <span className="font-sans text-fog-200 truncate group-hover:text-white transition-colors">
                {name}
              </span>
              <span className="font-mono font-bold text-white shrink-0 ml-2">
                {n}
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-ink-950 overflow-hidden border border-ink-800/80">
              <div
                className={`h-full rounded-full bg-gradient-to-r ${gradient} transition-all duration-700`}
                style={{
                  width: `${pct}%`,
                  boxShadow: `0 0 8px ${glowColor}50`
                }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export default function ThreatAnalytics({ stats, onOpenScan }) {
  const patterns = useMemo(
    () => Object.entries(stats?.patternDistribution || {}).sort((a, b) => b[1] - a[1]).slice(0, 8),
    [stats]
  );
  const classes = useMemo(
    () => Object.entries(stats?.classificationDistribution || {}).sort((a, b) => b[1] - a[1]).slice(0, 8),
    [stats]
  );

  if (!stats) {
    return (
      <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-8 text-center backdrop-blur-md">
        <Activity className="h-6 w-6 text-cyan-400 animate-spin mx-auto mb-2" />
        <p className="font-mono text-sm text-fog-400">Loading Threat Analytics Telemetry...</p>
      </div>
    );
  }

  const segments = [
    { label: 'Critical Risk', value: stats.criticalCount || 0, color: RISK.CRITICAL.color },
    { label: 'High Risk', value: stats.highCount || 0, color: RISK.HIGH.color },
    { label: 'Medium Risk', value: stats.mediumCount || 0, color: RISK.MEDIUM.color },
    { label: 'Low Risk', value: stats.lowCount || 0, color: RISK.LOW.color }
  ];
  const total = stats.totalScans || 0;
  const pct = (v) => (total ? Math.round((v / total) * 100) : 0);

  return (
    <div className="space-y-5 animate-fade-in text-fog-100 select-none">
      
      {/* 1. Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyan-500/20 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-display text-xl sm:text-2xl font-bold tracking-wider text-white">
              THREAT ANALYTICS
            </h1>
            <span className="rounded bg-cyan-950/80 border border-cyan-500/40 px-2 py-0.5 font-mono text-[10px] text-cyan-300 font-bold tracking-wider uppercase">
              LIVE TELEMETRY
            </span>
          </div>
          <p className="font-mono text-xs text-fog-400 mt-1">
            Global threat telemetry matrix — severity distribution, scam patterns, and priority adversary hosts.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400/90">
          <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
          <span>FEEDS ACTIVE: CERT-IN / SHODAN / ANYCAST</span>
        </div>
      </div>

      {/* 2. Top Row: 4 Cyber KPI Cards with Sparklines */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* KPI 1: Total Scans */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-fog-400">Total Scans</span>
            <Globe className="h-4 w-4 text-cyan-400/80" />
          </div>
          <div className="mt-2 font-mono text-2xl sm:text-3xl font-black text-white">
            {stats.totalScans || 0}
          </div>
          <div className="font-mono text-[11px] text-cyan-400 mt-1">
            {stats.uniqueDomains || 0} unique domains
          </div>
          <div className="mt-2">
            <SparklineWave color="#00d2ff" height={24} points={[10, 16, 12, 22, 18, 28, 24, 35, 30, 42]} />
          </div>
        </div>

        {/* KPI 2: Average Risk Score */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-fog-400">Average Risk Score</span>
            <Activity className="h-4 w-4 text-amber-400/80" />
          </div>
          <div className="mt-2 font-mono text-2xl sm:text-3xl font-black text-amber-300">
            {stats.averageScore || 0} <span className="text-xs font-normal text-fog-500">/ 100</span>
          </div>
          <div className="font-mono text-[11px] text-fog-400 mt-1">
            Calculated across all scans
          </div>
          <div className="mt-2">
            <SparklineWave color="#fbbf24" height={24} points={[20, 24, 22, 30, 28, 36, 32, 45, 40, 48]} />
          </div>
        </div>

        {/* KPI 3: Unknown but Suspicious */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-fog-400">Unknown but Suspicious</span>
            <AlertTriangle className="h-4 w-4 text-rose-400/80" />
          </div>
          <div className="mt-2 font-mono text-2xl sm:text-3xl font-black text-rose-400">
            {stats.unknownSuspiciousCount || 0}
          </div>
          <div className="font-mono text-[11px] text-rose-300/80 mt-1">
            Caught with zero prior blacklist hit
          </div>
          <div className="mt-2">
            <SparklineWave color="#f43f5e" height={24} points={[4, 6, 5, 8, 7, 12, 9, 14, 11, 16]} />
          </div>
        </div>

        {/* KPI 4: Watched Sites & Incidents */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-4 backdrop-blur-md shadow-[0_8px_30px_rgba(0,0,0,0.6)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-fog-400">Watched Targets</span>
            <Eye className="h-4 w-4 text-blue-400/80" />
          </div>
          <div className="mt-2 font-mono text-2xl sm:text-3xl font-black text-white">
            {stats.watchlistCount || 0}
          </div>
          <div className="font-mono text-[11px] text-blue-300 mt-1">
            {stats.activeIncidents || 0} open SOC investigations
          </div>
          <div className="mt-2">
            <SparklineWave color="#38bdf8" height={24} points={[2, 3, 3, 5, 4, 6, 5, 7, 6, 8]} />
          </div>
        </div>

      </div>

      {/* 3. Middle Row: Severity Mix & Highest-Risk Sites */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        
        {/* Severity Mix Panel */}
        <div className="lg:col-span-5 rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-5 backdrop-blur-md shadow-[0_8px_32px_rgba(0,0,0,0.6)] flex flex-col justify-between">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-cyan-500/15">
            <Layers className="h-4 w-4 text-cyan-400" />
            <h2 className="font-display text-xs font-bold tracking-wider text-cyan-300 uppercase">
              Severity Mix // Risk Breakdown
            </h2>
          </div>

          <AnimatedSeverityMix segments={segments} total={total} />
        </div>

        {/* Highest-Risk Sites Right Now */}
        <div className="lg:col-span-7 rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-5 backdrop-blur-md shadow-[0_8px_32px_rgba(0,0,0,0.6)] flex flex-col">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyan-500/15">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-rose-400" />
              <h2 className="font-display text-xs font-bold tracking-wider text-white uppercase">
                Highest-Risk Sites Right Now
              </h2>
            </div>
            <span className="font-mono text-[10px] text-fog-400">Latest scan per domain</span>
          </div>

          <div className="flex-1 overflow-y-auto max-h-[320px] pr-1 space-y-2">
            {stats.topThreats?.length ? (
              stats.topThreats.map((t) => {
                const score = t.score ?? 85;
                const isCrit = t.risk_level === 'CRITICAL' || score >= 80;

                return (
                  <div
                    key={t.id || t.domain}
                    onClick={() => onOpenScan && onOpenScan(t)}
                    className="flex items-center justify-between gap-3 p-2.5 rounded-xl border border-ink-800/60 bg-[#030816]/70 hover:border-cyan-500/40 hover:bg-cyan-950/30 transition-all cursor-pointer group"
                  >
                    <div className="min-w-0 flex items-start gap-2.5">
                      <span className={`h-2 w-2 rounded-full mt-1.5 shrink-0 ${isCrit ? 'bg-rose-400 animate-ping' : 'bg-amber-400'}`} />
                      <div className="min-w-0">
                        <div className="font-mono text-xs font-bold text-white group-hover:text-cyan-300 truncate">
                          {t.domain}
                        </div>
                        <div className="text-[11px] text-fog-400 truncate font-sans">
                          {t.primaryPattern || 'Gambling / Betting Indicators'}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded border ${
                          isCrit
                            ? 'border-rose-500/40 bg-rose-950/60 text-rose-300 shadow-[0_0_8px_rgba(244,63,94,0.3)]'
                            : 'border-amber-500/40 bg-amber-950/60 text-amber-300'
                        }`}
                      >
                        {t.risk_level || 'HIGH'} {score}
                      </span>
                      <ScoreRingMini score={score} />
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="p-5 font-mono text-xs text-fog-400 text-center">No high-risk threat domains recorded yet.</p>
            )}
          </div>
        </div>

      </div>

      {/* 4. Bottom Row: Scam Patterns & Website Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        
        {/* Scam Patterns Detected */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-5 backdrop-blur-md shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
          <div className="flex items-center gap-2 mb-4 pb-2 border-b border-cyan-500/15">
            <Zap className="h-4 w-4 text-cyan-400" />
            <h2 className="font-display text-xs font-bold tracking-wider text-cyan-300 uppercase">
              Scam Patterns Detected // Lexicon & Signals
            </h2>
          </div>

          {patterns.length ? (
            <CyberBarList entries={patterns} />
          ) : (
            <p className="font-mono text-xs text-fog-400">No pattern telemetry recorded yet.</p>
          )}
        </div>

        {/* Website Categories */}
        <div className="rounded-2xl border border-cyan-500/20 bg-[#050c1e]/85 p-5 backdrop-blur-md shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
          <div className="flex items-center gap-2 mb-4 pb-2 border-b border-cyan-500/15">
            <Layers className="h-4 w-4 text-cyan-400" />
            <h2 className="font-display text-xs font-bold tracking-wider text-cyan-300 uppercase">
              Website Categories // Classification Matrix
            </h2>
          </div>

          {classes.length ? (
            <CyberBarList entries={classes} isCategory />
          ) : (
            <p className="font-mono text-xs text-fog-400">No category telemetry recorded yet.</p>
          )}
        </div>

      </div>

    </div>
  );
}
