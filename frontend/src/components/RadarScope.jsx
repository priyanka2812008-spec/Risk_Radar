import React, { useMemo, useState } from 'react';
import { riskMeta, hashString, latestPerDomain, timeAgo } from '../lib/risk';

const SIZE = 420;
const C = SIZE / 2;
const R = 190;
const SWEEP_SECONDS = 4;

// Closer to the centre means closer to you: higher risk sits nearer the middle.
const radiusFor = (score) => 20 + (1 - Math.max(0, Math.min(100, score)) / 100) * (R - 30);

const polar = (r, deg) => {
  const a = (deg * Math.PI) / 180;
  return [C + r * Math.sin(a), C - r * Math.cos(a)];
};

const RINGS = [
  { score: 75, label: 'critical' },
  { score: 50, label: 'high' },
  { score: 30, label: 'medium' }
];

/**
 * Live radar of every domain scanned so far. Angle is a stable hash of the domain,
 * distance from the centre is the risk score. Each blip flashes as the sweep passes it.
 */
export default function RadarScope({ scans = [], onSelect, max = 48 }) {
  const [hover, setHover] = useState(null);

  const blips = useMemo(
    () =>
      latestPerDomain(scans)
        .slice(0, max)
        .map((s) => {
          const angle = hashString(s.domain) % 360;
          const r = radiusFor(s.score);
          const [x, y] = polar(r, angle);
          return { scan: s, angle, x, y, meta: riskMeta(s.risk_level) };
        })
        // draw low-risk first so critical blips sit on top
        .sort((a, b) => a.scan.score - b.scan.score),
    [scans, max]
  );

  // Sweep wedge drawn as fading slices trailing the leading edge (north)
  const wedges = useMemo(
    () =>
      Array.from({ length: 12 }, (_, i) => {
        const from = -i * 5;
        const to = -(i + 1) * 5;
        const [x1, y1] = polar(R, from);
        const [x2, y2] = polar(R, to);
        return { d: `M${C} ${C} L${x1} ${y1} A${R} ${R} 0 0 0 ${x2} ${y2} Z`, opacity: 0.26 * (1 - i / 12) };
      }),
    []
  );

  return (
    <div className="relative mx-auto aspect-square w-full max-w-[420px]">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="h-full w-full" role="img" aria-label={`Radar of ${blips.length} scanned domains, positioned by risk`}>
        <defs>
          <radialGradient id="scope-bg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#1A1550" stopOpacity="0.9" />
            <stop offset="70%" stopColor="#0E1030" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#0B0D24" stopOpacity="1" />
          </radialGradient>
        </defs>

        <circle cx={C} cy={C} r={R} fill="url(#scope-bg)" stroke="#3A4178" strokeWidth="1" />

        {/* bearing ticks every 10° */}
        {Array.from({ length: 36 }, (_, i) => {
          const deg = i * 10;
          const [x1, y1] = polar(R, deg);
          const [x2, y2] = polar(R - (deg % 90 === 0 ? 10 : 5), deg);
          return <line key={deg} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#3A4178" strokeWidth="1" />;
        })}

        {/* threshold rings */}
        {RINGS.map((ring) => {
          const r = radiusFor(ring.score);
          const [lx, ly] = polar(r, 0);
          return (
            <g key={ring.score}>
              <circle cx={C} cy={C} r={r} fill="none" stroke={riskMeta(ring.label).color} strokeOpacity="0.28" strokeDasharray="2 5" />
              <text x={lx + 5} y={ly - 4} fill={riskMeta(ring.label).color} fillOpacity="0.75" fontSize="10.5" fontFamily="IBM Plex Sans">
                {ring.label} · {ring.score}+
              </text>
            </g>
          );
        })}

        {/* crosshair */}
        <line x1={C - R} y1={C} x2={C + R} y2={C} stroke="#272D5C" />
        <line x1={C} y1={C - R} x2={C} y2={C + R} stroke="#272D5C" />

        {/* sweep */}
        <g className="motion-sweep animate-sweep" style={{ transformOrigin: `${C}px ${C}px`, transformBox: 'view-box' }}>
          {wedges.map((w, i) => (
            <path key={i} d={w.d} fill="#22D3EE" fillOpacity={w.opacity} />
          ))}
          <line x1={C} y1={C} x2={C} y2={C - R} stroke="#67E8F9" strokeWidth="1.5" strokeOpacity="0.9" />
        </g>

        {/* blips */}
        {blips.map((b) => {
          const danger = b.scan.score >= 50;
          const size = danger ? 5.5 : 4;
          const delay = `${((b.angle / 360) * SWEEP_SECONDS).toFixed(2)}s`;
          const isHover = hover?.scan.id === b.scan.id;
          return (
            <g
              key={b.scan.id}
              role="button"
              tabIndex={0}
              aria-label={`${b.scan.domain}, risk ${b.scan.score} of 100`}
              className="cursor-pointer outline-none"
              onMouseEnter={() => setHover(b)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(b)}
              onBlur={() => setHover(null)}
              onClick={() => onSelect?.(b.scan)}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onSelect?.(b.scan))}
            >
              <circle cx={b.x} cy={b.y} r="14" fill="transparent" />
              <circle
                cx={b.x}
                cy={b.y}
                r={size}
                fill={b.meta.color}
                className="motion-sweep animate-blip"
                style={{ animationDelay: delay, transformBox: 'fill-box', transformOrigin: 'center' }}
              />
              <circle cx={b.x} cy={b.y} r={isHover ? size + 2 : size} fill={b.meta.color} stroke="#07081A" strokeWidth="1.5" style={{ filter: danger ? `drop-shadow(0 0 6px ${b.meta.color})` : undefined, transition: 'r 120ms' }} />
            </g>
          );
        })}

        {/* you */}
        <circle cx={C} cy={C} r="5" fill="#A78BFA" />
        <circle cx={C} cy={C} r="10" fill="none" stroke="#A78BFA" strokeOpacity="0.5" />
      </svg>

      {hover && (
        <div
          className="pointer-events-none absolute z-10 w-max max-w-[220px] -translate-x-1/2 rounded-lg border border-ink-500/80 bg-ink-800/95 px-3 py-2 text-[12px] shadow-panel"
          style={{ left: `${(hover.x / SIZE) * 100}%`, top: `calc(${(hover.y / SIZE) * 100}% + 14px)` }}
        >
          <div className="domain truncate text-[12px]">{hover.scan.domain}</div>
          <div className="mt-0.5 flex items-center gap-2 text-fog-300">
            <span className="num font-semibold" style={{ color: hover.meta.color }}>
              {hover.scan.score}
            </span>
            <span>{hover.scan.classification?.primary || hover.scan.primaryPattern}</span>
          </div>
          <div className="text-[11px] text-fog-500">{timeAgo(hover.scan.timestamp)}</div>
        </div>
      )}
    </div>
  );
}
