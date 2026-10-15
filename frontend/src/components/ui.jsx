import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { riskMeta, levelFromScore, scoreColor } from '../lib/risk';

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

export function RiskBadge({ level, score, className = '' }) {
  const meta = riskMeta(level || (score !== undefined ? levelFromScore(score) : 'LOW'));
  return (
    <span className={`chip ${meta.chip} ${className}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} />
      {meta.label}
      {score !== undefined && score !== null && <span className="num font-semibold text-white/90">{score}</span>}
    </span>
  );
}

export function Tag({ children, className = '' }) {
  return <span className={`chip border-ink-500/70 bg-ink-700/50 text-fog-200 ${className}`}>{children}</span>;
}

export function Panel({ title, subtitle, action, children, className = '', bodyClassName = 'p-5', icon: Icon }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-600/60 px-5 py-4">
          <div className="min-w-0">
            <h2 className="panel-title flex items-center gap-2">
              {Icon && <Icon className="h-4 w-4 text-brand-300" aria-hidden />}
              {title}
            </h2>
            {subtitle && <p className="mt-0.5 text-[13px] text-fog-400">{subtitle}</p>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions, eyebrow }) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="max-w-2xl">
        {eyebrow}
        <h1 className="page-title">{title}</h1>
        {description && <p className="mt-1.5 text-[14px] leading-relaxed text-fog-300">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Meter({ value = 0, max = 100, color, className = '' }) {
  const pct = Math.max(0, Math.min(100, (value / (max || 1)) * 100));
  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-ink-700 ${className}`}>
      <div
        className="h-full rounded-full transition-[width] duration-700 ease-out"
        style={{ width: `${pct}%`, background: color || scoreColor(pct) }}
      />
    </div>
  );
}

export function ScoreRing({ score = 0, size = 168, stroke = 12, label = 'risk score', level }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = riskMeta(level || levelFromScore(score)).color;
  const offset = c - (c * Math.max(0, Math.min(100, score))) / 100;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1C2148" strokeWidth={stroke} />
        {/* tick marks at the level thresholds */}
        {[30, 50, 75].map((t) => {
          const a = (t / 100) * 2 * Math.PI;
          const x1 = size / 2 + (r - stroke / 2 - 2) * Math.cos(a);
          const y1 = size / 2 + (r - stroke / 2 - 2) * Math.sin(a);
          const x2 = size / 2 + (r + stroke / 2 + 2) * Math.cos(a);
          const y2 = size / 2 + (r + stroke / 2 + 2) * Math.sin(a);
          return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#07081A" strokeWidth="2" />;
        })}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 10px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="num text-white" style={{ fontSize: size * 0.3, lineHeight: 1, fontWeight: 600 }}>
          {score}
        </span>
        <span className="mt-1 text-[12px] text-fog-400">{label}</span>
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {Icon && (
        <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-ink-500/70 bg-ink-700/50">
          <Icon className="h-5 w-5 text-brand-300" aria-hidden />
        </div>
      )}
      <h3 className="font-display text-base font-semibold text-white">{title}</h3>
      {children && <p className="mt-1.5 max-w-sm text-[13px] leading-relaxed text-fog-400">{children}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, subtitle, children, footer, width = 'max-w-lg' }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', onKey);
    const first = ref.current?.querySelector('input, select, textarea, button');
    first?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-ink-950/75 p-4 backdrop-blur-sm sm:items-center" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className={`panel w-full ${width} animate-fade-in bg-ink-850`}>
        <div className="flex items-start justify-between gap-4 border-b border-ink-600/60 px-5 py-4">
          <div>
            <h2 className="font-display text-lg font-semibold text-white">{title}</h2>
            {subtitle && <p className="mt-0.5 text-[13px] text-fog-400">{subtitle}</p>}
          </div>
          <button type="button" onClick={onClose} className="icon-btn -mr-2 -mt-1" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-ink-600/60 px-5 py-3.5">{footer}</div>}
      </div>
    </div>
  );
}

export function Segmented({ options, value, onChange, className = '' }) {
  return (
    <div className={`inline-flex max-w-full overflow-x-auto no-scrollbar rounded-[10px] border border-ink-600/70 bg-ink-900/70 p-0.5 ${className}`} role="tablist">
      {options.map((o) => {
        const id = typeof o === 'string' ? o : o.id;
        const label = typeof o === 'string' ? o : o.label;
        const active = value === id;
        return (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(id)}
            className={`shrink-0 whitespace-nowrap rounded-lg px-3 py-1.5 text-[12px] font-medium transition-colors ${
              active ? 'bg-ink-600 text-white' : 'text-fog-400 hover:text-fog-100'
            }`}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="-mb-px flex gap-4 sm:gap-6 overflow-x-auto overflow-y-hidden no-scrollbar border-b border-ink-600/70 px-1 py-0.5 scroll-smooth" role="tablist">
      {tabs.map((t) => {
        const Icon = t.icon;
        const active = value === t.id;
        return (
          <button key={t.id} type="button" role="tab" aria-selected={active} onClick={() => onChange(t.id)} className={`tab shrink-0 ${active ? 'tab-active' : ''}`}>
            {Icon && <Icon className="h-4 w-4 shrink-0" aria-hidden />}
            <span className="whitespace-nowrap">{t.label}</span>
            {t.count !== undefined && <span className="rounded-md bg-ink-700 px-1.5 text-[11px] text-fog-300">{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export function Sparkline({ values = [], width = 96, height = 28, color = '#A78BFA' }) {
  const pts = values.filter((v) => typeof v === 'number');
  if (pts.length < 2) return <div style={{ width, height }} />;
  const min = Math.min(...pts, 0);
  const max = Math.max(...pts, 100);
  const step = width / (pts.length - 1);
  const y = (v) => height - 2 - ((v - min) / (max - min || 1)) * (height - 4);
  const d = pts.map((v, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  return (
    <svg width={width} height={height} aria-hidden>
      <path d={d} fill="none" stroke={color} strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={(pts.length - 1) * step} cy={y(pts[pts.length - 1])} r="2.5" fill={color} />
    </svg>
  );
}
