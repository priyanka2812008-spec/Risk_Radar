import React, { useMemo, useState } from 'react';
import {
  FileSearch, Eye, RotateCw, Download, Printer, BadgeCheck, ExternalLink, AlertTriangle, CheckCircle2, XCircle,
  Info, Mail, Phone, MapPin, Send, MessageSquare, Layers, ListChecks, Fingerprint, Activity, Radar, Copy, Check, ArrowRight,
  Network, Globe, DollarSign, UserCheck, ShieldAlert, ShieldCheck
} from 'lucide-react';
import { Panel, RiskBadge, ScoreRing, Tabs, Segmented, Meter, Modal, EmptyState, Tag } from './ui';
import { riskMeta, scoreColor, formatDateTime } from '../lib/risk';

const ACTION_STYLE = {
  BLOCK: 'border-risk-critical/50 bg-risk-critical/15 text-rose-100',
  AVOID: 'border-risk-high/50 bg-risk-high/15 text-orange-100',
  INVESTIGATE: 'border-risk-high/50 bg-risk-high/15 text-orange-100',
  REVIEW: 'border-risk-medium/50 bg-risk-medium/15 text-amber-100',
  MONITOR: 'border-risk-guarded/50 bg-risk-guarded/15 text-sky-100',
  ALLOW: 'border-risk-low/50 bg-risk-low/15 text-emerald-100'
};

const ACTION_COPY = {
  BLOCK: 'Block this site',
  AVOID: 'Avoid this site',
  INVESTIGATE: 'Investigate first',
  REVIEW: 'Review before trusting',
  MONITOR: 'Keep monitoring',
  ALLOW: 'Safe to use'
};

const sentence = (s = '') => (s ? s.charAt(0) + s.slice(1).toLowerCase() : '');

/* ---------------- Risk DNA spider chart ---------------- */
function DnaChart({ dims }) {
  const S = 300;
  const c = S / 2;
  const R = 112;
  const n = dims.length;
  const pt = (i, v) => {
    const a = (Math.PI * 2 * i) / n - Math.PI / 2;
    return [c + Math.cos(a) * R * (v / 100), c + Math.sin(a) * R * (v / 100)];
  };
  const poly = dims.map((d, i) => pt(i, d.score).join(',')).join(' ');
  return (
    <svg viewBox={`-56 -8 ${S + 112} ${S + 16}`} className="mx-auto h-auto w-full max-w-[420px]" role="img" aria-label="Risk DNA chart">
      {[25, 50, 75, 100].map((lvl) => (
        <polygon key={lvl} points={dims.map((_, i) => pt(i, lvl).join(',')).join(' ')} fill="none" stroke="#272D5C" strokeDasharray={lvl === 100 ? '0' : '2 4'} />
      ))}
      {dims.map((_, i) => {
        const [x, y] = pt(i, 100);
        return <line key={i} x1={c} y1={c} x2={x} y2={y} stroke="#1C2148" />;
      })}
      <polygon points={poly} fill="#8B5CF6" fillOpacity="0.22" stroke="#A78BFA" strokeWidth="2" strokeLinejoin="round" />
      {dims.map((d, i) => {
        const [x, y] = pt(i, d.score);
        return <circle key={d.key} cx={x} cy={y} r="3.5" fill={scoreColor(d.score)} stroke="#07081A" strokeWidth="1.5" />;
      })}
      {dims.map((d, i) => {
        const [x, y] = pt(i, 128);
        return (
          <text key={d.key} x={x} y={y} textAnchor={x < c - 10 ? 'end' : x > c + 10 ? 'start' : 'middle'} dominantBaseline="middle" fontSize="10.5" fill="#A4AAD6" fontFamily="IBM Plex Sans">
            {d.short}
          </text>
        );
      })}
    </svg>
  );
}

/* ---------------- Score timeline ---------------- */
function TimelineChart({ points }) {
  const W = 640;
  const H = 180;
  const pad = { l: 30, r: 16, t: 14, b: 28 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const x = (i) => pad.l + (points.length === 1 ? iw / 2 : (iw * i) / (points.length - 1));
  const y = (v) => pad.t + ih - (v / 100) * ih;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Risk score over time">
      {[30, 50, 75].map((t) => (
        <g key={t}>
          <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke={scoreColor(t)} strokeOpacity="0.25" strokeDasharray="3 5" />
          <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" fontSize="10.5" fill="#606795" fontFamily="IBM Plex Sans">{t}</text>
        </g>
      ))}
      <polyline points={points.map((p, i) => `${x(i)},${y(p.score)}`).join(' ')} fill="none" stroke="#A78BFA" strokeWidth="2.25" strokeLinejoin="round" />
      {points.map((p, i) => (
        <g key={i}>
          <circle cx={x(i)} cy={y(p.score)} r="4.5" fill={scoreColor(p.score)} stroke="#07081A" strokeWidth="2" />
          <text x={x(i)} y={H - 8} textAnchor="middle" fontSize="10.5" fill="#8188BA" fontFamily="IBM Plex Sans">
            {new Date(p.date).toLocaleDateString([], { day: 'numeric', month: 'short' })}
          </text>
        </g>
      ))}
    </svg>
  );
}

function SeverityDot({ level }) {
  return <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: riskMeta(level).color }} aria-hidden />;
}

function KV({ label, children }) {
  return (
    <div>
      <dt className="text-[12px] text-fog-400">{label}</dt>
      <dd className="mt-0.5 text-[14px] text-fog-50">{children}</dd>
    </div>
  );
}

/* ---------------- Tabs ---------------- */

function OverviewTab({ scan }) {
  const [done, setDone] = useState({});
  const pillars = [
    ['Technical security', scan.riskPillars?.technicalSecurity],
    ['Regulatory', scan.riskPillars?.regulatoryRisk],
    ['Commercial', scan.riskPillars?.commercialRisk],
    ['Reputation', scan.riskPillars?.reputationRisk]
  ].filter(([, p]) => p);

  return (
    <div className="space-y-6">
      {scan.governmentVerification && (
        <div className={`rounded-2xl border p-5 ${scan.governmentVerification.verified ? 'border-emerald-500/30 bg-emerald-500/[0.06]' : 'border-rose-500/30 bg-rose-500/[0.08]'}`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              {scan.governmentVerification.verified ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="h-5 w-5 text-rose-400" />
              )}
              <div>
                <span className="font-semibold text-white">{scan.governmentVerification.badge}</span>
                <span className="ml-2 text-[12px] text-fog-400">· {scan.governmentVerification.regulator}</span>
              </div>
            </div>
            <span
              className="text-[12px] font-bold px-2.5 py-1 rounded"
              style={{
                backgroundColor: `${scan.governmentVerification.badgeColor}25`,
                color: scan.governmentVerification.verified ? '#86efac' : '#fca5a5'
              }}
            >
              {scan.governmentVerification.status}
            </span>
          </div>
          <p className="mt-2 text-[13.5px] text-fog-200">{scan.governmentVerification.citation}</p>
          <ul className="mt-2.5 space-y-1 text-[12.5px] text-fog-300">
            {(scan.governmentVerification.evidence || []).map((ev, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className={scan.governmentVerification.verified ? 'text-emerald-400' : 'text-rose-400'}>•</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Why this score" subtitle="The signals that moved the needle most" icon={AlertTriangle}>
          <ul className="space-y-3.5">
            {(scan.topReasons || []).map((r, i) => (
              <li key={i} className="flex gap-3">
                <SeverityDot level={r.severity} />
                <div className="min-w-0">
                  <div className="text-[14px] font-medium text-fog-50">{r.reason}</div>
                  <div className="mt-0.5 text-[13px] leading-snug text-fog-400">{r.impact}</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="What to do now" subtitle={scan.recommendedAction?.rationale} icon={ListChecks}>
          <ul className="space-y-2">
            {(scan.recommendedAction?.immediateSteps || []).map((step, i) => (
              <li key={i}>
                <label className={`flex cursor-pointer gap-3 rounded-xl border px-3.5 py-2.5 text-[13px] leading-snug transition-colors ${done[i] ? 'border-risk-low/30 bg-risk-low/5 text-fog-400' : 'border-ink-600/70 bg-ink-900/50 text-fog-100 hover:border-ink-500'}`}>
                  <input type="checkbox" checked={!!done[i]} onChange={() => setDone((d) => ({ ...d, [i]: !d[i] }))} className="mt-0.5 h-4 w-4 shrink-0 accent-emerald-500" />
                  <span className={done[i] ? 'line-through' : ''}>{step}</span>
                </label>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {pillars.length > 0 && (
        <section className="panel grid grid-cols-2 divide-ink-600/60 md:grid-cols-4 md:divide-x">
          {pillars.map(([label, p]) => (
            <div key={label} className="p-5">
              <div className="flex items-baseline justify-between">
                <span className="text-[13px] text-fog-300">{label}</span>
                <span className="num text-[18px] font-semibold" style={{ color: scoreColor(p.score) }}>{p.score}</span>
              </div>
              <Meter value={p.score} className="mt-2.5" />
              <div className="mt-2 text-[12px] text-fog-400">{sentence(p.level)} risk</div>
            </div>
          ))}
        </section>
      )}

      {(scan.detectedPatterns || []).length > 0 && (
        <Panel title="Patterns detected" subtitle="Known scam and abuse patterns this site matches" icon={Layers}>
          <ul className="grid gap-3 md:grid-cols-2">
            {scan.detectedPatterns.map((p, i) => (
              <li key={i} className="panel-inset p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="font-medium text-white">{p.pattern}</div>
                  <span className="num shrink-0 text-[13px] text-fog-300">{p.confidence}% match</span>
                </div>
                <div className="mt-1 text-[12px] text-brand-300">{p.category}</div>
                <p className="mt-2 text-[13px] leading-relaxed text-fog-300">{p.explanation}</p>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {scan.withdrawalRisk && (
          <Panel
            title="Can you get your money out?"
            subtitle={scan.withdrawalRisk.summary}
            icon={scan.withdrawalRisk.detected ? XCircle : CheckCircle2}
            action={<RiskBadge level={scan.withdrawalRisk.detected ? (scan.withdrawalRisk.riskLevel === 'NONE' ? 'LOW' : scan.withdrawalRisk.riskLevel) : 'LOW'} />}
          >
            <ul className="space-y-2 text-[13px] leading-snug text-fog-200">
              {(scan.withdrawalRisk.indicators || []).map((t, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-fog-400" />
                  {t}
                </li>
              ))}
            </ul>
          </Panel>
        )}

        {scan.trustGap && (
          <Panel title="Claims vs. reality" subtitle={`Trust gap: ${sentence(scan.trustGap.gapLevel)}`} icon={Fingerprint}>
            <blockquote className="rounded-xl border-l-2 border-brand-400 bg-ink-900/60 px-4 py-3 text-[13px] italic text-fog-200">
              “{scan.trustGap.claim}”
            </blockquote>
            <ul className="mt-3 space-y-2 text-[13px] leading-snug text-fog-200">
              {(scan.trustGap.observed || []).map((o, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-signal-400" />
                  {o}
                </li>
              ))}
            </ul>
            {scan.trustGap.verdict && <p className="mt-3 text-[13px] text-fog-400">{scan.trustGap.verdict}</p>}
          </Panel>
        )}
      </div>
    </div>
  );
}

function tierLabel(sourceType = '') {
  if (sourceType.includes('Pre-execution')) return { label: 'Pre-execution', cls: 'text-signal-100 border-signal-400/40 bg-signal-400/10' };
  if (sourceType.startsWith('Tier 1')) return { label: 'Regulator', cls: 'text-sky-200 border-risk-guarded/40 bg-risk-guarded/10' };
  if (sourceType.startsWith('Tier 2')) return { label: 'Threat intel', cls: 'text-brand-200 border-brand-400/40 bg-brand-500/10' };
  if (sourceType.startsWith('Tier 3')) return { label: 'News', cls: 'text-amber-200 border-risk-medium/40 bg-risk-medium/10' };
  if (sourceType.startsWith('Tier 4')) return { label: 'Public record', cls: 'text-fog-200 border-ink-500 bg-ink-700/50' };
  return { label: 'Model', cls: 'text-fog-300 border-ink-500 bg-ink-700/50' };
}

function EvidenceTab({ signals }) {
  const [filter, setFilter] = useState('ALL');
  const map = { STRONG: 'STRONG_INDICATOR', CONTEXTUAL: 'CONTEXTUAL_SIGNAL', BENIGN: 'BENIGN_SIGNAL' };
  const rows = signals.filter((s) => filter === 'ALL' || s.signalType === map[filter]);
  const count = (t) => signals.filter((s) => s.signalType === map[t]).length;

  if (signals.length === 0) {
    return (
      <Panel>
        <EmptyState icon={ListChecks} title="No evidence stored for this scan">
          Older scans were saved without their raw signals. Re-scan the site to capture full evidence.
        </EmptyState>
      </Panel>
    );
  }

  return (
    <Panel
      title="Evidence"
      subtitle="Every signal the engines observed, with its source and score impact"
      bodyClassName="p-0"
      action={
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { id: 'ALL', label: `All ${signals.length}` },
            { id: 'STRONG', label: `Strong ${count('STRONG')}` },
            { id: 'CONTEXTUAL', label: `Context ${count('CONTEXTUAL')}` },
            { id: 'BENIGN', label: `Benign ${count('BENIGN')}` }
          ]}
        />
      }
    >
      <div className="overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Signal</th>
              <th className="hidden md:table-cell">Source</th>
              <th>Severity</th>
              <th className="text-right">Impact</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => {
              const tier = tierLabel(s.sourceType);
              return (
                <tr key={s.id || i}>
                  <td className="max-w-xl">
                    <div className="text-[12px] text-brand-300">{s.category}</div>
                    <div className="font-medium text-fog-50">{s.indicator}</div>
                    <div className="mt-0.5 text-[13px] leading-snug text-fog-400">{s.evidence}</div>
                  </td>
                  <td className="hidden whitespace-nowrap md:table-cell">
                    <span className={`chip ${tier.cls}`} title={s.sourceType}>{tier.label}</span>
                  </td>
                  <td className="whitespace-nowrap">
                    <RiskBadge level={s.severity} />
                  </td>
                  <td className={`num whitespace-nowrap text-right font-semibold ${s.scoreImpact > 0 ? 'text-rose-300' : 'text-emerald-300'}`}>
                    {s.scoreImpact > 0 ? `+${s.scoreImpact}` : s.scoreImpact}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function IdentityTab({ ci }) {
  if (!ci) {
    return (
      <Panel>
        <EmptyState icon={Mail} title="No contact data for this scan" />
      </Panel>
    );
  }
  const channels = [
    ci.emails?.length ? { name: 'Email', icon: Mail } : null,
    ci.phoneDetected ? { name: 'Phone', icon: Phone } : null,
    ci.addressDetected ? { name: 'Address', icon: MapPin } : null,
    ...(ci.messagingChannels || []).map((m) => ({ name: m, icon: m === 'Telegram' ? Send : MessageSquare }))
  ].filter(Boolean);

  const statusIcon = (st) =>
    st === 'PASS' ? <CheckCircle2 className="h-4 w-4 text-risk-low" /> : st === 'FAIL' ? <XCircle className="h-4 w-4 text-risk-critical" /> : st === 'WARN' ? <AlertTriangle className="h-4 w-4 text-risk-medium" /> : <Info className="h-4 w-4 text-fog-400" />;

  return (
    <div className="space-y-6">
      <section className="panel grid gap-6 p-5 md:grid-cols-[auto_1fr] md:items-center">
        <ScoreRing score={ci.transparencyScore} size={120} stroke={9} label="transparency" level={ci.level === 'HIGH' ? 'LOW' : ci.level === 'LOW' ? 'CRITICAL' : 'MEDIUM'} />
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KV label="Contact email">
            <span className="font-mono text-[13px]">{ci.primaryEmail || 'Not found'}</span>
            {ci.domainEmailMatch === true && <span className="mt-0.5 block text-[12px] text-emerald-300">Matches the site’s domain</span>}
            {ci.domainEmailMatch === false && <span className="mt-0.5 block text-[12px] text-amber-300">Uses an outside email domain</span>}
          </KV>
          <KV label="Phone">{ci.phones?.[0] || 'Not found'}</KV>
          <KV label="Business address">{ci.addresses?.[0] || 'Not found'}</KV>
          <KV label="Ways to reach them">
            <span className="mt-1 flex flex-wrap gap-1.5">
              {channels.length ? channels.map((c) => (
                <Tag key={c.name}><c.icon className="h-3 w-3" />{c.name}</Tag>
              )) : <span className="text-fog-400">None visible</span>}
            </span>
          </KV>
        </dl>
      </section>

      <Panel title="Identity checks" subtitle="Can you tell who runs this site, and how to hold them accountable?">
        <ul className="grid gap-3 md:grid-cols-2">
          {(ci.evidence || []).map((e, i) => (
            <li key={i} className="panel-inset flex gap-3 p-4">
              <span className="mt-0.5">{statusIcon(e.status)}</span>
              <div className="min-w-0">
                <div className="font-medium text-fog-50">{e.signal}</div>
                <p className="mt-1 text-[13px] leading-snug text-fog-400">{e.explanation}</p>
                {e.value && <p className="mt-1 truncate font-mono text-[12px] text-fog-300">{e.value}</p>}
              </div>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function DnaTab({ scan }) {
  const dna = scan.riskDNA || {};
  const dims = [
    { key: 'domain', short: 'Domain', label: 'Domain & registration', score: dna.domain },
    { key: 'technical', short: 'Technical', label: 'Technical posture', score: dna.technical },
    { key: 'content', short: 'Content', label: 'Content claims', score: dna.content },
    { key: 'businessModel', short: 'Business', label: 'Business model', score: dna.businessModel },
    { key: 'reputation', short: 'Reputation', label: 'Reputation', score: dna.reputation },
    { key: 'contactIdentity', short: 'Identity', label: 'Contact & identity', score: dna.contactIdentity ?? (scan.contactIdentity ? 100 - scan.contactIdentity.transparencyScore : 0) },
    { key: 'behavior', short: 'Behaviour', label: 'Page behaviour', score: dna.behavior },
    { key: 'changeOverTime', short: 'Volatility', label: 'Change over time', score: dna.changeOverTime }
  ].map((d) => ({ ...d, score: Math.round(d.score || 0) }));

  const cls = scan.classification;

  return (
    <div className="space-y-6">
      <Panel title="Risk DNA" subtitle="Eight independent dimensions, 0 = clean, 100 = severe">
        <div className="grid gap-8 lg:grid-cols-[1fr_1.1fr] lg:items-center">
          <DnaChart dims={dims} />
          <ul className="space-y-3">
            {dims.map((d) => (
              <li key={d.key}>
                <div className="flex items-baseline justify-between text-[13px]">
                  <span className="text-fog-200">{d.label}</span>
                  <span className="num font-semibold" style={{ color: scoreColor(d.score) }}>{d.score}</span>
                </div>
                <Meter value={d.score} className="mt-1.5" />
              </li>
            ))}
          </ul>
        </div>
      </Panel>

      {cls && (
        <Panel title="What kind of site this is" subtitle="Classification is separate from risk — a site can be a legitimate casino and still be high risk where you live.">
          <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
            <div>
              <div className="font-display text-[22px] font-semibold text-white">{cls.primary}</div>
              <div className="mt-1 flex items-center gap-3 text-[13px] text-fog-300">
                <span>{cls.confidence}% confidence</span>
                <Meter value={cls.confidence} color="#A78BFA" className="max-w-[140px]" />
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {(cls.secondary || []).map((t) => <Tag key={t}>{t}</Tag>)}
              </div>
              <p className="mt-4 text-[13px] leading-relaxed text-fog-300">{cls.explanation}</p>
            </div>
            <ul className="space-y-2">
              {(cls.evidence || []).map((e, i) => (
                <li key={i} className="panel-inset flex items-start justify-between gap-3 px-4 py-2.5 text-[13px]">
                  <span className="text-fog-100">{e.signal}</span>
                  <span className={`shrink-0 text-[12px] ${e.strength === 'high' ? 'text-rose-300' : e.strength === 'medium' ? 'text-amber-300' : 'text-fog-400'}`}>{e.strength}</span>
                </li>
              ))}
            </ul>
          </div>
        </Panel>
      )}
    </div>
  );
}

function TimelineTab({ timeline = [] }) {
  if (timeline.length === 0) {
    return (
      <Panel>
        <EmptyState icon={Activity} title="No history yet" />
      </Panel>
    );
  }
  return (
    <Panel title="How this site’s risk has changed" subtitle="Score at each observed change">
      <TimelineChart points={timeline} />
      <ol className="mt-6 space-y-0">
        {[...timeline].reverse().map((t, i) => (
          <li key={i} className="relative flex gap-4 pb-5 pl-6 last:pb-0">
            <span className="absolute left-[5px] top-2 h-full w-px bg-ink-600 last:hidden" aria-hidden />
            <span className="absolute left-0 top-1.5 h-[11px] w-[11px] rounded-full border-2 border-ink-850" style={{ background: scoreColor(t.score) }} aria-hidden />
            <div className="flex-1">
              <div className="flex flex-wrap items-baseline gap-x-3">
                <span className="num font-semibold text-white">{t.score}</span>
                <span className="text-[12px] text-fog-400">{new Date(t.date).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })}</span>
              </div>
              <p className="text-[13px] text-fog-300">{t.majorChanges}</p>
            </div>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

function PreExecutionTab({ pe, onNavigate }) {
  const comps = Object.entries(pe.scoring?.components || {});
  const threat = pe.intelligence?.threat;
  const domain = pe.intelligence?.domain;
  const infra = pe.intelligence?.infrastructure;
  return (
    <div className="space-y-6">
      <Panel
        title="Pre-execution intelligence"
        subtitle="Collected server-side — the site’s scripts never ran in your browser"
        icon={Radar}
        action={<RiskBadge level={pe.scoring.riskLevel} score={pe.scoring.totalScore} />}
      >
        <div className="grid gap-x-8 gap-y-4 md:grid-cols-2 lg:grid-cols-3">
          {comps.map(([k, c]) => (
            <div key={k}>
              <div className="flex items-baseline justify-between text-[13px]">
                <span className="text-fog-200">{c.label}</span>
                <span className="num text-fog-300">
                  <span className="font-semibold text-white">{c.score}</span> / {c.maxPoints}
                </span>
              </div>
              <Meter value={c.score} max={c.maxPoints} className="mt-1.5" color={scoreColor((c.score / c.maxPoints) * 100)} />
            </div>
          ))}
        </div>
        {pe.scoring.unknownSuspicious && (
          <p className="mt-5 rounded-xl border border-signal-400/30 bg-signal-400/[0.07] px-4 py-3 text-[13px] text-signal-100">
            <span className="font-semibold text-signal-300">Unknown but suspicious.</span> No threat feed lists this site yet, but several independent signals point to elevated risk.
          </p>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-3">
        {domain && (
          <Panel title="Domain">
            <dl className="space-y-3">
              <KV label="Age">{domain.ageDays} days (since {domain.registrationDate})</KV>
              <KV label="Registrar">{domain.registrar}</KV>
              <KV label="Hosting">{domain.hostingProvider} · {domain.country}</KV>
            </dl>
          </Panel>
        )}
        {threat && (
          <Panel title="Threat feeds" subtitle={`${threat.summary?.detectedBy || 0} of ${threat.summary?.totalProviders || 0} flagged`}>
            <ul className="space-y-2 text-[13px]">
              {(threat.providers || []).map((p) => (
                <li key={p.provider} className="flex items-center justify-between gap-3">
                  <span className="text-fog-200">{p.provider}</span>
                  <span className={p.status === 'DETECTED' ? 'text-rose-300' : p.status === 'CLEAN' ? 'text-emerald-300' : 'text-fog-400'}>
                    {sentence(p.status?.replace(/_/g, ' '))}
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        )}
        {infra && (
          <Panel title="Shared hosting" subtitle={`${infra.relatedDomains?.length || 0} neighbours on the same infrastructure`}>
            {infra.flaggedDomains?.length ? (
              <ul className="space-y-1.5">
                {infra.flaggedDomains.slice(0, 5).map((d) => (
                  <li key={d.domain || d} className="domain truncate text-rose-200">{d.domain || d}</li>
                ))}
              </ul>
            ) : (
              <p className="text-[13px] text-fog-300">No flagged sites share this host.</p>
            )}
          </Panel>
        )}
      </div>
      <button type="button" className="btn-secondary" onClick={() => onNavigate('pre-execution')}>
        Open pre-execution scanner <ArrowRight className="h-4 w-4" />
      </button>
    </div>
  );
}

function SevenDimensionsTab({ sevenD }) {
  if (!sevenD || !sevenD.matrix) return null;
  const m = sevenD.matrix;

  const dims = [
    { id: 'domain', name: '1. Domain', icon: Globe, weight: '15%', data: m.domain },
    { id: 'infrastructure', name: '2. Infrastructure', icon: Network, weight: '15%', data: m.infrastructure },
    { id: 'content', name: '3. Content', icon: Layers, weight: '15%', data: m.content },
    { id: 'claims', name: '4. Claims', icon: DollarSign, weight: '15%', data: m.claims },
    { id: 'behavior', name: '5. Behavior', icon: Activity, weight: '15%', data: m.behavior },
    { id: 'identity', name: '6. Identity', icon: UserCheck, weight: '15%', data: m.identity },
    { id: 'threatIntelligence', name: '7. Threat Intel', icon: ShieldAlert, weight: '10%', data: m.threatIntelligence }
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-brand-500/30 bg-brand-500/[0.06] p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-white">7D Multidimensional Classification</span>
              {sevenD.scoring?.unknownSuspicious && (
                <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[11px] font-bold text-amber-300">
                  UNKNOWN BUT SUSPICIOUS
                </span>
              )}
            </div>
            <div className="mt-1 text-[13.5px] text-fog-200">
              Primary: <strong className="text-white">{sevenD.classification?.primary}</strong> · Confidence: <strong className="text-white">{sevenD.classification?.confidence}%</strong>
            </div>
          </div>
          <div className="text-right">
            <span className="num text-[24px] font-bold" style={{ color: scoreColor(sevenD.scoring?.totalScore) }}>
              {sevenD.scoring?.totalScore}/100
            </span>
            <div className="text-[11.5px] text-fog-400">7D Composite Score</div>
          </div>
        </div>

        {sevenD.classification?.correlationNotes?.length > 0 && (
          <div className="mt-3 border-t border-brand-500/20 pt-3 text-[13px] text-fog-300">
            <span className="font-semibold text-white">Cross-Dimension Correlation:</span>
            {sevenD.classification.correlationNotes.map((note, idx) => (
              <div key={idx} className="mt-1 flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-400" />
                <span>{note}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {dims.map((dim) => {
          const Icon = dim.icon;
          const score = dim.data?.score ?? 0;
          return (
            <div key={dim.id} className="panel p-4">
              <div className="flex items-center justify-between">
                <Icon className="h-4 w-4 text-fog-400" />
                <span className="text-[11px] font-mono text-fog-400">{dim.weight}</span>
              </div>
              <div className="mt-2 text-[20px] font-bold" style={{ color: scoreColor(score) }}>
                {score}/100
              </div>
              <div className="text-[13px] font-medium text-white">{dim.name}</div>
              <Meter value={score} className="mt-2" />
            </div>
          );
        })}
      </div>

      {m.claims?.claims?.length > 0 && (
        <Panel title="Dimension 4: Claims Extracted" subtitle="Suspicious promotional and yield promises detected by dedicated claims layer" icon={DollarSign}>
          <div className="grid gap-3 sm:grid-cols-2">
            {m.claims.claims.map((c, i) => (
              <div key={i} className="panel-inset border-l-4 border-l-amber-400 p-3.5">
                <div className="text-[11.5px] font-semibold text-amber-300">{c.type}</div>
                <div className="mt-1 text-[13px] font-medium text-white">“{c.claim}”</div>
                <div className="mt-1 text-[12px] text-fog-400">{c.explanation}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {m.behavior?.signals?.length > 0 && (
        <Panel title="Dimension 5: Behavioral Demands" subtitle="Actions the website pushes the user to execute" icon={Activity}>
          <ul className="space-y-2">
            {m.behavior.signals.map((b, i) => (
              <li key={i} className="rounded-lg border border-ink-600/50 bg-ink-900/60 p-3 text-[13px]">
                <div className="font-semibold text-white">{b.signal}</div>
                <div className="mt-0.5 text-fog-300">{b.detail}</div>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Dimension 7: Threat Intelligence Feeds" subtitle="Multi-provider status abstraction" icon={ShieldAlert}>
        <div className="divide-y divide-ink-600/50">
          {(m.threatIntelligence?.providers || []).map((prov, i) => (
            <div key={i} className="flex items-center justify-between py-2.5 text-[13px]">
              <span className="text-fog-200">{prov.provider}</span>
              <span className={prov.status === 'DETECTED' ? 'font-semibold text-rose-300' : 'text-emerald-300'}>
                {prov.status === 'DETECTED' ? `DETECTED (${prov.detections})` : 'NOT LISTED'}
              </span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ---------------- Page ---------------- */

export default function RiskReportView({ scan, loading, onAddToWatchlist, onRescan, onNavigate }) {
  const [tab, setTab] = useState('overview');
  const [passportOpen, setPassportOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const signals = useMemo(() => scan?.signals || [], [scan]);

  if (loading && !scan) {
    return (
      <div className="space-y-6">
        <div className="panel h-56 animate-pulse" />
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="panel h-64 animate-pulse" />
          <div className="panel h-64 animate-pulse" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <Panel>
        <EmptyState
          icon={FileSearch}
          title="No report open"
          action={
            <div className="flex gap-2">
              <button type="button" className="btn-primary" onClick={() => onNavigate('dashboard')}>Scan a website</button>
              <button type="button" className="btn-secondary" onClick={() => onNavigate('history')}>Browse history</button>
            </div>
          }
        >
          Scan a website or pick one from your history to see its full risk report.
        </EmptyState>
      </Panel>
    );
  }

  const meta = riskMeta(scan.risk_level);
  const action = scan.recommendedAction?.action || 'MONITOR';
  const unknownSuspicious = scan.preExecution?.scoring?.unknownSuspicious || scan.passport?.unknownSuspicious;
  const engines = scan.engineScores;

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `risk-radar-${scan.domain}-${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const fingerprint = scan.passport?.fingerprint || `RR-FINGERPRINT-${scan.id}-${scan.score}`;

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: 'Evidence', count: signals.length },
    { id: 'identity', label: 'Identity' },
    { id: 'dna', label: 'Risk DNA' },
    { id: 'timeline', label: 'History' },
    ...(scan.sevenDimensions || scan.preExecution?.sevenDimensions ? [{ id: '7d', label: '7D Classification' }] : []),
    ...(scan.preExecution ? [{ id: 'pre', label: 'Pre-execution' }] : [])
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Verdict header */}
      <section className="panel relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-1" style={{ background: meta.color }} aria-hidden />
        <div className="pointer-events-none absolute -right-20 -top-28 h-72 w-72 rounded-full blur-3xl" style={{ background: `${meta.color}22` }} aria-hidden />
        <div className="relative grid gap-6 p-4 sm:p-6 lg:p-8 sm:grid-cols-[auto_1fr] lg:grid-cols-[auto_1fr_auto] items-center sm:items-start lg:items-center">
          <div className="flex justify-center sm:justify-start">
            <ScoreRing score={scan.score} level={scan.risk_level} size={150} />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge level={scan.risk_level} />
              {scan.governmentVerification?.badge && (
                <span className={`chip inline-flex items-center gap-1.5 text-xs font-medium ${
                  scan.governmentVerification.verified
                    ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                    : scan.governmentVerification.status === 'prohibited'
                    ? 'border-rose-500/40 bg-rose-500/15 text-rose-300'
                    : 'border-amber-500/40 bg-amber-500/15 text-amber-300'
                }`}>
                  {scan.governmentVerification.verified ? (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  ) : (
                    <ShieldAlert className="h-3.5 w-3.5" />
                  )}
                  {scan.governmentVerification.badge}
                </span>
              )}
              {unknownSuspicious && <span className="chip border-signal-400/40 bg-signal-400/10 text-signal-100">Unknown but suspicious</span>}
              {scan.classification?.primary && <Tag>{scan.classification.primary}</Tag>}
            </div>
            <h1 className="mt-3 break-all font-mono text-[20px] font-medium text-white sm:text-[26px]">{scan.domain}</h1>
            <p className="mt-2 max-w-2xl text-[14px] sm:text-[15px] leading-relaxed text-fog-200">{scan.verdictExplanation}</p>
            <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-[13px] text-fog-400">
              <span>Scanned {formatDateTime(scan.timestamp)}</span>
              <a href={scan.url} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 hover:text-fog-100" title="Opens the live website — be careful">
                Open live site <ExternalLink className="h-3.5 w-3.5" />
              </a>
              {engines && engines.forensic !== engines.preExecution && (
                <span title="Risk Radar runs two engines and reports the higher score — unknown is never treated as safe.">
                  Forensic engine <span className="num text-fog-200">{engines.forensic}</span> · Pre-execution <span className="num text-fog-200">{engines.preExecution}</span>
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-col gap-3 sm:col-span-2 lg:col-span-1 lg:w-60">
            <div className={`rounded-xl border px-4 py-3 ${ACTION_STYLE[action] || ACTION_STYLE.MONITOR}`}>
              <div className="text-[12px] opacity-80">Recommendation</div>
              <div className="font-display text-[18px] font-semibold">{ACTION_COPY[action] || sentence(action)}</div>
            </div>
            <div className="no-print grid grid-cols-2 gap-2">
              <button type="button" className="btn-secondary btn-sm" onClick={() => onAddToWatchlist(scan)}>
                <Eye className="h-3.5 w-3.5" /> Watch
              </button>
              <button type="button" className="btn-secondary btn-sm" onClick={() => onRescan(scan.url)}>
                <RotateCw className="h-3.5 w-3.5" /> Re-scan
              </button>
              <button type="button" className="btn-secondary btn-sm" onClick={() => setPassportOpen(true)}>
                <BadgeCheck className="h-3.5 w-3.5" /> Passport
              </button>
              <button type="button" className="btn-secondary btn-sm" onClick={exportJson}>
                <Download className="h-3.5 w-3.5" /> JSON
              </button>
            </div>
          </div>
        </div>
      </section>

      <div className="no-print">
        <Tabs tabs={tabs} value={tab} onChange={setTab} />
      </div>

      {tab === 'overview' && <OverviewTab scan={scan} />}
      {tab === 'evidence' && <EvidenceTab signals={signals} />}
      {tab === 'identity' && <IdentityTab ci={scan.contactIdentity} />}
      {tab === 'dna' && <DnaTab scan={scan} />}
      {tab === 'timeline' && <TimelineTab timeline={scan.timeline} />}
      {tab === '7d' && (scan.sevenDimensions || scan.preExecution?.sevenDimensions) && (
        <SevenDimensionsTab sevenD={scan.sevenDimensions || scan.preExecution?.sevenDimensions} />
      )}
      {tab === 'pre' && scan.preExecution && <PreExecutionTab pe={scan.preExecution} onNavigate={onNavigate} />}

      <Modal
        open={passportOpen}
        onClose={() => setPassportOpen(false)}
        title="Digital risk passport"
        subtitle="A shareable summary you can attach to a ticket or send to a partner."
        footer={
          <>
            <button type="button" className="btn-ghost" onClick={() => window.print()}>
              <Printer className="h-4 w-4" /> Print
            </button>
            <button type="button" className="btn-primary" onClick={exportJson}>
              <Download className="h-4 w-4" /> Download JSON
            </button>
          </>
        }
      >
        <div className="flex items-center gap-4">
          <ScoreRing score={scan.score} level={scan.risk_level} size={96} stroke={8} label="score" />
          <div className="min-w-0">
            <div className="domain truncate text-[15px]">{scan.domain}</div>
            <div className="mt-1 text-[13px] text-fog-300">{scan.verdict ? sentence(scan.verdict) : meta.label}</div>
          </div>
        </div>
        <dl className="mt-5 grid grid-cols-2 gap-4">
          <KV label="Recommendation">{ACTION_COPY[action] || action}</KV>
          <KV label="Classification">{scan.classification?.primary || '—'}</KV>
          <KV label="Contact transparency">{scan.contactIdentity ? `${sentence(scan.contactIdentity.level)} (${scan.contactIdentity.transparencyScore}/100)` : '—'}</KV>
          <KV label="Verification token"><span className="font-mono text-[13px]">{scan.passport?.verificationToken || '—'}</span></KV>
        </dl>
        <div className="mt-5 flex items-center justify-between gap-3 rounded-xl border border-ink-600/70 bg-ink-900/70 px-4 py-3">
          <div className="min-w-0">
            <div className="text-[12px] text-fog-400">Fingerprint</div>
            <div className="truncate font-mono text-[12px] text-fog-100">{fingerprint}</div>
          </div>
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={() => {
              navigator.clipboard?.writeText(fingerprint);
              setCopied(true);
              setTimeout(() => setCopied(false), 1800);
            }}
          >
            {copied ? <Check className="h-3.5 w-3.5 text-risk-low" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </Modal>
    </div>
  );
}

