import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Radar, Search, Loader2, Check, AlertTriangle, ShieldCheck, Globe, ShieldAlert, Network, Tag as TagIcon, UserCheck,
  SlidersHorizontal, BadgeCheck, Copy, FileSearch, Eye, FlaskConical, HelpCircle, Printer
} from 'lucide-react';
import { api, errorMessage } from '../services/api';
import { Panel, PageHeader, ScoreRing, RiskBadge, Tabs, Meter, Modal, Tag, EmptyState } from './ui';
import { riskMeta, scoreColor } from '../lib/risk';

const STAGES = [
  { title: 'Domain intelligence', desc: 'WHOIS/RDAP age, DNS, SSL and network owner' },
  { title: 'Threat intelligence', desc: 'VirusTotal, Google Web Risk, PhishTank, URLhaus, OpenPhish' },
  { title: 'Infrastructure', desc: 'Sites sharing the same IP, nameservers and certificates' },
  { title: 'Classification', desc: 'Betting, Ponzi, phishing and crypto-scam language' },
  { title: 'Contact & identity', desc: 'Business email, address, registry and messaging-only support' },
  { title: 'Correlation', desc: 'Weak signals combined into one explainable score' }
];

const FALLBACK_SCENARIOS = [
  { id: 'unknown-suspicious', title: 'Unknown but suspicious', url: 'https://instant-bonus-pay.cc/claim-bonus', category: 'Gambling / referral scheme' },
  { id: 'known-phishing', title: 'Known phishing domain', url: 'https://paypal-security-update.fake-auth.xyz/verify-login', category: 'Phishing' },
  { id: 'new-gambling', title: 'New betting platform', url: 'https://bet777-instant-win.online/sportsbook', category: 'Betting / casino' },
  { id: 'ponzi-scheme', title: 'High-yield Ponzi scheme', url: 'https://daily-crypto-roi-1000.top/invest', category: 'Ponzi / crypto' },
  { id: 'legitimate-enterprise', title: 'Legitimate enterprise', url: 'https://stripe.com', category: 'Legitimate' }
];

const sentence = (s = '') => (s ? s.charAt(0) + s.slice(1).toLowerCase().replace(/_/g, ' ') : '');

function KV({ label, children, mono }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-ink-700/60 py-2 last:border-0">
      <dt className="shrink-0 text-[13px] text-fog-400">{label}</dt>
      <dd className={`min-w-0 truncate text-right text-[13px] text-fog-50 ${mono ? 'font-mono' : ''}`}>{children}</dd>
    </div>
  );
}

/** target → IP → network → neighbouring domains */
function InfraGraph({ result }) {
  const related = (result.intelligence.infrastructure.relatedDomains || []).slice(0, 6);
  const W = 720;
  const rowH = 52;
  const H = Math.max(200, related.length * rowH + 40);
  const cy = H / 2;
  const node = (x, y, w, label, sub, tone) => (
    <g>
      <rect x={x} y={y - 22} width={w} height="44" rx="10" fill={tone.fill} stroke={tone.stroke} />
      <text x={x + 12} y={y - 3} fontSize="12" fill={tone.text} fontFamily="IBM Plex Mono">{label.length > 24 ? `${label.slice(0, 23)}…` : label}</text>
      <text x={x + 12} y={y + 13} fontSize="10.5" fill="#8188BA" fontFamily="IBM Plex Sans">{sub}</text>
    </g>
  );
  const base = { fill: '#141838', stroke: '#3A4178', text: '#E6E8FA' };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Infrastructure relationships">
      <path d={`M190 ${cy} H230`} stroke="#3A4178" strokeWidth="1.5" />
      <path d={`M380 ${cy} H420`} stroke="#3A4178" strokeWidth="1.5" />
      {related.map((d, i) => {
        const y = 20 + rowH / 2 + i * rowH + (H - 40 - related.length * rowH) / 2;
        const flagged = d.status === 'flagged';
        return (
          <path key={d.domain} d={`M420 ${cy} C 470 ${cy}, 470 ${y}, 500 ${y}`} fill="none" stroke={flagged ? '#F43F5E' : '#3A4178'} strokeOpacity={flagged ? 0.8 : 1} strokeWidth="1.5" />
        );
      })}
      {node(10, cy, 180, result.domain, 'Target', { fill: '#1E1650', stroke: '#8B5CF6', text: '#fff' })}
      {node(230, cy, 150, result.intelligence.domain.ipAddress || '—', 'Resolves to', base)}
      {related.map((d, i) => {
        const y = 20 + rowH / 2 + i * rowH + (H - 40 - related.length * rowH) / 2;
        const flagged = d.status === 'flagged';
        return (
          <g key={d.domain}>
            {node(500, y, 210, d.domain, flagged ? `Flagged · ${sentence(d.relationship)}` : sentence(d.relationship), flagged ? { fill: '#2A0F22', stroke: '#F43F5E', text: '#FECDD3' } : base)}
          </g>
        );
      })}
      <text x="400" y={cy - 30} textAnchor="middle" fontSize="10.5" fill="#8188BA" fontFamily="IBM Plex Sans">
        {result.intelligence.domain.asn?.asn} · {result.intelligence.domain.asn?.name}
      </text>
    </svg>
  );
}

export default function PreExecutionScanner({ request, onAddToWatchlist, onOpenReport, onScanned }) {
  const [url, setUrl] = useState(request?.target || '');
  const [scanning, setScanning] = useState(false);
  const [step, setStep] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('domain');
  const [demoMode, setDemoMode] = useState(false);
  const [scenarios, setScenarios] = useState(FALLBACK_SCENARIOS);
  const [copied, setCopied] = useState(false);
  const [methodOpen, setMethodOpen] = useState(false);
  const demoRef = useRef(demoMode);
  useEffect(() => {
    demoRef.current = demoMode;
  }, [demoMode]);

  useEffect(() => {
    api.getDemoScenarios().then((res) => res?.data?.length && setScenarios(res.data)).catch(() => {});
  }, []);

  const runScan = useCallback(
    async (target, options = {}) => {
      const t = (target || '').trim();
      if (!t) return;
      setUrl(t);
      setScanning(true);
      setError(null);
      setStep(0);
      const timer = setInterval(() => setStep((s) => Math.min(s + 1, STAGES.length - 1)), 380);
      try {
        const res = await api.scanPreExecution(t, { demoMode: options.demoMode ?? demoRef.current, demoScenario: options.demoScenario });
        setStep(STAGES.length);
        await new Promise((r) => setTimeout(r, 350));
        setResult(res.data);
        setTab('domain');
        onScanned?.();
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        clearInterval(timer);
        setScanning(false);
      }
    },
    [onScanned]
  );

  // Only an explicit request (dashboard button, extension deep link) triggers an automatic scan
  useEffect(() => {
    if (request?.target) runScan(request.target);
  }, [request?.nonce]); // eslint-disable-line react-hooks/exhaustive-deps

  const copyToken = (token) => {
    navigator.clipboard?.writeText(token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const s = result?.scoring;
  const intel = result?.intelligence;
  const peMeta = s ? riskMeta(s.riskLevel) : null;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Pre-execution scan"
        description="Inspect a website before you click, log in or pay. Everything is collected server-side, so the site’s scripts never run in your browser."
        actions={
          <>
            <button type="button" className="btn-ghost" onClick={() => setMethodOpen(true)}>
              <HelpCircle className="h-4 w-4" /> How it works
            </button>
            <button
              type="button"
              onClick={() => setDemoMode((d) => !d)}
              aria-pressed={demoMode}
              className={demoMode ? 'btn border border-signal-400/50 bg-signal-400/15 text-signal-100' : 'btn-secondary'}
            >
              <FlaskConical className="h-4 w-4" /> {demoMode ? 'Demo data on' : 'Demo data off'}
            </button>
          </>
        }
      />

      <Panel bodyClassName="p-5 sm:p-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runScan(url);
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <label htmlFor="pe-url" className="sr-only">
            Website to inspect
          </label>
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fog-400" />
            <input
              id="pe-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={scanning}
              placeholder="https://instant-bonus-pay.cc/claim-bonus"
              autoComplete="off"
              spellCheck="false"
              className="input py-3 pl-10 font-mono"
            />
          </div>
          <button type="submit" disabled={scanning || !url.trim()} className="btn-signal px-6 py-3">
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            {scanning ? 'Inspecting…' : 'Inspect safely'}
          </button>
        </form>

        <div className="mt-5">
          <div className="mb-2 text-[13px] text-fog-400">Demo scenarios — each one shows a different kind of risk</div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {scenarios.slice(0, 5).map((sc) => {
              const active = result?.url && sc.url.includes(result.domain);
              return (
                <button
                  key={sc.id}
                  type="button"
                  disabled={scanning}
                  onClick={() => runScan(sc.url, { demoMode: true, demoScenario: sc.id })}
                  className={`rounded-xl border px-3.5 py-3 text-left transition-colors disabled:opacity-50 ${
                    active ? 'border-signal-400/60 bg-signal-400/10' : 'border-ink-600/70 bg-ink-900/50 hover:border-ink-500 hover:bg-ink-800'
                  }`}
                >
                  <div className="text-[13px] font-medium text-white">{sc.title.replace(/\s*\(.*\)$/, '')}</div>
                  <div className="mt-0.5 truncate text-[12px] text-fog-400">{sc.category}</div>
                </button>
              );
            })}
          </div>
        </div>
      </Panel>

      {error && (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-risk-critical/40 bg-risk-critical/10 px-4 py-3 text-[13px] text-rose-100">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-critical" />
          <span className="flex-1">{error}</span>
          <button type="button" className="text-rose-200 underline-offset-2 hover:underline" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {scanning && (
        <Panel bodyClassName="p-6">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {STAGES.map((st, i) => {
              const done = i < step;
              const current = i === step;
              return (
                <div
                  key={st.title}
                  className={`rounded-xl border px-4 py-3 transition-colors ${
                    done ? 'border-risk-low/30 bg-risk-low/5' : current ? 'border-signal-400/50 bg-signal-400/10' : 'border-ink-600/60 bg-ink-900/40 opacity-60'
                  }`}
                >
                  <div className="flex items-center gap-2 text-[14px] font-medium text-white">
                    {done ? <Check className="h-4 w-4 text-risk-low" /> : current ? <Loader2 className="h-4 w-4 animate-spin text-signal-400" /> : <span className="h-4 w-4 rounded-full border border-ink-500" />}
                    {st.title}
                  </div>
                  <p className="mt-1 text-[12px] leading-snug text-fog-400">{st.desc}</p>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {!scanning && !result && !error && (
        <Panel>
          <EmptyState icon={Radar} title="Pick a scenario or paste a link">
            You’ll see the score, the reasons behind it, and every intelligence source that contributed — before anything loads.
          </EmptyState>
        </Panel>
      )}

      {result && !scanning && (
        <>
          <section className="panel relative overflow-hidden">
            <div className="pointer-events-none absolute inset-x-0 top-0 h-1" style={{ background: peMeta.color }} aria-hidden />
            <div className="grid gap-6 p-4 sm:p-6 lg:p-8 sm:grid-cols-[auto_1fr] lg:grid-cols-[auto_1fr_minmax(0,280px)] items-center sm:items-start">
              <div className="flex justify-center sm:justify-start">
                <ScoreRing score={s.totalScore} level={s.riskLevel} size={150} />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <RiskBadge level={s.riskLevel} />
                  <Tag>{result.classification.primary} · {result.classification.confidence}%</Tag>
                  {result.demoMode && <Tag className="border-signal-400/40 text-signal-100">Simulated feeds</Tag>}
                </div>
                <h2 className="mt-3 break-all font-mono text-[22px] text-white">{result.domain}</h2>
                <p className="mt-2 text-[15px] leading-relaxed text-fog-200">{s.riskDescription}</p>
                {s.unknownSuspicious && (
                  <div className="mt-4 rounded-xl border border-signal-400/40 bg-signal-400/[0.08] px-4 py-3">
                    <div className="font-display text-[16px] font-semibold text-signal-300">Unknown but suspicious</div>
                    <p className="mt-0.5 text-[13px] leading-snug text-fog-200">
                      No threat feed lists this site yet — but independent signals (young domain, risky neighbours, weak identity) add up to real risk.
                    </p>
                  </div>
                )}
                <p className="mt-3 text-[13px] text-fog-400">{result.classification.explanation}</p>
              </div>
              <div className="flex flex-col gap-2">
                {result.reportScanId && (
                  <button type="button" className="btn-primary" onClick={() => onOpenReport(result.reportScanId)}>
                    <FileSearch className="h-4 w-4" /> Open full report
                  </button>
                )}
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => onAddToWatchlist({ url: result.url, domain: result.domain, alert_notes: `${result.classification.primary} — pre-execution watch` })}
                >
                  <Eye className="h-4 w-4" /> Add to watchlist
                </button>
                <button type="button" className="btn-ghost justify-between" onClick={() => copyToken(result.verificationToken)} title="Copy verification token">
                  <span className="font-mono text-[12px]">{result.verificationToken}</span>
                  {copied ? <Check className="h-3.5 w-3.5 text-risk-low" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
                <p className="text-[12px] text-fog-500">Scanned in {result.durationMs} ms</p>
              </div>
            </div>

            <div className="border-t border-ink-600/60 px-6 py-5 sm:px-8">
              <h3 className="panel-title">Why</h3>
              <ul className="mt-3 grid gap-x-8 gap-y-3 md:grid-cols-2">
                {s.topFactors.map((f, i) => (
                  <li key={`n${i}`} className="flex gap-3">
                    <span className="num mt-0.5 w-8 shrink-0 text-right text-[13px] font-semibold text-rose-300">+{f.impact}</span>
                    <span className="min-w-0">
                      <span className="block text-[14px] text-fog-50">{f.signal}</span>
                      <span className="block text-[13px] leading-snug text-fog-400">{f.detail}</span>
                    </span>
                  </li>
                ))}
                {(s.positiveFactors || []).map((f, i) => (
                  <li key={`p${i}`} className="flex gap-3">
                    <span className="num mt-0.5 w-8 shrink-0 text-right text-[13px] font-semibold text-emerald-300">{f.impact}</span>
                    <span className="min-w-0">
                      <span className="block text-[14px] text-fog-50">{f.signal}</span>
                      <span className="block text-[13px] leading-snug text-fog-400">{f.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { id: 'domain', label: 'Domain', icon: Globe },
              { id: 'threat', label: 'Threat feeds', icon: ShieldAlert },
              { id: 'infra', label: 'Infrastructure', icon: Network },
              { id: 'class', label: 'Content', icon: TagIcon },
              { id: 'identity', label: 'Identity', icon: UserCheck },
              { id: 'scoring', label: 'Score breakdown', icon: SlidersHorizontal },
              { id: 'passport', label: 'Passport', icon: BadgeCheck }
            ]}
          />

          {tab === 'domain' && (
            <div className="grid gap-6 lg:grid-cols-3">
              <Panel title="Registration">
                <dl>
                  <KV label="Age">{intel.domain.ageDays} days</KV>
                  <KV label="Created" mono>{intel.domain.registrationDate}</KV>
                  <KV label="Expires" mono>{intel.domain.expirationDate}</KV>
                  <KV label="Registrar">{intel.domain.registrar}</KV>
                  <KV label="WHOIS privacy">{intel.domain.whoisPrivacy ? 'Hidden' : 'Public'}</KV>
                </dl>
              </Panel>
              <Panel title="Network">
                <dl>
                  <KV label="IP address" mono>{intel.domain.ipAddress}</KV>
                  <KV label="Network" mono>{intel.domain.asn?.asn}</KV>
                  <KV label="Owner">{intel.domain.asn?.org || intel.domain.asn?.name}</KV>
                  <KV label="Hosting">{intel.domain.hostingProvider}</KV>
                  <KV label="Country">{intel.domain.country}</KV>
                </dl>
              </Panel>
              <Panel title="Certificate & DNS">
                <dl>
                  <KV label="Certificate">{intel.domain.ssl?.type}</KV>
                  <KV label="Issuer">{intel.domain.ssl?.issuer}</KV>
                  <KV label="Expires in">{intel.domain.ssl?.daysRemaining} days</KV>
                  <KV label="Nameservers" mono>{(intel.domain.dnsRecords?.ns || []).join(', ') || '—'}</KV>
                  <KV label="Mail (MX)" mono>{(intel.domain.dnsRecords?.mx || []).join(', ') || 'None'}</KV>
                </dl>
              </Panel>
            </div>
          )}

          {tab === 'threat' && (
            <Panel title="Threat-intelligence feeds" subtitle={intel.threat.summary.text} bodyClassName="p-0">
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      <th>Result</th>
                      <th className="text-right">Detections</th>
                      <th className="hidden sm:table-cell">Category</th>
                    </tr>
                  </thead>
                  <tbody>
                    {intel.threat.providers.map((p) => (
                      <tr key={p.provider}>
                        <td className="font-medium text-fog-50">
                          {p.provider}
                          {p.realData === false && <span className="ml-2 text-[12px] font-normal text-fog-500">simulated</span>}
                        </td>
                        <td>
                          <span className={p.status === 'DETECTED' ? 'text-rose-300' : p.status === 'PROVIDER_UNAVAILABLE' ? 'text-fog-400' : 'text-emerald-300'}>
                            {p.status === 'DETECTED' ? 'Flagged' : p.status === 'PROVIDER_UNAVAILABLE' ? 'Unavailable' : 'Not listed'}
                          </span>
                        </td>
                        <td className="num text-right">{p.detections} / {p.totalEngines}</td>
                        <td className="hidden capitalize text-fog-300 sm:table-cell">{p.category}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {intel.threat.summary.isClean && (
                <p className="border-t border-ink-600/60 px-5 py-4 text-[13px] text-fog-300">
                  <span className="font-semibold text-signal-300">Not listed is not the same as safe.</span> New scam domains usually go 7–14 days before any feed catches them.
                </p>
              )}
            </Panel>
          )}

          {tab === 'infra' && (
            <Panel
              title="Who else lives on this server?"
              subtitle={
                intel.infrastructure.flaggedDomains.length
                  ? `${intel.infrastructure.flaggedDomains.length} neighbouring site(s) were previously reported. Sharing a host doesn’t prove guilt, but dense clusters deserve scrutiny.`
                  : 'No previously reported sites share this infrastructure.'
              }
            >
              {intel.infrastructure.relatedDomains.length ? <InfraGraph result={result} /> : <p className="text-[13px] text-fog-400">No related domains observed.</p>}
            </Panel>
          )}

          {tab === 'class' && (
            <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
              <Panel title={result.classification.primary} subtitle={`${result.classification.confidence}% confidence`}>
                <div className="flex flex-wrap gap-1.5">
                  {result.classification.secondary.map((t) => <Tag key={t}>{t}</Tag>)}
                </div>
                <p className="mt-4 text-[13px] leading-relaxed text-fog-300">{result.classification.explanation}</p>
              </Panel>
              <Panel title="Phrases and cues found" subtitle="Read from the page server-side — nothing executed">
                {result.classification.contentSignals?.length ? (
                  <ul className="grid gap-2 sm:grid-cols-2">
                    {result.classification.contentSignals.map((c, i) => (
                      <li key={i} className="panel-inset px-3.5 py-2.5">
                        <div className="text-[13px] text-fog-50">“{c.text}”</div>
                        <div className="mt-0.5 text-[12px] text-fog-400">{sentence(c.category)}</div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-[13px] text-fog-400">No risky phrases detected.</p>
                )}
              </Panel>
            </div>
          )}

          {tab === 'identity' && (
            <Panel title={`Identity transparency: ${sentence(intel.identity.level)}`} subtitle={`${intel.identity.transparencyScore}/100 · ${intel.identity.messagingOnly ? 'Support only via Telegram/WhatsApp' : 'Multiple contact channels'}`}>
              <ul className="grid gap-3 md:grid-cols-2">
                {intel.identity.checks.map((c, i) => (
                  <li key={i} className="panel-inset flex gap-3 p-4">
                    {c.status === 'POSITIVE' ? <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-risk-low" /> : c.status === 'NEGATIVE' ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-critical" /> : <HelpCircle className="mt-0.5 h-4 w-4 shrink-0 text-fog-400" />}
                    <div className="min-w-0">
                      <div className="font-medium text-fog-50">{c.signal}</div>
                      <p className="mt-0.5 text-[13px] leading-snug text-fog-400">{c.detail}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {tab === 'scoring' && (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Object.entries(s.components).map(([k, c]) => {
                const pct = Math.round((c.score / c.maxPoints) * 100);
                return (
                  <Panel key={k} title={c.label} action={<span className="num text-[15px] text-white">{c.score}<span className="text-fog-400">/{c.maxPoints}</span></span>}>
                    <Meter value={pct} color={scoreColor(pct)} />
                    <ul className="mt-4 space-y-2.5">
                      {c.signals.slice(0, 4).map((sig, i) => {
                        const impact = sig.scoreImpact ?? sig.impact;
                        return (
                          <li key={i} className="flex gap-2.5 text-[13px]">
                            <span className={`num w-8 shrink-0 text-right ${impact > 0 ? 'text-rose-300' : impact < 0 ? 'text-emerald-300' : 'text-fog-500'}`}>
                              {impact > 0 ? `+${impact}` : impact ?? '·'}
                            </span>
                            <span className="text-fog-200">{sig.signal}</span>
                          </li>
                        );
                      })}
                      {c.signals.length === 0 && <li className="text-[13px] text-fog-500">No signals in this dimension.</li>}
                    </ul>
                  </Panel>
                );
              })}
            </div>
          )}

          {tab === 'passport' && (
            <Panel
              title="Digital risk passport"
              subtitle="A shareable, verifiable summary of this assessment"
              action={
                <button type="button" className="btn-secondary btn-sm" onClick={() => window.print()}>
                  <Printer className="h-3.5 w-3.5" /> Print
                </button>
              }
            >
              <dl className="grid gap-x-10 sm:grid-cols-2">
                <KV label="Website" mono>{result.passport.domain}</KV>
                <KV label="Passport ID" mono>{result.passport.passportId}</KV>
                <KV label="Risk score">{result.passport.overallScore}/100 · {sentence(result.passport.riskLevel)}</KV>
                <KV label="Status">{sentence(result.passport.statusLabel)}</KV>
                <KV label="Classification">{result.passport.classification.primary}</KV>
                <KV label="Compliance">{sentence(result.passport.complianceStatus)}</KV>
                <KV label="Threat feeds">{result.passport.threatIntelSummary.detectedBy} of {result.passport.threatIntelSummary.totalEngines} flagged</KV>
                <KV label="Flagged neighbours">{result.passport.infrastructureSummary.flaggedDomainsAssociated}</KV>
                <KV label="Verification token" mono>{result.passport.verificationToken}</KV>
                <KV label="Issued">{new Date(result.passport.timestamp).toLocaleString()}</KV>
              </dl>
            </Panel>
          )}
        </>
      )}

      <Modal
        open={methodOpen}
        onClose={() => setMethodOpen(false)}
        title="How pre-execution scanning works"
        footer={<button type="button" className="btn-primary" onClick={() => setMethodOpen(false)}>Got it</button>}
      >
        <div className="space-y-4 text-[14px] leading-relaxed text-fog-200">
          <p>
            Risk Radar never opens the site in your browser. Our server collects public intelligence about it and correlates the signals into one explainable score.
          </p>
          <ul className="space-y-3">
            {[
              ['Unknown isn’t safe.', 'A site missing from VirusTotal or PhishTank may simply be too new to be listed.'],
              ['Weak signals add up.', 'A 2-day-old domain, a host shared with reported scams and Telegram-only support together are a strong warning.'],
              ['Every point is explained.', 'Each part of the score links back to the evidence that produced it.'],
              ['Nothing runs locally.', 'The target’s JavaScript is never executed on your device.']
            ].map(([h, b]) => (
              <li key={h} className="flex gap-3">
                <Check className="mt-1 h-4 w-4 shrink-0 text-signal-400" />
                <span>
                  <span className="font-semibold text-white">{h}</span> {b}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </Modal>
    </div>
  );
}
