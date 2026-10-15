import React, { useCallback, useEffect, useState } from 'react';
import {
  Layers, Search, Loader2, ShieldAlert, ShieldCheck, AlertTriangle, Globe, Network,
  FileText, Sparkles, UserCheck, Activity, HelpCircle, Check, ArrowRight, ExternalLink,
  ChevronRight, BadgeCheck, AlertCircle, Info, DollarSign, Lock, RefreshCw, Zap
} from 'lucide-react';
import { api, errorMessage } from '../services/api';
import { Panel, PageHeader, ScoreRing, RiskBadge, Tabs, Meter, EmptyState, Tag } from './ui';
import { riskMeta, scoreColor } from '../lib/risk';

const DIMENSION_DEFS = [
  { id: 'domain', name: '1. Domain', icon: Globe, weight: '15%', desc: 'Age, tenure, lookalike, subdomain depth, registrar & TLD risk' },
  { id: 'infrastructure', name: '2. Infrastructure', icon: Network, weight: '15%', desc: 'IP, ASN, hosting, SSL & shared flagged infrastructure' },
  { id: 'content', name: '3. Content', icon: FileText, weight: '15%', desc: 'Safe page analysis, forms & category detection' },
  { id: 'claims', name: '4. Claims', icon: DollarSign, weight: '15%', desc: 'Dedicated analysis of guaranteed returns & unrealistic ROI' },
  { id: 'behavior', name: '5. Behavior', icon: Activity, weight: '15%', desc: 'Deposit gates, withdrawal locks, credential collection' },
  { id: 'identity', name: '6. Identity', icon: UserCheck, weight: '15%', desc: 'Corporate credentials, domain email match & messaging-only support' },
  { id: 'threatIntelligence', name: '7. Threat Intel', icon: ShieldAlert, weight: '10%', desc: 'Multi-provider abstraction (VirusTotal, Web Risk, PhishTank, etc.)' }
];

const SAMPLE_TARGETS = [
  { label: 'Unknown but Suspicious', url: 'https://instant-bonus-pay.cc/claim-bonus' },
  { label: 'Bank KYC Phishing', url: 'https://paypal-security-update.fake-auth.xyz/verify-login' },
  { label: 'Betting / Satta App', url: 'https://betwaysatta1.com/maint-betway?maintenance' },
  { label: 'Ponzi Yield Trap', url: 'https://daily-crypto-roi-1000.top/invest' },
  { label: 'Legitimate Enterprise', url: 'https://stripe.com' }
];

export default function SevenDimensionsEngine({ initialUrl = '', onNavigate, onOpenReport }) {
  const [url, setUrl] = useState(initialUrl || 'https://instant-bonus-pay.cc/claim-bonus');
  const [scanning, setScanning] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('matrix');
  const [selectedDimension, setSelectedDimension] = useState('claims');

  const executeScan = useCallback(async (targetUrl) => {
    const t = (targetUrl || url || '').trim();
    if (!t) return;
    setScanning(true);
    setError(null);
    try {
      const res = await api.scan7D(t);
      if (res.success && res.data) {
        setData(res.data);
      } else {
        setError(res.error || '7D Classification analysis failed.');
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setScanning(false);
    }
  }, [url]);

  useEffect(() => {
    // Run initial scan on mount for demonstration
    executeScan('https://instant-bonus-pay.cc/claim-bonus');
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const scoring = data?.scoring;
  const matrix = data?.matrix;
  const classification = data?.classification;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="7D Website Risk Classification Engine"
        description="Multi-dimensional predictive cybersecurity intelligence. Assesses websites across 7 independent vectors with cross-dimension correlation. 'Unknown does not mean safe.'"
        badge={<span className="rounded-full border border-brand-500/40 bg-brand-500/10 px-3 py-1 text-[12px] font-semibold text-brand-300">7D Classification Engine</span>}
      />

      {/* Hero Search Bar */}
      <Panel bodyClassName="p-5 sm:p-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeScan(url);
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <div className="relative flex min-w-0 flex-1 items-center">
            <Search className="pointer-events-none absolute left-3.5 h-4 w-4 text-fog-400" />
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter website URL (e.g. instant-bonus-pay.cc or stripe.com)"
              autoComplete="off"
              spellCheck="false"
              className="input w-full min-w-0 py-3 pl-10 pr-4 font-mono text-[14px]"
            />
          </div>
          <button type="submit" disabled={scanning || !url.trim()} className="btn-primary shrink-0 px-6 py-3">
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
            {scanning ? 'Analyzing 7 Dimensions…' : 'Classify 7D Risk'}
          </button>
        </form>

        <div className="mt-4 flex flex-wrap items-center gap-2 text-[12.5px]">
          <span className="text-fog-400">Quick Test:</span>
          {SAMPLE_TARGETS.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => {
                setUrl(s.url);
                executeScan(s.url);
              }}
              disabled={scanning}
              className="rounded-full border border-ink-600/70 bg-ink-800/80 px-3 py-1 text-fog-200 transition-colors hover:border-brand-400/60 hover:text-white"
            >
              {s.label}
            </button>
          ))}
        </div>
      </Panel>

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-risk-critical/40 bg-risk-critical/10 p-4 text-[13px] text-rose-100">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-critical" />
          <div className="flex-1">{error}</div>
        </div>
      )}

      {data && matrix && (
        <>
          {/* Executive Verdict Banner */}
          <section className="panel grid gap-6 p-6 lg:grid-cols-[1.4fr_1fr] lg:items-center">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2.5">
                <RiskBadge level={scoring.riskLevel} />
                <span className="text-[13px] font-medium text-fog-300">
                  Target: <span className="font-mono text-white">{data.domain}</span>
                </span>
                {scoring.unknownSuspicious && (
                  <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-0.5 text-[11.5px] font-semibold text-amber-200">
                    UNKNOWN BUT SUSPICIOUS
                  </span>
                )}
              </div>

              <div>
                <h2 className="font-display text-[26px] font-semibold text-white sm:text-[30px]">
                  {classification?.primary || 'Evaluated Entity'}
                </h2>
                <p className="mt-1 text-[14px] text-fog-300">
                  Classification Confidence: <span className="font-semibold text-white">{classification?.confidence}%</span>
                  <span className="mx-2 text-fog-500">•</span>
                  Independent from Risk Score ({scoring?.totalScore}/100)
                </p>
              </div>

              {scoring.unknownSuspicious && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/[0.08] p-3 text-[13px] leading-relaxed text-amber-100">
                  <span className="font-semibold">Core Principle Applied:</span> "Unknown does not mean safe." Zero blacklist listings observed, yet multi-dimensional indicators (new domain age, opaque identity, aggressive claims) correlate into elevated risk.
                </div>
              )}

              {classification?.correlationNotes?.length > 0 && (
                <div className="space-y-1.5 text-[13px] text-fog-300">
                  <span className="font-semibold text-fog-100">Cross-Dimension Correlation:</span>
                  {classification.correlationNotes.map((note, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-400" />
                      <span>{note}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex flex-col items-center justify-center rounded-2xl border border-ink-600/50 bg-ink-900/60 p-6 text-center">
              <ScoreRing score={scoring.totalScore} size={140} stroke={12} />
              <div className="mt-3 text-[14px] font-semibold text-white">7D Composite Risk Score</div>
              <div className="text-[12px] text-fog-400">{data.durationMs}ms correlated across 7 dimensions</div>
              {data.recommendation && (
                <div className="mt-3 rounded-lg border border-ink-500/60 bg-ink-800/80 px-3 py-1.5 text-[12px] font-medium text-fog-200">
                  Action: <span className="font-bold text-white">{data.recommendation.action}</span>
                </div>
              )}
            </div>
          </section>

          {/* 7 Dimensions Strip Overview */}
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 [&>*:last-child]:col-span-2 sm:[&>*:last-child]:col-span-1">
            {DIMENSION_DEFS.map((dim) => {
              const dData = matrix[dim.id];
              const score = dData?.score ?? 0;
              const Icon = dim.icon;
              const isSelected = selectedDimension === dim.id;

              return (
                <button
                  key={dim.id}
                  type="button"
                  onClick={() => {
                    setSelectedDimension(dim.id);
                    setActiveTab('inspect');
                  }}
                  className={`panel relative flex flex-col justify-between p-4 text-left transition-all hover:border-brand-400/60 ${
                    isSelected ? 'border-brand-400 ring-2 ring-brand-500/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <Icon className="h-4 w-4 text-fog-300" />
                    <span className="text-[11px] font-mono text-fog-400">{dim.weight}</span>
                  </div>
                  <div className="mt-3">
                    <div className="num text-[22px] font-bold" style={{ color: scoreColor(score) }}>
                      {score}
                    </div>
                    <div className="truncate text-[12px] font-medium text-fog-100">{dim.name}</div>
                  </div>
                  <Meter value={score} className="mt-2.5 h-1" />
                </button>
              );
            })}
          </section>

          {/* Navigation Tabs */}
          <div className="flex border-b border-ink-600/60">
            <button
              type="button"
              onClick={() => setActiveTab('matrix')}
              className={`border-b-2 px-5 py-3 text-[14px] font-medium transition-colors ${
                activeTab === 'matrix' ? 'border-brand-400 text-white' : 'border-transparent text-fog-400 hover:text-fog-200'
              }`}
            >
              7D Signal Matrix
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('claims')}
              className={`border-b-2 px-5 py-3 text-[14px] font-medium transition-colors ${
                activeTab === 'claims' ? 'border-brand-400 text-white' : 'border-transparent text-fog-400 hover:text-fog-200'
              }`}
            >
              Claims Analysis (Dedicated) {matrix.claims.claims?.length > 0 && `(${matrix.claims.claims.length})`}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('behavior')}
              className={`border-b-2 px-5 py-3 text-[14px] font-medium transition-colors ${
                activeTab === 'behavior' ? 'border-brand-400 text-white' : 'border-transparent text-fog-400 hover:text-fog-200'
              }`}
            >
              Behavioral Gates
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('threat')}
              className={`border-b-2 px-5 py-3 text-[14px] font-medium transition-colors ${
                activeTab === 'threat' ? 'border-brand-400 text-white' : 'border-transparent text-fog-400 hover:text-fog-200'
              }`}
            >
              Threat Intelligence Providers
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('inspect')}
              className={`border-b-2 px-5 py-3 text-[14px] font-medium transition-colors ${
                activeTab === 'inspect' ? 'border-brand-400 text-white' : 'border-transparent text-fog-400 hover:text-fog-200'
              }`}
            >
              Dimension Inspector
            </button>
          </div>

          {/* TAB 1: 7D SIGNAL MATRIX */}
          {activeTab === 'matrix' && (
            <div className="grid gap-6 lg:grid-cols-2">
              {DIMENSION_DEFS.map((dim) => {
                const item = matrix[dim.id];
                const Icon = dim.icon;
                if (!item) return null;

                return (
                  <Panel
                    key={dim.id}
                    title={dim.name}
                    subtitle={dim.desc}
                    icon={Icon}
                    action={
                      <div className="flex items-center gap-2">
                        <span className="num text-[16px] font-semibold" style={{ color: scoreColor(item.score) }}>
                          {item.score}/100
                        </span>
                        <span className="text-[12px] text-fog-400">({dim.weight})</span>
                      </div>
                    }
                  >
                    <div className="space-y-3">
                      {item.signals?.length > 0 ? (
                        <ul className="space-y-2">
                          {item.signals.map((sig, sIdx) => (
                            <li key={sIdx} className="rounded-lg border border-ink-600/40 bg-ink-900/50 p-2.5 text-[13px]">
                              <div className="flex items-center justify-between">
                                <span className="font-medium text-white">{sig.signal}</span>
                                <span className={`text-[11px] font-semibold ${sig.severity === 'CRITICAL' ? 'text-rose-400' : sig.severity === 'HIGH' ? 'text-orange-400' : 'text-amber-300'}`}>
                                  {sig.severity}
                                </span>
                              </div>
                              <p className="mt-1 text-[12px] leading-relaxed text-fog-300">{sig.detail}</p>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div className="text-[13px] text-fog-400 italic">No elevated risk signals triggered in this dimension.</div>
                      )}

                      {item.evidence?.length > 0 && (
                        <div className="border-t border-ink-600/40 pt-2.5">
                          <span className="text-[11.5px] uppercase tracking-wider text-fog-400">Dimension Evidence:</span>
                          <ul className="mt-1 space-y-1 text-[12px] text-fog-200">
                            {item.evidence.map((ev, eIdx) => (
                              <li key={eIdx} className="flex items-baseline gap-2">
                                <span className="h-1 w-1 shrink-0 rounded-full bg-brand-400" />
                                <span>{ev}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </Panel>
                );
              })}
            </div>
          )}

          {/* TAB 2: CLAIMS ANALYSIS (DEDICATED) */}
          {activeTab === 'claims' && (
            <Panel
              title="Dimension 4 — Dedicated Claims Analysis"
              subtitle="Detects suspicious financial, yield, ROI, bonus, and promotional promises"
              icon={DollarSign}
            >
              {matrix.claims.claims?.length > 0 ? (
                <div className="space-y-4">
                  <div className="rounded-xl border border-brand-500/20 bg-brand-500/[0.06] p-4 text-[13.5px] leading-relaxed text-fog-200">
                    <span className="font-semibold text-white">Claims Engine Analysis:</span> The system extracts promotional guarantees and evaluates whether they violate financial logic (e.g. daily compound yield, risk-free profit). Claims are treated as contributing signals, not standalone fraud proof.
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    {matrix.claims.claims.map((claim, cIdx) => (
                      <div key={cIdx} className="panel-inset border-l-4 border-l-amber-400 p-4">
                        <div className="flex items-start justify-between gap-3">
                          <span className="text-[12px] font-semibold text-amber-300">{claim.type}</span>
                          <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[11px] font-bold text-rose-300">
                            {claim.severity}
                          </span>
                        </div>
                        <blockquote className="mt-2 text-[14px] font-medium italic text-white">
                          “{claim.claim}”
                        </blockquote>
                        <p className="mt-2 text-[12.5px] leading-relaxed text-fog-300">{claim.explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState icon={DollarSign} title="No Suspicious Promotional Claims Detected">
                  The content scanner did not detect unverified daily ROI, guaranteed profits, or excessive bonus multiplier claims.
                </EmptyState>
              )}
            </Panel>
          )}

          {/* TAB 3: BEHAVIORAL GATES */}
          {activeTab === 'behavior' && (
            <Panel
              title="Dimension 5 — Behavioral Intent & User Actions"
              subtitle="Analyzes what the site attempts to make the visitor do (onboarding, deposit gates, withdrawal locks)"
              icon={Activity}
            >
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="panel-inset p-3.5">
                    <div className="text-[12px] text-fog-400">Deposit Gating</div>
                    <div className="mt-1 font-semibold text-white">
                      {matrix.behavior.metrics?.demandsDeposit ? 'Active Deposit Trigger' : 'Not Detected'}
                    </div>
                  </div>
                  <div className="panel-inset p-3.5">
                    <div className="text-[12px] text-fog-400">Credential Intake</div>
                    <div className="mt-1 font-semibold text-white">
                      {matrix.behavior.metrics?.harvestsCredentials ? 'High-Priority Auth Form' : 'Standard Navigation'}
                    </div>
                  </div>
                  <div className="panel-inset p-3.5">
                    <div className="text-[12px] text-fog-400">Urgency Mechanics</div>
                    <div className="mt-1 font-semibold text-white">
                      {matrix.behavior.metrics?.urgencyCuesDetected ? 'Countdown / Urgent Action' : 'Standard Flow'}
                    </div>
                  </div>
                </div>

                <ul className="space-y-2">
                  {matrix.behavior.signals?.map((bSig, bIdx) => (
                    <li key={bIdx} className="rounded-xl border border-ink-600/60 bg-ink-900/60 p-4">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-white">{bSig.signal}</span>
                        <span className="text-[12px] font-mono text-fog-300">+{bSig.impact} pts</span>
                      </div>
                      <p className="mt-1 text-[13px] text-fog-300">{bSig.detail}</p>
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}

          {/* TAB 4: THREAT INTEL PROVIDERS */}
          {activeTab === 'threat' && (
            <Panel
              title="Dimension 7 — Multi-Provider Threat Intelligence"
              subtitle="Normalized feeds across VirusTotal, Google Web Risk, PhishTank, URLhaus, OpenPhish"
              icon={ShieldAlert}
            >
              <div className="space-y-4">
                <div className="rounded-xl border border-ink-600/60 bg-ink-900/80 p-4 text-[13.5px] leading-relaxed text-fog-200">
                  <div className="flex items-center gap-2 font-semibold text-white">
                    <Info className="h-4 w-4 text-signal-400" />
                    Strict Operational Requirement:
                  </div>
                  <p className="mt-1">
                    When every threat intelligence provider returns clean, the platform outputs:
                    <span className="font-mono text-signal-300"> "No known threat-intelligence match found."</span>
                    It will <strong className="text-white">NEVER</strong> state "Website is safe", because new scam domains are registered faster than blacklists can populate.
                  </p>
                </div>

                <div className="divide-y divide-ink-600/50 rounded-xl border border-ink-600/50 bg-ink-900/40">
                  {matrix.threatIntelligence.providers?.map((prov, pIdx) => (
                    <div key={pIdx} className="flex items-center justify-between p-3.5">
                      <div>
                        <div className="font-medium text-white">{prov.provider}</div>
                        <div className="text-[12px] text-fog-400">{prov.source}</div>
                      </div>
                      <div className="text-right">
                        <span className={`inline-block rounded px-2.5 py-0.5 text-[12px] font-semibold ${
                          prov.status === 'DETECTED' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/10 text-emerald-300'
                        }`}>
                          {prov.status === 'DETECTED' ? `DETECTED (${prov.detections})` : 'NOT LISTED'}
                        </span>
                        <div className="text-[11px] text-fog-400">{prov.category || 'clean'}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          )}

          {/* TAB 5: DIMENSION INSPECTOR */}
          {activeTab === 'inspect' && (
            <Panel
              title={`Inspecting: ${DIMENSION_DEFS.find((d) => d.id === selectedDimension)?.name}`}
              subtitle={DIMENSION_DEFS.find((d) => d.id === selectedDimension)?.desc}
            >
              {matrix[selectedDimension] && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-xl border border-ink-600/60 bg-ink-900/70 p-4">
                    <div>
                      <div className="text-[12px] text-fog-400">Dimension Score</div>
                      <div className="num text-[28px] font-bold" style={{ color: scoreColor(matrix[selectedDimension].score) }}>
                        {matrix[selectedDimension].score}/100
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[12px] text-fog-400">Weighted Influence</div>
                      <div className="text-[18px] font-semibold text-white">{matrix[selectedDimension].weight}% of composite</div>
                    </div>
                  </div>

                  {matrix[selectedDimension].metrics && (
                    <div className="rounded-xl border border-ink-600/60 bg-ink-900/40 p-4">
                      <div className="text-[12px] font-semibold uppercase tracking-wider text-fog-400">Telemetry Metrics</div>
                      <div className="mt-2 grid gap-2 sm:grid-cols-2">
                        {Object.entries(matrix[selectedDimension].metrics).map(([k, v]) => (
                          <div key={k} className="flex justify-between border-b border-ink-700/50 py-1.5 text-[13px]">
                            <span className="text-fog-400">{k}</span>
                            <span className="font-mono text-white">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
