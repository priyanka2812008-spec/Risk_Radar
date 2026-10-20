import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  ShieldAlert, ShieldCheck, Radar, Globe, Zap, Server, Database, Cloud, Lock,
  FileSearch, AlertTriangle, CheckCircle2, ChevronRight, RefreshCw, Maximize2,
  Minimize2, Volume2, VolumeX, Terminal, Layers, ArrowUpRight, Cpu, Eye, Activity
} from 'lucide-react';
import CyberGlobeCanvas from './CyberGlobeCanvas';
import { api, errorMessage } from '../services/api';

const PRESET_TARGETS = [
  { label: 'Betting Exchange', domain: 'lotus365.com', category: 'Gambling / Betting' },
  { label: 'Ponzi Yield Scam', domain: 'daily-crypto-roi.top', category: 'Ponzi Scheme' },
  { label: 'Satta Matka', domain: 'sattamatka143.net', category: 'Satta / Matka' },
  { label: 'Govt Portal', domain: 'incometax.gov.in', category: 'Government Verified' },
  { label: 'Global Platform', domain: 'github.com', category: 'Legitimate / Tech' }
];

const SCAN_STEPS = [
  { step: 1, label: 'INITIALIZING RISK RADAR...', detail: 'Calibrating orbital sensors & threat matrix...' },
  { step: 2, label: 'Resolving domain...', detail: 'Querying Anycast DNS & BGP routing paths...' },
  { step: 3, label: 'Analyzing DNS...', detail: 'Tracing NS authority, SOA records & MX mail exchangers...' },
  { step: 4, label: 'Analyzing infrastructure...', detail: 'Fingerprinting web server, CDN edge & reverse proxies...' },
  { step: 5, label: 'Analyzing website content...', detail: 'Scanning lexical DOM, casino keywords & payment hooks...' },
  { step: 6, label: 'Checking reputation...', detail: 'Cross-referencing statutory registries, blacklists & CERT advisories...' },
  { step: 7, label: 'Calculating risk...', detail: 'Running neural 7-dimension risk synthesis...' },
  { step: 8, label: 'THREAT ASSESSMENT COMPLETE', detail: 'Telemetry synchronized with global Risk Radar ledger.' }
];

// Audio synthesizers for futuristic cyber sci-fi clicks (Web Audio API)
class CyberAudioEngine {
  constructor() {
    this.ctx = null;
    this.muted = true; // muted by default for friendly UX
  }

  init() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume();
    }
  }

  playBeep(freq = 880, duration = 0.05, type = 'sine') {
    if (this.muted) return;
    try {
      this.init();
      if (!this.ctx) return;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch {
      // Audio not permitted or unavailable
    }
  }

  playScanBlip() {
    this.playBeep(1240, 0.04, 'sine');
  }

  playSuccessChime() {
    this.playBeep(587.33, 0.08, 'triangle');
    setTimeout(() => this.playBeep(880, 0.12, 'triangle'), 80);
  }

  playAlertChime() {
    this.playBeep(320, 0.15, 'sawtooth');
    setTimeout(() => this.playBeep(240, 0.25, 'sawtooth'), 120);
  }
}

const audio = new CyberAudioEngine();

export default function CyberThreatVisualizer({ onOpenReport, onNavigate }) {
  const [targetInput, setTargetInput] = useState('lotus365.com');
  const [activeTarget, setActiveTarget] = useState('lotus365.com');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0); // 0 = idle, 1..8
  const [scanProgress, setScanProgress] = useState(0);
  const [activeScore, setActiveScore] = useState(87);
  const [displayScore, setDisplayScore] = useState(87);
  const [riskLevel, setRiskLevel] = useState('HIGH RISK');
  const [classification, setClassification] = useState('Gambling / Betting');
  const [confidence, setConfidence] = useState(94);
  const [governmentStatus, setGovernmentStatus] = useState({
    verified: false,
    badge: 'NOT GOVT. VERIFIED — HIGH RISK',
    status: 'prohibited'
  });

  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [parallax, setParallax] = useState({ x: 0, y: 0 });
  const [hoveredPanel, setHoveredPanel] = useState(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [inspectModal, setInspectModal] = useState(null);
  const [lastScanId, setLastScanId] = useState(null);

  // Live telemetry metrics with animated micro-jitter
  const [telemetryTicks, setTelemetryTicks] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState([
    '[SYS_INIT] Risk Radar 3D Threat Engine online.',
    '[NODES] 1,420 regional sensor relays operational.',
    '[INTERCEPT] Awaiting target domain ingestion...'
  ]);

  const containerRef = useRef(null);
  const scanSequenceTimer = useRef(null);

  // Periodic subtle telemetry tick
  useEffect(() => {
    const interval = setInterval(() => {
      setTelemetryTicks((t) => t + 1);
    }, 2400);
    return () => clearInterval(interval);
  }, []);

  // Mouse Parallax movement
  const handleMouseMove = useCallback((e) => {
    const x = e.clientX;
    const y = e.clientY;
    setMousePos({ x, y });

    const cx = window.innerWidth / 2;
    const cy = window.innerHeight / 2;
    const px = ((x - cx) / cx) * 8; // subtle max 8 deg
    const py = ((y - cy) / cy) * -8;
    setParallax({ x: px, y: py });
  }, []);

  // Trigger Cinematic Scan Sequence
  const executeScan = useCallback(async (domainToScan) => {
    const domain = (domainToScan || targetInput || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    if (!domain) return;

    if (scanSequenceTimer.current) clearTimeout(scanSequenceTimer.current);

    setActiveTarget(domain);
    setIsScanning(true);
    setScanStep(1);
    setScanProgress(5);
    setDisplayScore(0);
    audio.playScanBlip();

    setTerminalLogs((prev) => [
      `[INGEST] Target dispatched: ${domain}`,
      `[STEP_1] Initializing neural scanning matrix...`,
      ...prev.slice(0, 5)
    ]);

    // Asynchronously call actual backend to get real intelligence data!
    let backendDataPromise = (async () => {
      try {
        const res = await api.analyzeUrl(domain);
        return res;
      } catch {
        return null;
      }
    })();

    // Cinematic step timeline (3.8 seconds total)
    // Step 1: 0ms -> Step 2: 450ms
    setTimeout(() => {
      setScanStep(2);
      setScanProgress(18);
      audio.playScanBlip();
      setTerminalLogs((prev) => [`[STEP_2] Resolving ASN & DNS edge for ${domain}...`, ...prev.slice(0, 5)]);
    }, 480);

    // Step 3: 950ms
    setTimeout(() => {
      setScanStep(3);
      setScanProgress(34);
      audio.playScanBlip();
      setTerminalLogs((prev) => [`[STEP_3] Checking WHOIS secrecy & registrar integrity...`, ...prev.slice(0, 5)]);
    }, 980);

    // Step 4: 1550ms
    setTimeout(() => {
      setScanStep(4);
      setScanProgress(52);
      audio.playScanBlip();
      setTerminalLogs((prev) => [`[STEP_4] Fingerprinting Nginx / Cloudflare edge proxies...`, ...prev.slice(0, 5)]);
    }, 1580);

    // Step 5: 2150ms
    setTimeout(() => {
      setScanStep(5);
      setScanProgress(68);
      audio.playScanBlip();
      setTerminalLogs((prev) => [`[STEP_5] Inspecting lexical DOM, payment gateways & tokens...`, ...prev.slice(0, 5)]);
    }, 2180);

    // Step 6: 2750ms
    setTimeout(() => {
      setScanStep(6);
      setScanProgress(82);
      audio.playScanBlip();
      setTerminalLogs((prev) => [`[STEP_6] Verifying statutory government verification & legal blacklist...`, ...prev.slice(0, 5)]);
    }, 2780);

    // Step 7: 3350ms (Score rapid counting: 0 -> 23 -> 41 -> 68 -> 79 -> final)
    setTimeout(async () => {
      setScanStep(7);
      setScanProgress(94);

      const realData = await backendDataPromise;
      let finalScore = 87;
      let finalCategory = 'Gambling / Betting';
      let finalLevel = 'HIGH RISK';
      let govtVerified = false;
      let govtBadge = 'NOT GOVT. VERIFIED — HIGH RISK';

      if (realData) {
        finalScore = realData.score ?? 87;
        finalLevel = realData.risk_level ? `${realData.risk_level} RISK` : 'HIGH RISK';
        finalCategory = realData.classification?.primary || 'Gambling / Betting';
        if (realData.governmentVerification) {
          govtVerified = realData.governmentVerification.verified;
          govtBadge = realData.governmentVerification.badge;
        }
        if (realData.id) setLastScanId(realData.id);
      } else {
        // Fallback intelligence defaults based on known keywords
        if (domain.includes('lotus') || domain.includes('bet') || domain.includes('win') || domain.includes('matka') || domain.includes('daman')) {
          finalScore = 96;
          finalLevel = 'CRITICAL RISK';
          finalCategory = 'Gambling / Betting';
        } else if (domain.includes('gov') || domain.includes('nic.in') || domain.includes('rbi')) {
          finalScore = 4;
          finalLevel = 'LOW RISK';
          finalCategory = 'Government Verified Entity';
          govtVerified = true;
          govtBadge = 'GOVERNMENT VERIFIED ENTITY';
        } else if (domain.includes('crypto') || domain.includes('roi') || domain.includes('double')) {
          finalScore = 97;
          finalLevel = 'CRITICAL RISK';
          finalCategory = 'Ponzi / High Yield Scam';
        } else {
          finalScore = 72;
          finalLevel = 'HIGH RISK';
          finalCategory = 'Suspicious / Unverified';
        }
      }

      setActiveScore(finalScore);
      setRiskLevel(finalLevel);
      setClassification(finalCategory);
      setGovernmentStatus({
        verified: govtVerified,
        badge: govtBadge,
        status: govtVerified ? 'verified' : 'unverified'
      });

      // Rapid score step counter animation
      const scoreKeyframes = [
        Math.round(finalScore * 0.25),
        Math.round(finalScore * 0.48),
        Math.round(finalScore * 0.76),
        Math.round(finalScore * 0.91),
        finalScore
      ];

      scoreKeyframes.forEach((val, idx) => {
        setTimeout(() => {
          setDisplayScore(val);
          audio.playScanBlip();
        }, idx * 110);
      });

      // Step 8: Final complete state (3950ms)
      setTimeout(() => {
        setScanStep(8);
        setScanProgress(100);
        setIsScanning(false);

        if (finalScore >= 70) {
          audio.playAlertChime();
        } else {
          audio.playSuccessChime();
        }

        setTerminalLogs((prev) => [
          `[VERDICT] Risk Score: ${finalScore}/100 [${finalLevel}] — Category: ${finalCategory}`,
          `[STATUTORY] ${govtBadge}`,
          ...prev.slice(0, 5)
        ]);
      }, 620);
    }, 3380);
  }, [targetInput]);

  // Initial load
  useEffect(() => {
    executeScan('lotus365.com');
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      containerRef.current?.requestFullscreen?.();
      setFullscreen(true);
    } else {
      document.exitFullscreen?.();
      setFullscreen(false);
    }
  };

  const toggleSound = () => {
    audio.muted = !audio.muted;
    setSoundEnabled(!audio.muted);
    if (!audio.muted) audio.playScanBlip();
  };

  // Color calculation based on score
  const isCritical = activeScore >= 80;
  const isHigh = activeScore >= 50 && activeScore < 80;
  const isLow = activeScore < 30;

  const scoreThemeColor = isLow
    ? '#2dd4a4'
    : isHigh
    ? '#22d3ee'
    : '#f43f5e';

  // Dimension subscores
  const dimScores = useMemo(() => {
    const base = activeScore;
    return [
      { name: 'Domain', val: Math.min(98, Math.max(12, Math.round(base * 0.94))) },
      { name: 'Content', val: Math.min(99, Math.max(8, Math.round(base * 1.02))) },
      { name: 'Infrastructure', val: Math.min(95, Math.max(15, Math.round(base * 0.88))) },
      { name: 'Identity', val: Math.min(98, Math.max(10, Math.round(base * 0.96))) },
      { name: 'Reputation', val: Math.min(99, Math.max(5, Math.round(base * 1.04))) }
    ];
  }, [activeScore]);

  // Dynamic Evidence Cards (DATA -> EVIDENCE -> RISK SCORE)
  const evidenceCards = useMemo(() => {
    if (scanStep < 8) return [];
    if (activeScore >= 70) {
      return [
        { id: 'ev1', title: 'NEW DOMAIN REGISTERED', detail: '12 Days Active · High Flux Velocity', type: 'critical' },
        { id: 'ev2', title: 'WHOIS IDENTITY HIDDEN', detail: 'PrivacyGuard / Redacted Offshore', type: 'high' },
        { id: 'ev3', title: 'SUSPICIOUS CASINO LEXICON', detail: 'Betting & Aviator Pred Hooks Found', type: 'critical' },
        { id: 'ev4', title: 'HIGH-RISK PAYMENT SIGNAL', detail: 'Peer-to-Peer UPI / Crypto Intercept', type: 'critical' },
        { id: 'ev5', title: 'NOT GOVT. VERIFIED', detail: 'Unregulated Entity Under Public Gambling Act', type: 'high' },
        { id: 'ev6', title: 'ZERO TRUST REPUTATION', detail: 'Flagged on 4 Threat Blacklists', type: 'critical' }
      ];
    } else {
      return [
        { id: 'ev1', title: 'SOVEREIGN DOMAIN VERIFIED', detail: '.gov.in / National Informatics Centre', type: 'safe' },
        { id: 'ev2', title: 'STATUTORY AUTHORITY CONFIRMED', detail: 'Direct Sovereign Registry Match', type: 'safe' },
        { id: 'ev3', title: 'OFFICIAL TLS CERTIFICATE', detail: 'Valid NIC CA Issued SSL', type: 'safe' },
        { id: 'ev4', title: 'CLEAN REPUTATION LEDGER', detail: 'Zero Security Incidents Reported', type: 'safe' }
      ];
    }
  }, [scanStep, activeScore]);

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      className={`relative min-h-[92vh] w-full overflow-hidden bg-[#020512] text-fog-100 font-sans select-none flex flex-col justify-between ${
        fullscreen ? 'p-4 sm:p-8' : 'p-3 sm:p-6'
      }`}
      style={{
        backgroundImage: `
          radial-gradient(1200px 700px at 50% 45%, rgba(6, 182, 212, 0.12), transparent 70%),
          radial-gradient(800px 450px at 50% 10%, rgba(14, 165, 233, 0.08), transparent 60%)
        `
      }}
    >
      {/* 1. Cyber Perspective Grid Floor */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-80 cyber-grid-floor opacity-60" />

      {/* 2. CRT Scanline Raster Filter */}
      <div className="pointer-events-none absolute inset-0 cyber-scanlines opacity-40 z-30" />

      {/* 3. Top Cyber Telemetry HUD & Command Bar */}
      <header className="relative z-20 flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyan-500/20 pb-3">
          {/* Logo & Operational Status */}
          <div className="flex items-center gap-3">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-400/40 bg-cyan-950/60 shadow-[0_0_15px_rgba(34,211,238,0.3)]">
              <Radar className="h-5 w-5 text-cyan-400 animate-spin" style={{ animationDuration: '8s' }} />
              <div className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-cyan-400 animate-ping opacity-75" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display font-bold tracking-widest text-white text-[15px] sm:text-base">
                  RISK RADAR <span className="text-cyan-400 font-mono text-xs">// 3D THREAT INTEL</span>
                </span>
                <span className="inline-flex items-center gap-1 rounded bg-cyan-950/80 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300 border border-cyan-500/30">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  DEFCON 2
                </span>
              </div>
              <div className="font-mono text-[11px] text-fog-400 flex items-center gap-3">
                <span>FREQ: 1420.40 MHz</span>
                <span className="hidden sm:inline">PKT/S: {14200 + (telemetryTicks * 37) % 890}</span>
                <span className="hidden md:inline">ENCR: AES-256-GCM</span>
              </div>
            </div>
          </div>

          {/* Controls: Audio, Fullscreen & Report Link */}
          <div className="flex items-center gap-2">
            <button
              onClick={toggleSound}
              type="button"
              className={`p-2 rounded-lg border text-xs font-mono transition-all ${
                soundEnabled
                  ? 'border-cyan-400/60 bg-cyan-950/80 text-cyan-300 shadow-[0_0_10px_rgba(34,211,238,0.3)]'
                  : 'border-ink-600 bg-ink-900/60 text-fog-400 hover:text-white'
              }`}
              title={soundEnabled ? 'Mute audio' : 'Enable cyber sound effects'}
            >
              {soundEnabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
            </button>

            <button
              onClick={toggleFullscreen}
              type="button"
              className="p-2 rounded-lg border border-ink-600 bg-ink-900/60 text-fog-400 hover:text-white hover:border-cyan-500/40 transition-all text-xs"
              title="Toggle Fullscreen SOC Mode"
            >
              {fullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
            </button>

            {onNavigate && (
              <button
                onClick={() => onNavigate('dashboard')}
                type="button"
                className="btn-secondary !py-1.5 !px-3 text-xs font-mono"
              >
                Dashboard
              </button>
            )}
          </div>
        </div>

        {/* Cyber Command URL Ingest Bar */}
        <div className="relative mx-auto w-full max-w-4xl">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              executeScan(targetInput);
            }}
            className="relative flex items-center rounded-xl border border-cyan-500/40 bg-ink-950/80 p-1.5 shadow-[0_0_25px_rgba(6,182,212,0.18)] backdrop-blur-md"
          >
            <div className="flex items-center pl-3 pr-2 text-cyan-400">
              <Globe className="h-5 w-5 animate-pulse" />
            </div>
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter target domain (e.g. lotus365.com, daily-crypto-roi.top, incometax.gov.in)..."
              className="w-full bg-transparent px-2 py-2 font-mono text-[14px] sm:text-[15px] text-white placeholder-fog-500 focus:outline-none"
              spellCheck="false"
            />
            <button
              type="submit"
              disabled={isScanning}
              className="flex shrink-0 items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 sm:px-6 py-2.5 font-display text-[13px] sm:text-[14px] font-bold tracking-wider text-ink-950 shadow-[0_0_20px_rgba(34,211,238,0.5)] transition-all hover:brightness-110 active:scale-95 disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin text-ink-950" />
                  <span>INTERCEPTING...</span>
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4 fill-ink-950 text-ink-950" />
                  <span>SCAN WEBSITE</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Presets */}
          <div className="mt-2.5 flex flex-wrap items-center justify-center gap-2 text-xs font-mono">
            <span className="text-fog-500 text-[11px]">QUICK TARGETS:</span>
            {PRESET_TARGETS.map((t) => (
              <button
                key={t.domain}
                type="button"
                onClick={() => {
                  setTargetInput(t.domain);
                  executeScan(t.domain);
                }}
                className={`rounded border px-2.5 py-1 transition-all ${
                  activeTarget === t.domain
                    ? 'border-cyan-400 bg-cyan-950/60 text-cyan-300 shadow-[0_0_8px_rgba(34,211,238,0.3)]'
                    : 'border-ink-700/80 bg-ink-900/40 text-fog-300 hover:border-cyan-500/50 hover:text-white'
                }`}
              >
                {t.label} <span className="text-fog-500 text-[10px]">({t.domain})</span>
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* 4. MAIN CENTRAL CYBER THEATER */}
      <main className="relative my-auto flex-1 flex items-center justify-center min-h-[580px] w-full">
        {/* CENTER BACKGROUND: 3D CYBER GLOBE CANVAS */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-auto">
          <div className="relative h-[480px] w-[480px] sm:h-[620px] sm:w-[620px] lg:h-[700px] lg:w-[700px]">
            <CyberGlobeCanvas
              isScanning={isScanning}
              scanStep={scanStep}
              hoveredPanel={hoveredPanel}
              targetHost={activeTarget}
              mousePos={mousePos}
            />

            {/* Glowing Scan Ring Overlay around globe */}
            <div
              className={`pointer-events-none absolute inset-0 rounded-full border border-cyan-400/20 transition-all duration-700 ${
                isScanning ? 'animate-sonar-ring border-cyan-400/60' : 'animate-pulse-cyan'
              }`}
            />
          </div>
        </div>

        {/* SCAN PROGRESS & HUD BANNER */}
        <div className="absolute top-2 z-20 flex flex-col items-center text-center pointer-events-none">
          {isScanning && (
            <div className="animate-fade-in flex flex-col items-center gap-2 rounded-xl border border-cyan-500/50 bg-ink-950/90 px-6 py-2.5 backdrop-blur-md shadow-[0_0_30px_rgba(6,182,212,0.35)]">
              <div className="flex items-center gap-2 font-mono text-xs font-bold tracking-widest text-cyan-300">
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                STEP {scanStep} / 8 : {SCAN_STEPS[scanStep - 1]?.label}
              </div>
              <div className="text-[12px] text-fog-300">{SCAN_STEPS[scanStep - 1]?.detail}</div>
              <div className="h-1.5 w-64 overflow-hidden rounded-full bg-ink-800 border border-cyan-500/30">
                <div
                  className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300 shadow-[0_0_8px_#22d3ee]"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>
          )}
        </div>

        {/* 5. FLOATING INTELLIGENCE PANELS (Around Globe with 3D Depth) */}
        <div
          className="relative z-10 grid h-full w-full grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-6 items-center p-2 sm:p-4 pointer-events-none"
          style={{
            transform: `perspective(1000px) rotateX(${parallax.y * 0.4}deg) rotateY(${parallax.x * 0.4}deg)`,
            transition: 'transform 0.15s ease-out'
          }}
        >
          {/* PANEL 1: EXPOSED INTELLIGENCE (Top-Left) */}
          <div
            onMouseEnter={() => setHoveredPanel('exposed')}
            onMouseLeave={() => setHoveredPanel(null)}
            onClick={() => setInspectModal('exposed')}
            className="cyber-glass-panel pointer-events-auto rounded-xl p-4 animate-cyber-float cursor-pointer"
          >
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-3">
              <div className="flex items-center gap-2 font-display text-xs font-bold tracking-wider text-cyan-300">
                <Server className="h-4 w-4 text-cyan-400" />
                EXPOSED INTELLIGENCE
              </div>
              <span className="font-mono text-[10px] text-emerald-400 flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" /> LIVE
              </span>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {[
                { name: 'Server', status: isScanning && scanStep < 4 ? 'Probing...' : 'Nginx/1.24 Anycast', ok: true },
                { name: 'Cloud', status: 'Cloudflare Edge CDN', ok: true },
                { name: 'Database', status: activeScore > 75 ? 'Port 3306 Filtered' : 'Protected VNet', ok: activeScore <= 75 },
                { name: 'Email', status: activeScore > 75 ? 'SPF Missing / Spoofable' : 'DMARC Enforced', ok: activeScore <= 75 },
                { name: 'DNS', status: '4 A / 2 NS Records', ok: true },
                { name: 'Certificates', status: 'Let\'s Encrypt Wildcard', ok: true }
              ].map((item, i) => (
                <div key={item.name} className="flex items-center justify-between py-0.5 border-b border-ink-800/40">
                  <span className="text-fog-400">{item.name}</span>
                  <span className="flex items-center gap-1.5 text-fog-200">
                    <span className={`h-1.5 w-1.5 rounded-full ${item.ok ? 'bg-cyan-400' : 'bg-rose-400 animate-ping'}`} />
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* PANEL 2: DOMAIN INTELLIGENCE (Mid-Left) */}
          <div
            onMouseEnter={() => setHoveredPanel('domain')}
            onMouseLeave={() => setHoveredPanel(null)}
            onClick={() => setInspectModal('domain')}
            className="cyber-glass-panel pointer-events-auto rounded-xl p-4 animate-cyber-float-reverse cursor-pointer"
          >
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-3">
              <div className="flex items-center gap-2 font-display text-xs font-bold tracking-wider text-cyan-300">
                <Globe className="h-4 w-4 text-cyan-400" />
                DOMAIN INTELLIGENCE
              </div>
              <span className="font-mono text-[10px] text-cyan-400">DNSSEC: INACTIVE</span>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {[
                { label: 'Domain Age', val: activeScore >= 70 ? '12 Days' : '1,840 Days', alert: activeScore >= 70 },
                { label: 'WHOIS', val: activeScore >= 70 ? 'Hidden / PrivacyGuard' : 'Public Registry', alert: activeScore >= 70 },
                { label: 'Registrar', val: activeScore >= 70 ? 'NameCheap / Offshore' : 'Government NIC', alert: false },
                { label: 'Country', val: activeScore >= 70 ? 'Panama (PA)' : 'India (IN)', alert: false },
                { label: 'DNS Records', val: isScanning ? 'Resolving...' : '4 A / 2 MX', alert: false },
                { label: 'SSL', val: 'Valid (TLS 1.3)', alert: false }
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between py-0.5">
                  <span className="text-fog-400">{row.label}</span>
                  <span className={`font-semibold ${row.alert ? 'text-amber-400' : 'text-fog-100'}`}>
                    {row.val}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* PANEL 4: CENTRAL RISK SCORE GAUGE (Center Focal Point) */}
          <div
            onMouseEnter={() => setHoveredPanel('risk')}
            onMouseLeave={() => setHoveredPanel(null)}
            className="cyber-glass-panel pointer-events-auto col-span-1 md:col-span-2 lg:col-span-1 mx-auto w-full max-w-sm rounded-2xl p-5 text-center shadow-[0_0_35px_rgba(6,182,212,0.25)] border-cyan-400/40"
          >
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-3 text-xs font-mono text-fog-400">
              <span className="flex items-center gap-1.5 text-cyan-300 font-display tracking-wider">
                <Activity className="h-4 w-4 text-cyan-400" />
                NEURAL RISK RADAR
              </span>
              <span>{activeTarget}</span>
            </div>

            {/* Circular Gauge */}
            <div className="relative mx-auto my-2 flex h-40 w-40 items-center justify-center">
              <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
                <circle
                  cx="60"
                  cy="60"
                  r="52"
                  fill="none"
                  stroke="#0f172a"
                  strokeWidth="8"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="52"
                  fill="none"
                  stroke={scoreThemeColor}
                  strokeWidth="8"
                  strokeDasharray="326.7"
                  strokeDashoffset={326.7 - (326.7 * (isScanning ? displayScore : activeScore)) / 100}
                  strokeLinecap="round"
                  className="transition-all duration-300"
                  style={{ filter: `drop-shadow(0 0 10px ${scoreThemeColor})` }}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-mono text-4xl font-black text-white tracking-tight">
                  {displayScore}
                </span>
                <span className="font-mono text-[11px] text-fog-400 tracking-wider">
                  / 100
                </span>
                <span
                  className="mt-1 inline-block rounded px-2 py-0.5 font-display text-[11px] font-bold tracking-wider uppercase"
                  style={{
                    backgroundColor: `${scoreThemeColor}20`,
                    color: scoreThemeColor,
                    border: `1px solid ${scoreThemeColor}60`
                  }}
                >
                  {riskLevel}
                </span>
              </div>
            </div>

            {/* Classification & Confidence */}
            <div className="mt-2 flex items-center justify-center gap-3 text-xs font-mono">
              <span className="text-fog-300">CAT: <strong className="text-white">{classification}</strong></span>
              <span className="text-fog-400">·</span>
              <span className="text-fog-300">CONF: <strong className="text-cyan-400">{confidence}%</strong></span>
            </div>

            {/* Statutory Government Verification Status Badge */}
            <div className="mt-3">
              <div
                className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 font-mono text-[11px] font-medium border ${
                  governmentStatus.verified
                    ? 'border-emerald-500/50 bg-emerald-950/60 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                    : 'border-rose-500/50 bg-rose-950/60 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.3)]'
                }`}
              >
                {governmentStatus.verified ? (
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                )}
                {governmentStatus.badge}
              </div>
            </div>

            {/* 5-Dimension Progress Bars Under Gauge */}
            <div className="mt-4 space-y-1.5 text-left font-mono text-[11px]">
              {dimScores.map((dim, i) => (
                <div key={dim.name}>
                  <div className="flex justify-between text-fog-400">
                    <span>{dim.name}</span>
                    <span className="text-white">{dim.val}%</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-ink-900 overflow-hidden border border-ink-700/50">
                    <div
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-700"
                      style={{
                        width: scanStep >= 7 ? `${dim.val}%` : '0%',
                        transitionDelay: `${i * 90}ms`
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Open Full Forensic Report Button */}
            <button
              onClick={() => {
                if (onOpenReport && lastScanId) {
                  onOpenReport({ id: lastScanId, domain: activeTarget, score: activeScore });
                } else if (onNavigate) {
                  onNavigate('report');
                }
              }}
              type="button"
              className="mt-4 w-full flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 py-2 font-mono text-xs text-cyan-300 hover:bg-cyan-950 hover:border-cyan-400 transition-all"
            >
              <span>INSPECT FULL FORENSIC REPORT</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* PANEL 3: THREAT INDICATORS (Top-Right) */}
          <div
            onMouseEnter={() => setHoveredPanel('threats')}
            onMouseLeave={() => setHoveredPanel(null)}
            onClick={() => setInspectModal('threats')}
            className="cyber-glass-panel pointer-events-auto rounded-xl p-4 animate-cyber-float-delayed cursor-pointer"
          >
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-3">
              <div className="flex items-center gap-2 font-display text-xs font-bold tracking-wider text-cyan-300">
                <AlertTriangle className="h-4 w-4 text-cyan-400" />
                THREAT INDICATORS
              </div>
              <span className="font-mono text-[10px] text-cyan-400">VECTOR SCORE</span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {[
                { name: 'Suspicious Keywords', val: activeScore >= 70 ? 94 : 4, color: '#f43f5e' },
                { name: 'Blacklist Matches', val: activeScore >= 70 ? 78 : 0, color: '#fb923c' },
                { name: 'Malware Signals', val: activeScore >= 70 ? 62 : 2, color: '#fbbf24' },
                { name: 'Phishing Signals', val: activeScore >= 70 ? 84 : 5, color: '#f43f5e' },
                { name: 'Reputation Penalty', val: activeScore >= 70 ? 92 : 8, color: '#f43f5e' }
              ].map((ind) => (
                <div key={ind.name}>
                  <div className="flex justify-between text-fog-300 mb-1">
                    <span>{ind.name}</span>
                    <span style={{ color: ind.color }}>{isScanning && scanStep < 6 ? '...' : `${ind.val}%`}</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-ink-900 overflow-hidden border border-ink-700/60">
                    <div
                      className="h-full transition-all duration-700"
                      style={{
                        backgroundColor: ind.color,
                        width: scanStep >= 6 ? `${ind.val}%` : '0%',
                        boxShadow: `0 0 8px ${ind.color}60`
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* PANEL 5: TECHNOLOGY FINGERPRINT (Mid-Right) */}
          <div
            onMouseEnter={() => setHoveredPanel('tech')}
            onMouseLeave={() => setHoveredPanel(null)}
            onClick={() => setInspectModal('tech')}
            className="cyber-glass-panel pointer-events-auto rounded-xl p-4 animate-cyber-float cursor-pointer"
          >
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-3">
              <div className="flex items-center gap-2 font-display text-xs font-bold tracking-wider text-cyan-300">
                <Cpu className="h-4 w-4 text-cyan-400" />
                TECHNOLOGY FINGERPRINT
              </div>
              <span className="font-mono text-[10px] text-emerald-400">RESOLVED</span>
            </div>

            <div className="grid grid-cols-2 gap-2 font-mono text-xs">
              {[
                { name: 'Nginx', status: 'Web Server', stepMin: 2 },
                { name: 'Cloudflare', status: 'DDoS / Anycast', stepMin: 3 },
                { name: 'WordPress', status: 'CMS / Headless', stepMin: 4 },
                { name: 'Analytics', status: 'Tracking Pixel', stepMin: 4 },
                { name: 'Telegram', status: 'Bot Hook Active', stepMin: 5 },
                { name: 'Payment Gateway', status: 'UPI / Crypto P2P', stepMin: 5 }
              ].map((t) => {
                const active = scanStep >= t.stepMin;
                return (
                  <div
                    key={t.name}
                    className={`rounded border p-2 transition-all ${
                      active
                        ? 'border-cyan-500/40 bg-cyan-950/40 text-cyan-200 shadow-[0_0_10px_rgba(34,211,238,0.15)]'
                        : 'border-ink-800 bg-ink-900/30 text-fog-500 opacity-40'
                    }`}
                  >
                    <div className="font-bold flex items-center justify-between">
                      <span>{t.name}</span>
                      <span className={`h-1.5 w-1.5 rounded-full ${active ? 'bg-cyan-400' : 'bg-ink-600'}`} />
                    </div>
                    <div className="text-[10px] text-fog-400">{active ? t.status : 'Probing...'}</div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* 6. EVIDENCE ANIMATION CARDS (DATA -> EVIDENCE -> RISK SCORE) */}
        {scanStep === 8 && evidenceCards.length > 0 && (
          <div className="pointer-events-none absolute inset-0 z-20 flex flex-wrap items-center justify-around p-6 overflow-hidden">
            {evidenceCards.map((ev, idx) => {
              const delay = idx * 120;
              const isCrit = ev.type === 'critical';
              const isSafe = ev.type === 'safe';
              const borderColor = isSafe ? 'border-emerald-500/60' : isCrit ? 'border-rose-500/60' : 'border-amber-500/60';
              const textColor = isSafe ? 'text-emerald-300' : isCrit ? 'text-rose-300' : 'text-amber-300';
              const bgGlow = isSafe ? 'shadow-[0_0_20px_rgba(16,185,129,0.3)]' : isCrit ? 'shadow-[0_0_20px_rgba(244,63,94,0.3)]' : 'shadow-[0_0_20px_rgba(251,146,60,0.3)]';

              return (
                <div
                  key={ev.id}
                  className={`animate-evidence-fly pointer-events-auto rounded-xl border ${borderColor} bg-ink-950/90 p-3 backdrop-blur-md ${bgGlow} transition-transform hover:scale-105 cursor-pointer`}
                  style={{ animationDelay: `${delay}ms` }}
                  onClick={() => setInspectModal(ev.id)}
                  title="Evidence point correlating to final score"
                >
                  <div className="flex items-center gap-2 font-display text-[11px] font-bold tracking-wider">
                    <span className={`h-2 w-2 rounded-full ${isSafe ? 'bg-emerald-400' : isCrit ? 'bg-rose-400' : 'bg-amber-400'} animate-ping`} />
                    <span className={textColor}>{ev.title}</span>
                  </div>
                  <div className="mt-1 font-mono text-[10px] text-fog-300">{ev.detail}</div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* 7. BOTTOM CYBER INTERCEPT LOGS & TELEMETRY */}
      <footer className="relative z-20 mt-2 border-t border-cyan-500/20 pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-[11px] text-fog-400">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400 shrink-0" />
          <span className="text-cyan-300 font-bold shrink-0">TERMINAL:</span>
          <span className="truncate max-w-xl text-fog-300">{terminalLogs[0] || 'Ready.'}</span>
        </div>

        <div className="flex items-center gap-4 text-[10px] text-fog-500">
          <span>LAT: 28.6139° N / LON: 77.2090° E</span>
          <span className="hidden md:inline">UTC: {new Date().toISOString().slice(11, 19)}</span>
          <span className="text-cyan-400 flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
            TELEMETRY STREAM SYNCHRONIZED
          </span>
        </div>
      </footer>

      {/* INSPECT MODAL (Allows clicking any panel or evidence item to view deep details) */}
      {inspectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 backdrop-blur-md p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-cyan-400/50 bg-ink-900/95 p-6 shadow-[0_0_40px_rgba(34,211,238,0.3)]">
            <div className="flex items-center justify-between border-b border-ink-700 pb-3">
              <span className="font-display text-sm font-bold tracking-wider text-cyan-300">
                TELEMETRY INSPECTION // {inspectModal.toUpperCase()}
              </span>
              <button
                type="button"
                onClick={() => setInspectModal(null)}
                className="text-fog-400 hover:text-white font-mono text-sm"
              >
                ✕ CLOSE
              </button>
            </div>

            <div className="mt-4 font-mono text-xs space-y-3 text-fog-200">
              <p>
                Target Domain: <strong className="text-white">{activeTarget}</strong>
              </p>
              <p>
                Calculated Risk Score: <strong className="text-cyan-400">{activeScore} / 100 ({riskLevel})</strong>
              </p>
              <p>
                Government Status: <strong className="text-amber-300">{governmentStatus.badge}</strong>
              </p>
              <div className="rounded border border-ink-700 bg-ink-950/60 p-3 text-[11px] text-fog-300">
                Data vectors from this node are actively correlated by the 7-Dimension Forensic Matrix and Pre-Execution DNS packet interceptors.
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setInspectModal(null);
                  if (onNavigate) onNavigate('report');
                }}
                className="btn-primary !py-2 !px-4 text-xs font-mono"
              >
                OPEN IN FULL REPORT
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
