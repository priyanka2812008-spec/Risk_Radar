import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';
import Sidebar from './components/Sidebar';
import TopHeader from './components/TopHeader';
import DashboardView from './components/DashboardView';
import RiskReportView from './components/RiskReportView';
import PreExecutionScanner from './components/PreExecutionScanner';
import ScanHistory from './components/ScanHistory';
import WatchlistManager from './components/WatchlistManager';
import IncidentQueue from './components/IncidentQueue';
import ApiKeysManager from './components/ApiKeysManager';
import ThreatAnalytics from './components/ThreatAnalytics';
import SevenDimensionsEngine from './components/SevenDimensionsEngine';
import ScanProgress from './components/ScanProgress';
import CyberThreatVisualizer from './components/CyberThreatVisualizer';
import MobileBottomNav from './components/MobileBottomNav';
import { api, errorMessage } from './services/api';

const TABS = ['dashboard', 'threat-globe', 'pre-execution', 'report', 'history', 'investigations', 'watchlist', 'intelligence', 'settings', '7d-engine'];

const parseHash = () => {
  const [, tab = 'dashboard', id] = (window.location.hash || '').split('/');
  return { tab: TABS.includes(tab) ? tab : 'dashboard', id: id ? decodeURIComponent(id) : null };
};

const hostOf = (value) =>
  value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0];

export default function App() {
  const [route, setRoute] = useState(parseHash);
  const [currentScan, setCurrentScan] = useState(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [preExecutionRequest, setPreExecutionRequest] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [watchlist, setWatchlist] = useState([]);
  const [queue, setQueue] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState({ status: 'checking' });
  const [scanning, setScanning] = useState(null); // target being scanned
  const [toast, setToast] = useState(null);
  const [navOpen, setNavOpen] = useState(false);
  const toastTimer = useRef(null);

  const showToast = useCallback((message, tone = 'success') => {
    clearTimeout(toastTimer.current);
    setToast({ message, tone, key: Date.now() });
    toastTimer.current = setTimeout(() => setToast(null), 4200);
  }, []);

  const navigate = useCallback((tab, id) => {
    const hash = id ? `#/${tab}/${encodeURIComponent(id)}` : `#/${tab}`;
    if (window.location.hash !== hash) window.location.hash = hash;
    else setRoute(parseHash());
    setNavOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  useEffect(() => {
    const onHash = () => {
      setRoute(parseHash());
      window.scrollTo({ top: 0 });
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const loadData = useCallback(async () => {
    const results = await Promise.allSettled([api.getScans(), api.getStats(), api.getWatchlist(), api.getQueue(), api.getApiKeys()]);
    const [scansRes, statsRes, watchRes, queueRes, keysRes] = results;
    if (scansRes.status === 'fulfilled') setRecentScans(scansRes.value.data || []);
    if (statsRes.status === 'fulfilled') setStats(statsRes.value.data || null);
    if (watchRes.status === 'fulfilled') setWatchlist(watchRes.value.data || []);
    if (queueRes.status === 'fulfilled') setQueue(queueRes.value.data || []);
    if (keysRes.status === 'fulfilled') setApiKeys(keysRes.value.data || []);
    return results.every((r) => r.status === 'fulfilled');
  }, []);

  const checkHealth = useCallback(async (isManualRetry = false) => {
    if (isManualRetry) setHealth((prev) => ({ ...prev, retrying: true }));
    try {
      const h = await api.health();
      setHealth({ ...h, status: 'online', retrying: false });
      return true;
    } catch {
      setHealth((prev) => ({ ...prev, status: 'offline', retrying: false }));
      return false;
    }
  }, []);

  const handleRetry = useCallback(async () => {
    const ok = await checkHealth(true);
    if (ok) {
      await loadData();
      showToast('Scanning engine connected successfully!', 'success');
    } else {
      showToast('Still unable to reach scanning engine. Render may take ~20-30s to wake up.', 'error');
    }
  }, [checkHealth, loadData, showToast]);

  // Boot: health, data, and deep links from the browser extension (?scan=domain)
  useEffect(() => {
    checkHealth().then((ok) => ok && loadData());
    const timer = setInterval(checkHealth, 30000);

    const params = new URLSearchParams(window.location.search);
    const target = (params.get('scan') || params.get('url') || '').trim();
    if (target) {
      window.history.replaceState(null, '', window.location.pathname + window.location.hash);
      setPreExecutionRequest({ target, nonce: Date.now() });
      navigate('pre-execution');
    }
    return () => clearInterval(timer);
  }, [checkHealth, loadData, navigate]);

  // Keep the open report in sync with #/report/<id>
  useEffect(() => {
    if (route.tab !== 'report' || !route.id || currentScan?.id === route.id) return;
    let cancelled = false;
    setLoadingScan(true);
    api
      .getScanById(route.id)
      .then((res) => !cancelled && setCurrentScan(res.data))
      .catch((err) => !cancelled && showToast(errorMessage(err), 'error'))
      .finally(() => !cancelled && setLoadingScan(false));
    return () => {
      cancelled = true;
    };
  }, [route, currentScan?.id, showToast]);

  const openScan = useCallback(
    (scanOrId) => {
      const id = typeof scanOrId === 'string' ? scanOrId : scanOrId?.id;
      if (!id) return;
      if (typeof scanOrId === 'object' && scanOrId.signals) setCurrentScan(scanOrId);
      navigate('report', id);
    },
    [navigate]
  );

  const handleScanTarget = useCallback(
    async (url) => {
      const target = (url || '').trim();
      if (!target || scanning) return;
      setScanning(target);
      try {
        const res = await api.scanUrl(target);
        if (res.success && res.data) {
          setCurrentScan(res.data);
          navigate('report', res.data.id);
          showToast(`Scanned ${res.data.domain} — risk score ${res.data.score}/100.`);
          loadData();
        } else {
          showToast(res?.error || 'Intelligence scanning could not complete.', 'error');
        }
      } catch (err) {
        showToast(errorMessage(err), 'error');
      } finally {
        setScanning(null);
      }
    },
    [scanning, navigate, showToast, loadData]
  );

  // Open the existing report for an exact domain match, otherwise run a new scan
  const handleInspect = useCallback(
    (query) => {
      if (!query?.trim()) return;
      const host = hostOf(query);
      const existing = recentScans.find((s) => hostOf(s.domain || '') === host);
      if (existing) {
        openScan(existing);
      } else {
        handleScanTarget(query);
      }
    },
    [recentScans, openScan, handleScanTarget]
  );

  const startPreExecution = useCallback(
    (target) => {
      setPreExecutionRequest(target ? { target, nonce: Date.now() } : null);
      navigate('pre-execution');
    },
    [navigate]
  );

  const handleAddToWatchlist = useCallback(
    async (data) => {
      try {
        const res = await api.addToWatchlist({
          url: data.url,
          domain: data.domain,
          frequency: data.frequency || 'Daily',
          alert_notes: data.alert_notes
        });
        showToast(res.alreadyTracked ? `${res.data.domain} is already on your watchlist.` : `Added ${res.data.domain} to the watchlist.`, res.alreadyTracked ? 'info' : 'success');
        loadData();
        return true;
      } catch (err) {
        showToast(errorMessage(err), 'error');
        return false;
      }
    },
    [showToast, loadData]
  );

  const handleRemoveFromWatchlist = useCallback(
    async (item) => {
      try {
        await api.removeFromWatchlist(item.id);
        showToast(`Removed ${item.domain} from the watchlist.`);
        loadData();
      } catch (err) {
        showToast(errorMessage(err), 'error');
      }
    },
    [showToast, loadData]
  );

  const handleRescanWatchlist = useCallback(
    async (item) => {
      try {
        const res = await api.rescanWatchlist(item.id);
        const delta = res.data?.score_change || 0;
        showToast(`Re-scanned ${item.domain}: ${res.data?.current_score}/100${delta ? ` (${delta > 0 ? '+' : ''}${delta})` : ', no change'}.`, delta > 0 ? 'info' : 'success');
        loadData();
      } catch (err) {
        showToast(errorMessage(err), 'error');
      }
    },
    [showToast, loadData]
  );

  const handleUpdateQueueItem = useCallback(
    async (id, updates) => {
      // Optimistic update so selects feel instant
      setQueue((q) => q.map((i) => (i.id === id ? { ...i, ...updates } : i)));
      try {
        await api.updateQueueItem(id, updates);
        if (updates.status) showToast(`Incident marked ${updates.status.toLowerCase()}.`);
        loadData();
      } catch (err) {
        showToast(errorMessage(err), 'error');
        loadData();
      }
    },
    [showToast, loadData]
  );

  const handleCreateApiKey = useCallback(
    async (name) => {
      const res = await api.createApiKey(name);
      loadData();
      return res.data;
    },
    [loadData]
  );

  const handleBulkScan = useCallback(
    async (urls) => {
      const res = await api.scanBulk(urls);
      loadData();
      return res.data || [];
    },
    [loadData]
  );

  const counts = useMemo(
    () => ({
      investigations: queue.filter((q) => !['Reviewed', 'Allowed'].includes(q.status)).length,
      watchlist: watchlist.length
    }),
    [queue, watchlist]
  );

  const offline = health.status === 'offline';

  return (
    <div className="flex min-h-screen text-fog-100">
      <Sidebar
        active={route.tab}
        onNavigate={navigate}
        counts={counts}
        health={health}
        open={navOpen}
        onClose={() => setNavOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <TopHeader
          recentScans={recentScans}
          queue={queue}
          watchlist={watchlist}
          scanning={Boolean(scanning)}
          onSearch={handleInspect}
          onSelectScan={openScan}
          onNavigate={navigate}
          onOpenNav={() => setNavOpen(true)}
        />

        {offline && (
          <div className="no-print mx-4 mt-4 flex items-start gap-3 rounded-xl border border-risk-critical/40 bg-risk-critical/10 px-4 py-3 text-[13px] text-rose-100 sm:mx-8">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-critical" />
            <div className="flex-1">
              <span className="font-semibold">The scanning engine is offline or spinning up.</span>{' '}
              {health.retrying
                ? 'Connecting to backend engine... (Render free tier may take ~20-30s to wake up)'
                : 'Unable to reach backend API. If deployed on Render free tier, instances spin down when idle and take ~20–30s to wake up on first request.'}
            </div>
            <button
              type="button"
              className="btn-secondary btn-sm flex items-center gap-1.5 shrink-0"
              disabled={health.retrying}
              onClick={handleRetry}
            >
              {health.retrying && <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-white/20 border-t-white" />}
              {health.retrying ? 'Connecting…' : 'Retry'}
            </button>
          </div>
        )}

        <main className={`mx-auto w-full flex-1 ${route.tab === 'threat-globe' || route.tab === 'dashboard' ? 'max-w-[1560px] p-2 sm:p-4' : 'max-w-[1320px] px-3.5 pb-24 pt-4 sm:px-6 sm:pb-28 sm:pt-6 lg:px-8 lg:pb-16 lg:pt-8'}`}>
          {route.tab === 'threat-globe' && (
            <CyberThreatVisualizer
              onOpenReport={openScan}
              onNavigate={navigate}
            />
          )}

          {route.tab === 'dashboard' && (
            <DashboardView
              stats={stats}
              recentScans={recentScans}
              queue={queue}
              scanning={Boolean(scanning)}
              onScan={handleScanTarget}
              onPreExecution={startPreExecution}
              onOpenScan={openScan}
              onNavigate={navigate}
            />
          )}

          {route.tab === 'pre-execution' && (
            <PreExecutionScanner
              request={preExecutionRequest}
              onAddToWatchlist={handleAddToWatchlist}
              onOpenReport={openScan}
              onScanned={loadData}
            />
          )}

          {route.tab === 'report' && (
            <RiskReportView
              scan={route.id && currentScan?.id !== route.id ? null : currentScan}
              loading={loadingScan}
              onAddToWatchlist={handleAddToWatchlist}
              onRescan={handleScanTarget}
              onNavigate={navigate}
            />
          )}

          {route.tab === 'history' && (
            <ScanHistory scans={recentScans} onOpenScan={openScan} onScan={handleScanTarget} onBulkScan={handleBulkScan} scanning={Boolean(scanning)} />
          )}

          {route.tab === 'investigations' && (
            <IncidentQueue queue={queue} onUpdate={handleUpdateQueueItem} onInspect={handleInspect} />
          )}

          {route.tab === 'watchlist' && (
            <WatchlistManager
              watchlist={watchlist}
              onAdd={handleAddToWatchlist}
              onRemove={handleRemoveFromWatchlist}
              onRescan={handleRescanWatchlist}
              onInspect={handleInspect}
            />
          )}

          {route.tab === 'intelligence' && <ThreatAnalytics stats={stats} onOpenScan={openScan} />}

          {route.tab === '7d-engine' && <SevenDimensionsEngine onNavigate={navigate} onOpenReport={openScan} />}

          {route.tab === 'settings' && <ApiKeysManager apiKeys={apiKeys} health={health} onCreate={handleCreateApiKey} />}
        </main>
      </div>

      <MobileBottomNav
        active={route.tab}
        onNavigate={navigate}
        counts={counts}
        onOpenSidebar={() => setNavOpen(true)}
      />

      {scanning && <ScanProgress target={scanning} />}

      {toast && (
        <div key={toast.key} role="status" className="no-print fixed bottom-20 sm:bottom-5 right-3 sm:right-5 left-3 sm:left-auto z-[60] flex max-w-sm animate-toast-in items-start gap-3 rounded-xl border border-ink-500/70 bg-ink-800/95 px-4 py-3 text-[13px] text-fog-50 shadow-panel backdrop-blur">
          {toast.tone === 'error' ? (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-critical" />
          ) : toast.tone === 'info' ? (
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-signal-400" />
          ) : (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-risk-low" />
          )}
          <span className="flex-1 leading-snug">{toast.message}</span>
          <button type="button" onClick={() => setToast(null)} className="-mr-1 text-fog-400 hover:text-white" aria-label="Dismiss">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
