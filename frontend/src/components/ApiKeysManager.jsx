import React, { useState } from 'react';
import { KeyRound, Plus, Copy, Check, AlertTriangle, Puzzle } from 'lucide-react';
import { PageHeader, Panel, Modal, Meter, EmptyState } from './ui';
import { timeAgo } from '../lib/risk';
import { errorMessage, getActiveApiUrl } from '../services/api';

const API_BASE = getActiveApiUrl();

function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn-secondary btn-sm"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-risk-low" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

export default function ApiKeysManager({ apiKeys = [], health, onCreate }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(null);
  const [error, setError] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setCreated(await onCreate(name.trim()));
      setName('');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    setOpen(false);
    setCreated(null);
    setError(null);
  };

  const curl = `curl -X POST ${API_BASE}/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://example.com"}'`;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="API & settings"
        description="Plug Risk Radar into your pipelines, SIEM or browser. Keys are shown once when created — store them somewhere safe."
        actions={
          <button type="button" className="btn-primary" onClick={() => setOpen(true)}>
            <Plus className="h-4 w-4" /> Create API key
          </button>
        }
      />

      <Panel title="API keys" subtitle={`${apiKeys.length} active`} bodyClassName="p-0">
        {apiKeys.length === 0 ? (
          <EmptyState icon={KeyRound} title="No API keys yet">
            Create a key to call the scanning API from your own tools.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th className="hidden md:table-cell">This month</th>
                  <th className="hidden sm:table-cell">Last used</th>
                  <th className="hidden lg:table-cell">Created</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((k) => (
                  <tr key={k.id}>
                    <td className="font-medium text-fog-50">
                      {k.name}
                      <span className="ml-2 chip border-risk-low/40 bg-risk-low/10 text-emerald-200">{k.status}</span>
                    </td>
                    <td className="font-mono text-[13px] text-fog-200">{k.keyPrefix}_••••••••</td>
                    <td className="hidden min-w-[180px] md:table-cell">
                      <div className="flex items-baseline justify-between text-[12px] text-fog-400">
                        <span className="num text-fog-100">{(k.monthlyUsed || 0).toLocaleString()}</span>
                        <span>of {(k.monthlyLimit || 0).toLocaleString()}</span>
                      </div>
                      <Meter value={k.monthlyUsed || 0} max={k.monthlyLimit || 1} color="#A78BFA" className="mt-1" />
                    </td>
                    <td className="hidden text-fog-400 sm:table-cell">{k.lastUsed ? timeAgo(k.lastUsed) : 'Never'}</td>
                    <td className="hidden text-fog-400 lg:table-cell">{new Date(k.createdAt).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Panel title="Scan from the command line" subtitle="Same engine the dashboard uses" action={<CopyButton text={curl} />}>
          <pre className="overflow-x-auto rounded-xl border border-ink-600/70 bg-ink-950/80 p-4 font-mono text-[12.5px] leading-relaxed text-fog-100">{curl}</pre>
          <p className="mt-3 text-[13px] text-fog-400">
            Other endpoints: <code className="font-mono text-fog-200">/scan/pre-execution</code>, <code className="font-mono text-fog-200">/scan/bulk</code>,{' '}
            <code className="font-mono text-fog-200">/analyze-url</code> (browser extension), <code className="font-mono text-fog-200">/soc/stats</code>.
          </p>
        </Panel>

        <Panel title="Browser extension" icon={Puzzle}>
          <p className="text-[13px] leading-relaxed text-fog-300">
            The Chrome extension in the <code className="font-mono text-fog-100">extension/</code> folder scores the page you’re on with one click. Load it from{' '}
            <span className="text-fog-100">chrome://extensions → Load unpacked</span>.
          </p>
          <dl className="mt-4 space-y-2 text-[13px]">
            <div className="flex justify-between gap-4">
              <dt className="text-fog-400">Engine</dt>
              <dd className={health?.status === 'online' ? 'text-emerald-300' : 'text-rose-300'}>{health?.status === 'online' ? 'Online' : 'Offline'}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fog-400">Storage</dt>
              <dd className="text-fog-100">{health?.database === 'mongodb' ? 'MongoDB' : 'In memory'}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fog-400">API base</dt>
              <dd className="truncate font-mono text-fog-100">{API_BASE}</dd>
            </div>
          </dl>
        </Panel>
      </div>

      <Modal
        open={open}
        onClose={close}
        title={created ? 'Your new API key' : 'Create API key'}
        subtitle={created ? undefined : 'Name it after the system that will use it.'}
        footer={
          created ? (
            <button type="button" className="btn-primary" onClick={close}>
              I’ve saved it
            </button>
          ) : (
            <>
              <button type="button" className="btn-ghost" onClick={close}>
                Cancel
              </button>
              <button type="submit" form="key-form" className="btn-primary" disabled={busy || !name.trim()}>
                {busy ? 'Creating…' : 'Create key'}
              </button>
            </>
          )
        }
      >
        {created ? (
          <div className="space-y-4">
            <div className="flex gap-3 rounded-xl border border-risk-medium/40 bg-risk-medium/10 px-4 py-3 text-[13px] text-amber-100">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-risk-medium" />
              Copy this key now. For security it won’t be shown again.
            </div>
            <div className="flex items-center gap-3 rounded-xl border border-ink-600/70 bg-ink-950/80 p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-[12.5px] text-signal-100">{created.rawToken}</code>
              <CopyButton text={created.rawToken} />
            </div>
          </div>
        ) : (
          <form id="key-form" onSubmit={create}>
            <label htmlFor="key-name" className="label">
              Key name
            </label>
            <input id="key-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="CI/CD scanner" className="input" autoComplete="off" />
            {error && <p className="mt-2 text-[13px] text-rose-300">{error}</p>}
          </form>
        )}
      </Modal>
    </div>
  );
}
