import React, { useEffect, useState } from 'react';
import { Check, Loader2 } from 'lucide-react';

const STEPS = [
  'Resolving domain, WHOIS and SSL',
  'Querying threat-intelligence feeds',
  'Mapping shared hosting infrastructure',
  'Reading page content and payment cues',
  'Checking contact and business identity',
  'Correlating signals into a risk score'
];

export default function ScanProgress({ target }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 320);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="no-print fixed inset-x-0 bottom-6 z-[55] flex justify-center px-4" role="status" aria-live="polite">
      <div className="panel w-full max-w-md animate-toast-in overflow-hidden bg-ink-850">
        <div className="relative h-0.5 overflow-hidden bg-ink-700">
          <div className="absolute inset-y-0 w-1/2 animate-scan-line bg-gradient-to-r from-transparent via-signal-400 to-transparent" />
        </div>
        <div className="px-5 py-4">
          <div className="flex items-baseline justify-between gap-3">
            <span className="font-display text-[15px] font-semibold text-white">Scanning</span>
            <span className="truncate font-mono text-[12px] text-signal-300">{target}</span>
          </div>
          <ol className="mt-3 space-y-1.5">
            {STEPS.map((label, i) => (
              <li key={label} className={`flex items-center gap-2.5 text-[13px] ${i < step ? 'text-fog-300' : i === step ? 'text-white' : 'text-fog-500'}`}>
                {i < step ? (
                  <Check className="h-3.5 w-3.5 text-risk-low" />
                ) : i === step ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-signal-400" />
                ) : (
                  <span className="h-3.5 w-3.5 rounded-full border border-ink-500" />
                )}
                {label}
              </li>
            ))}
          </ol>
        </div>
      </div>
    </div>
  );
}
