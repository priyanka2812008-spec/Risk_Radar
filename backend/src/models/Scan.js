import mongoose from 'mongoose';

const ScanSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_id: { type: String, default: 'usr_soc_analyst_01' },
  organization_id: { type: String, default: 'org_acme_sec_default' },
  url: { type: String, required: true },
  domain: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  score: { type: Number, required: true, min: 0, max: 100 },
  risk_level: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
  primaryPattern: { type: String, default: 'No Major Pattern' },
  
  riskDNA: {
    domain: { type: Number, default: 10 },
    technical: { type: Number, default: 10 },
    content: { type: Number, default: 10 },
    businessModel: { type: Number, default: 10 },
    reputation: { type: Number, default: 10 },
    behavior: { type: Number, default: 10 },
    changeOverTime: { type: Number, default: 10 }
  },

  topReasons: [{
    reason: String,
    severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    impact: String
  }],

  detectedPatterns: [{
    id: String,
    pattern: String,
    category: String,
    confidence: Number,
    supportingSignals: [String],
    explanation: String,
    severity: String
  }],

  withdrawalRisk: {
    detected: { type: Boolean, default: false },
    riskLevel: { type: String, default: 'NONE' },
    summary: String,
    indicators: [String],
    conditions: [String]
  },

  verdict: { type: String },
  verdictExplanation: { type: String },
  classification: { type: mongoose.Schema.Types.Mixed },
  contactIdentity: { type: mongoose.Schema.Types.Mixed },
  riskPillars: { type: mongoose.Schema.Types.Mixed },
  passport: { type: mongoose.Schema.Types.Mixed },

  trustGap: {
    claim: String,
    observed: [String],
    gapLevel: { type: String, enum: ['NEGLIGIBLE', 'LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'NEGLIGIBLE' },
    verdict: String
  },

  recommendedAction: {
    action: { 
      type: String, 
      enum: ['ALLOW', 'ALLOW WITH CAUTION', 'MONITOR', 'MANUAL REVIEW', 'INVESTIGATE', 'BLOCK', 'INVESTIGATE / BLOCK', 'AVOID', 'REVIEW'],
      default: 'MONITOR'
    },
    rationale: String,
    immediateSteps: [String]
  },

  timeline: [{
    date: String,
    score: Number,
    risk_level: String,
    majorChanges: String
  }],

  signalsCount: {
    strong: { type: Number, default: 0 },
    contextual: { type: Number, default: 0 },
    benign: { type: Number, default: 0 }
  },

  metadata: {
    serverIp: String,
    serverCountry: String,
    sslIssuer: String,
    dnsTtl: Number,
    domainAgeDays: Number,
    responseLatencyMs: Number
  }
}, {
  // Keep pre-execution intelligence, evidence signals and engine scores that are not
  // declared above — the report view depends on them.
  strict: false,
  minimize: false
});

export const Scan = mongoose.model('Scan', ScanSchema);
