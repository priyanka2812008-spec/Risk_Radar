import mongoose from 'mongoose';

const RiskSignalSchema = new mongoose.Schema({
  id: { type: String, required: true },
  scan_id: { type: String, required: true, index: true },
  category: { 
    type: String, 
    enum: ['Domain', 'Technical', 'Content', 'Business Model', 'Reputation', 'Behavior', 'Regulatory', 'Contact & Identity', 'Infrastructure', 'Threat Intelligence', 'Website Classification'],
    required: true 
  },
  indicator: { type: String, required: true },
  evidence: { type: String, required: true },
  sourceType: { type: String, default: 'Model-derived' },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
  confidence: { type: Number, min: 0, max: 100, required: true },
  scoreImpact: { type: Number, required: true },
  signalType: { 
    type: String, 
    enum: ['STRONG_INDICATOR', 'CONTEXTUAL_SIGNAL', 'BENIGN_SIGNAL'],
    default: 'STRONG_INDICATOR'
  },
  detectedAt: { type: Date, default: Date.now }
});

export const RiskSignal = mongoose.model('RiskSignal', RiskSignalSchema);
