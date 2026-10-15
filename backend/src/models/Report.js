import mongoose from 'mongoose';

const ReportSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  scan_id: { type: String, required: true, index: true },
  title: { type: String, required: true },
  reportType: { 
    type: String, 
    enum: ['Risk Assessment', 'Bulk Scan Report', 'Monitoring Report', 'Organization Risk Summary', 'Business Risk Passport'],
    default: 'Risk Assessment'
  },
  summary: { type: String, required: true },
  recommendations: [String],
  riskScore: Number,
  riskLevel: String,
  targetUrl: String,
  analysisVersion: { type: String, default: 'RR-SEC-v4.2.1' },
  generated_at: { type: Date, default: Date.now },
  passportDetails: {
    website: String,
    overallRisk: Number,
    riskLevel: String,
    riskDNA: mongoose.Schema.Types.Mixed,
    topRiskPatterns: [mongoose.Schema.Types.Mixed],
    evidenceSummary: [String],
    recommendedAction: String,
    complianceStatus: String
  }
});

export const Report = mongoose.model('Report', ReportSchema);
