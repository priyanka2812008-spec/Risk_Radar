import mongoose from 'mongoose';

const WatchlistSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_id: { type: String, default: 'usr_soc_analyst_01' },
  organization_id: { type: String, default: 'org_acme_sec_default' },
  url: { type: String, required: true },
  domain: { type: String, required: true },
  current_score: { type: Number, required: true },
  previous_score: { type: Number, default: null },
  risk_level: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
  score_change: { type: Number, default: 0 },
  monitoring_state: { type: String, enum: ['Active Monitoring', 'Paused', 'Alerting'], default: 'Active Monitoring' },
  frequency: { type: String, enum: ['Hourly', 'Daily', 'Weekly'], default: 'Daily' },
  last_scan: { type: Date, default: Date.now },
  alert_notes: String,
  history: [{
    date: { type: Date, default: Date.now },
    score: Number,
    note: String
  }],
  createdAt: { type: Date, default: Date.now }
});

export const Watchlist = mongoose.model('Watchlist', WatchlistSchema);
