import mongoose from 'mongoose';

const OrganizationSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  plan: { type: String, default: 'Enterprise SOC Tier-1' },
  monitoredAssets: { type: Number, default: 42 },
  apiUsageLimit: { type: Number, default: 100000 },
  apiUsageToday: { type: Number, default: 1842 },
  investigationQueue: [{
    id: String,
    url: String,
    risk: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    score: Number,
    assignedTo: String,
    status: { type: String, enum: ['New', 'Investigating', 'Reviewed', 'Blocked', 'Allowed'], default: 'New' },
    lastUpdated: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

export const Organization = mongoose.model('Organization', OrganizationSchema);
