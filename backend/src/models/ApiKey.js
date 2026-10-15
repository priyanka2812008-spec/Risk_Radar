import mongoose from 'mongoose';

const ApiKeySchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  organization_id: { type: String, default: 'org_acme_sec_default' },
  name: { type: String, required: true },
  keyPrefix: { type: String, required: true }, // e.g. "rr_live_9a7c..."
  keyHash: { type: String, required: true },
  rateLimitPerMin: { type: Number, default: 60 },
  monthlyLimit: { type: Number, default: 100000 },
  monthlyUsed: { type: Number, default: 1240 },
  status: { type: String, enum: ['Active', 'Revoked', 'Expired'], default: 'Active' },
  lastUsed: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

export const ApiKey = mongoose.model('ApiKey', ApiKeySchema);
