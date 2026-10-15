import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  organization: { type: String, default: 'Acme Cybersecurity Labs' },
  organizationId: { type: String, default: 'org_acme_sec_default' },
  role: { type: String, enum: ['Admin', 'Analyst', 'Viewer'], default: 'Analyst' },
  status: { type: String, default: 'Active' },
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

export const User = mongoose.model('User', UserSchema);
