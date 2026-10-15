import mongoose from 'mongoose';

const AuditEventSchema = new mongoose.Schema({
  id: { type: String, required: true },
  actor: { type: String, required: true },
  action: { type: String, required: true },
  entity: { type: String, required: true },
  entityId: String,
  timestamp: { type: Date, default: Date.now },
  ipAddress: { type: String, default: '127.0.0.1' },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
});

export const AuditEvent = mongoose.model('AuditEvent', AuditEventSchema);
