import express from 'express';
import { 
  getGlobalStats, 
  getInvestigationQueue, 
  updateQueueItem, 
  getApiKeys, 
  createApiKey 
} from '../store/riskStore.js';

const router = express.Router();

/**
 * GET /api/soc/stats
 * Real-time threat matrix overview & KPI counters
 */
router.get('/soc/stats', async (req, res) => {
  try {
    const stats = await getGlobalStats();
    res.json({ success: true, data: stats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/soc/queue
 * SOC triage & incident review queue
 */
router.get('/soc/queue', (req, res) => {
  try {
    const queue = getInvestigationQueue();
    res.json({ success: true, count: queue.length, data: queue });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PATCH /api/soc/queue/:id
 * Update incident status or analyst assignment
 */
router.patch('/soc/queue/:id', (req, res) => {
  try {
    const { status, assignedTo } = req.body;
    const item = updateQueueItem(req.params.id, { status, assignedTo });
    if (!item) {
      return res.status(404).json({ error: 'Incident queue item not found.' });
    }
    res.json({ success: true, data: item });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/soc/keys
 * API credentials management
 */
router.get('/soc/keys', async (req, res) => {
  try {
    const keys = await getApiKeys();
    res.json({ success: true, count: keys.length, data: keys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/soc/keys
 * Issue new SOC enterprise integration key
 */
router.post('/soc/keys', async (req, res) => {
  try {
    const { name } = req.body;
    const key = await createApiKey(name);
    res.status(201).json({ success: true, data: key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
