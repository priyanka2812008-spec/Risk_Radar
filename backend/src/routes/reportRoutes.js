import express from 'express';
import { getReports, getReportById } from '../store/riskStore.js';

const router = express.Router();

/**
 * GET /api/reports
 * Retrieve all generated Digital Risk Passports & intelligence reports
 */
router.get('/reports', async (req, res) => {
  try {
    const list = await getReports();
    res.json({ success: true, count: list.length, data: list });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/reports/:id
 * Retrieve specific report by ID or scan_id
 */
router.get('/reports/:id', async (req, res) => {
  try {
    const report = await getReportById(req.params.id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json({ success: true, data: report });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
