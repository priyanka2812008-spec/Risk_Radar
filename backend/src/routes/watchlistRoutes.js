import express from 'express';
import { getWatchlist, addToWatchlist, removeFromWatchlist, saveScanAssessment, updateWatchlistAfterScan } from '../store/riskStore.js';
import { runFullAssessment, validateTarget } from '../services/assessment.js';

const router = express.Router();

/**
 * GET /api/watchlist
 * Retrieve continuous monitored target inventory
 */
router.get('/watchlist', async (req, res) => {
  try {
    const list = await getWatchlist();
    res.json({ success: true, count: list.length, data: list });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/watchlist
 * Add asset to continuous monitoring
 */
router.post('/watchlist', async (req, res) => {
  try {
    const { url, frequency, alert_notes } = req.body;
    const invalid = validateTarget(url);
    if (invalid) return res.status(400).json({ error: invalid });

    // Baseline scan so the watchlist starts from a real score
    const assessment = await runFullAssessment(url);
    await saveScanAssessment(assessment);

    const item = await addToWatchlist({
      url: assessment.url,
      domain: assessment.domain,
      current_score: assessment.score,
      risk_level: assessment.risk_level,
      frequency: frequency || 'Daily',
      alert_notes: alert_notes || `${assessment.primaryPattern} tracking`,
      history: (assessment.timeline || []).map(t => ({ date: new Date(t.date), score: t.score, note: t.majorChanges }))
    });

    res.status(item.alreadyTracked ? 200 : 201).json({ success: true, data: item, alreadyTracked: Boolean(item.alreadyTracked) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/watchlist/:id
 * Remove asset from continuous monitoring
 */
router.delete('/watchlist/:id', async (req, res) => {
  try {
    await removeFromWatchlist(req.params.id);
    res.json({ success: true, message: 'Asset removed from active monitoring.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/watchlist/:id/rescan
 * Re-scan monitored asset
 */
router.post('/watchlist/:id/rescan', async (req, res) => {
  try {
    const list = await getWatchlist();
    const item = list.find(w => w.id === req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Watchlist target not found' });
    }

    const assessment = await runFullAssessment(item.url);
    await saveScanAssessment(assessment);
    const updated = await updateWatchlistAfterScan(item.id, assessment);

    res.json({ success: true, data: updated, assessment });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
