const db = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { handleError } = require('../utils');

module.exports = function(app) {
  app.get('/api/statuses', requireAuth, async (req, res) => {
    try {
      const statuses = await db.listStatuses();
      res.json(statuses);
    } catch (err) {
      handleError(res, err, 'Failed to load statuses');
    }
  });

  app.post('/api/statuses', requireAuth, requireAdmin, async (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'name required' });
    try {
      if (await db.statusExists(name)) {
        return res.status(400).json({ error: 'Status exists' });
      }
      const status = await db.createStatus(name);
      res.status(201).json(status);
    } catch (err) {
      handleError(res, err, 'Failed to create status');
    }
  });

  app.put('/api/statuses/:id', requireAuth, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'name required' });
    try {
      const status = await db.updateStatus(id, name);
      if (!status) return res.status(404).json({ error: 'Status not found' });
      res.json(status);
    } catch (err) {
      handleError(res, err, 'Failed to update status');
    }
  });

  app.delete('/api/statuses/:id', requireAuth, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const ok = await db.deleteStatus(id);
      if (!ok) return res.status(404).json({ error: 'Status not found' });
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err, 'Failed to delete status');
    }
  });
};
