const db = require('../db');
const { handleError } = require('../utils');
const { requireAdmin } = require('../middleware/auth');

module.exports = function(app) {
  app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
      const users = await db.listUsers();
      res.json(users);
    } catch (err) {
      handleError(res, err, 'Failed to load users');
    }
  });

  app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const ok = await db.deleteUser(id);
      if (!ok) return res.status(404).json({ error: 'User not found' });
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err, 'Failed to delete user');
    }
  });

  app.get('/api/admin/logs', requireAdmin, async (req, res) => {
    const limit = parseInt(req.query.limit, 10) || 100;
    try {
      const logs = await db.listActivity(limit);
      res.json(logs);
    } catch (err) {
      handleError(res, err, 'Failed to load logs');
    }
  });

  app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
      const stats = await db.getStats();
      res.json(stats);
    } catch (err) {
      handleError(res, err, 'Failed to load stats');
    }
  });

  app.get('/api/admin/reports', requireAdmin, async (req, res) => {
    try {
      const reports = await db.getReports();
      res.json(reports);
    } catch (err) {
      handleError(res, err, 'Failed to load reports');
    }
  });
};
