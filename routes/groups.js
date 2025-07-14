const db = require('../db');
const { handleError } = require('../utils');
const { requireAuth, requireGroupAdmin } = require('../middleware/auth');

module.exports = function(app) {
  app.post('/api/groups', requireAuth, requireGroupAdmin, async (req, res) => {
    const name = req.body.name;
    if (!name) return res.status(400).json({ error: 'name required' });
    try {
      const group = await db.createGroup(name);
      await db.addUserToGroup(group.id, req.session.userId);
      res.status(201).json(group);
    } catch (err) {
      handleError(res, err, 'Failed to create group');
    }
  });

  app.post('/api/groups/:id/join', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      await db.addUserToGroup(id, req.session.userId);
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err, 'Failed to join group');
    }
  });

  app.get('/api/groups', requireAuth, async (req, res) => {
    try {
      const groups = await db.listUserGroups(req.session.userId);
      res.json(groups);
    } catch (err) {
      handleError(res, err, 'Failed to load groups');
    }
  });
};
