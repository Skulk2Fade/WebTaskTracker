const db = require('../db');
const { handleError } = require('../utils');
const { requireAuth } = require('../middleware/auth');

module.exports = function (app) {
  app.get('/api/reports', requireAuth, async (req, res) => {
    try {
      const data = await db.getUserReports(req.session.userId);
      res.json(data);
    } catch (err) {
      handleError(res, err, 'Failed to load reports');
    }
  });
};
