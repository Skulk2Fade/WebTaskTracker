const db = require('../db');
const { handleError } = require('../utils');
const { requireAuth } = require('../middleware/auth');

module.exports = function(app) {
  app.get('/api/preferences', requireAuth, async (req, res) => {
    try {
      const user = await db.getUserById(req.session.userId);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({
        emailReminders: !!user.emailReminders,
        emailNotifications: !!user.emailNotifications,
        notifySms: !!user.notifySms,
        phoneNumber: user.phoneNumber || null,
        notificationTemplate: user.notificationTemplate || null,
        pushToken: user.pushToken || null,
        slackId: user.slackId || null,
        teamsId: user.teamsId || null,
        timezone: user.timezone || 'UTC'
      });
    } catch (err) {
      handleError(res, err, 'Failed to load preferences');
    }
  });

  app.put('/api/preferences', requireAuth, async (req, res) => {
    const {
      emailReminders,
      emailNotifications,
      notifySms,
      phoneNumber,
      notificationTemplate,
      pushToken,
      slackId,
      teamsId,
      timezone
    } = req.body;
    try {
      const user = await db.updateUserPreferences(req.session.userId, {
        emailReminders,
        emailNotifications,
        notifySms,
        phoneNumber,
        notificationTemplate,
        pushToken,
        slackId,
        teamsId,
        timezone
      });
      res.json({
        emailReminders: !!user.emailReminders,
        emailNotifications: !!user.emailNotifications,
        notifySms: !!user.notifySms,
        phoneNumber: user.phoneNumber || null,
        notificationTemplate: user.notificationTemplate || null,
        pushToken: user.pushToken || null,
        slackId: user.slackId || null,
        teamsId: user.teamsId || null,
        timezone: user.timezone || 'UTC'
      });
    } catch (err) {
      handleError(res, err, 'Failed to update preferences');
    }
  });
};
