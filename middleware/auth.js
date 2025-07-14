const db = require('../db');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

async function requireWriter(req, res, next) {
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user || user.role === 'observer') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

async function requireGroupAdmin(req, res, next) {
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user || (user.role !== 'group_admin' && user.role !== 'admin')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { requireAuth, requireWriter, requireGroupAdmin, requireAdmin };
