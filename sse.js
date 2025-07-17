const logger = require('./logger');
const db = require('./db');
const config = require('./config');
const {
  addSseClient,
  sendSse,
  getSseClientIds,
} = require('./utils');

let dueSoonOffset = 0;

async function checkDueSoon() {
  const ids = getSseClientIds();
  if (ids.length === 0) return;
  const batchSize = Math.min(config.DUE_SOON_BATCH_SIZE, ids.length);
  const batch = [];
  for (let i = 0; i < batchSize; i++) {
    batch.push(ids[(dueSoonOffset + i) % ids.length]);
  }
  dueSoonOffset = (dueSoonOffset + batchSize) % ids.length;

  for (const id of batch) {
    const uid = parseInt(id, 10);
    try {
      const user = await db.getUserById(uid);
      const tz = user && user.timezone ? user.timezone : 'UTC';
      const tasks = await db.getDueSoonTasks(uid, tz);
      for (const t of tasks) {
        sendSse(uid, 'task_due', {
          taskId: t.id,
          text: t.text,
          dueDate: t.dueDate,
          dueTime: t.dueTime,
        });
      }
    } catch (err) {
      logger.error(err);
    }
  }
}

function setupSse(app, requireAuth) {
  app.get('/api/events', requireAuth, (req, res) => {
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.flushHeaders();
    addSseClient(req.session.userId, res);
  });
  setInterval(checkDueSoon, config.DUE_SOON_CHECK_INTERVAL);
}

module.exports = { setupSse };
