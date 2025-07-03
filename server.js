const express = require('express');
const path = require('path');
const db = require('./db');
const session = require('express-session');
const SQLiteStore = require('./sqliteStore');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const csurf = require('csurf');
const totp = require('./totp');
const email = require('./email');
const app = express();

// Use a higher bcrypt work factor for stronger password hashing.
// Configurable via the BCRYPT_ROUNDS environment variable.
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

app.use(express.json());
app.use(express.text({ type: ['text/csv', 'application/csv'] }));

function isValidFutureDate(str) {
  if (str === undefined || str === null || str === '') return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
  const date = new Date(str + 'T00:00:00Z');
  if (isNaN(date.getTime())) return false;
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  return date >= today;
}

function isStrongPassword(pw) {
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw)
  );
}
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  console.error('SESSION_SECRET environment variable is required');
  process.exit(1);
}
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      dbFile: process.env.DB_FILE || path.join(__dirname, 'tasks.db')
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    }
  })
);
app.use(express.static(path.join(__dirname, 'public')));
app.use(csurf());

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
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

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include upper and lower case letters and a number'
    });
  }
  try {
    const userCount = await db.countUsers();
    if (userCount > 0) {
      if (!req.session.userId) {
        return res.status(403).json({ error: 'Only admins can create users' });
      }
      const current = await db.getUserById(req.session.userId);
      if (!current || current.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can create users' });
      }
    }

    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const role = userCount === 0 ? 'admin' : 'member';
    const user = await db.createUser({ username, password: hashed, role });
    if (userCount === 0) {
      req.session.userId = user.id;
    }
    res.json({ id: user.id, username: user.username, role: user.role });
  } catch (err) {
    console.error(err);
    if (err.code === 'SQLITE_CONSTRAINT') {
      res.status(400).json({ error: 'Username taken' });
    } else {
      res.status(500).json({ error: 'Failed to register' });
    }
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, token } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  try {
    const user = await db.getUserByUsername(username);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    if (user.twofaSecret) {
      if (!totp.verifyToken(token, user.twofaSecret)) {
        return res.status(400).json({ error: 'Invalid 2FA token' });
      }
    }
    req.session.userId = user.id;
    res.json({ id: user.id, username: user.username, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.post('/api/enable-2fa', requireAuth, async (req, res) => {
  try {
    const secret = totp.generateSecret();
    await db.setUserTwoFactorSecret(req.session.userId, secret);
    res.json({ secret });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to enable 2FA' });
  }
});

app.post('/api/disable-2fa', requireAuth, async (req, res) => {
  try {
    await db.setUserTwoFactorSecret(req.session.userId, null);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

app.post('/api/request-password-reset', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  try {
    const user = await db.getUserByUsername(username);
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await db.createPasswordReset({ userId: user.id, token, expiresAt });
      // In a real app, the token would be emailed to the user
      res.json({ ok: true, token });
    } else {
      // Respond with ok even if user doesn't exist to avoid enumeration
      res.json({ ok: true });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create reset token' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and password required' });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error:
        'Password must be at least 8 characters and include upper and lower case letters and a number'
    });
  }
  try {
    const reset = await db.getPasswordReset(token);
    if (!reset || reset.used || new Date(reset.expiresAt) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await db.updateUserPassword(reset.userId, hashed);
    await db.markPasswordResetUsed(reset.id);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = await db.getUserById(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({ user: { id: user.id, username: user.username, role: user.role } });
});


app.get('/api/tasks', requireAuth, async (req, res) => {
  const { priority, done, sort, category, search } = req.query;
  try {
    const tasks = await db.listTasks({
      priority,
      done: done === 'true' ? true : done === 'false' ? false : undefined,
      sort,
      userId: req.session.userId,
      category,
      search
    });
    res.json(tasks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load tasks' });
  }
});

function escapeCsv(val) {
  if (val === undefined || val === null) return '';
  const str = String(val);
  if (/[,"\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function toCsv(tasks) {
  const header = [
    'text',
    'dueDate',
    'priority',
    'done',
    'category',
    'assignedTo',
    'repeatInterval'
  ].join(',');
  const rows = tasks.map(t =>
    [
      escapeCsv(t.text),
      escapeCsv(t.dueDate),
      escapeCsv(t.priority),
      escapeCsv(t.done ? 1 : 0),
      escapeCsv(t.category),
      escapeCsv(t.assignedTo),
      escapeCsv(t.repeatInterval)
    ].join(',')
  );
  return [header, ...rows].join('\n');
}

function parseCsvLine(line) {
  const vals = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQ = false;
        }
      } else {
        cur += ch;
      }
    } else {
      if (ch === '"') {
        inQ = true;
      } else if (ch === ',') {
        vals.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
  }
  vals.push(cur);
  return vals;
}

function fromCsv(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length === 0) return [];
  const headers = parseCsvLine(lines[0]);
  const tasks = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i]) continue;
    const vals = parseCsvLine(lines[i]);
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = vals[idx];
    });
    tasks.push(obj);
  }
  return tasks;
}

app.get('/api/tasks/export', requireAuth, async (req, res) => {
  const format = req.query.format === 'csv' ? 'csv' : 'json';
  try {
    const tasks = await db.listTasks({ userId: req.session.userId });
    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="tasks.csv"');
      res.send(toCsv(tasks));
    } else {
      res.setHeader('Content-Disposition', 'attachment; filename="tasks.json"');
      res.json(tasks);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to export tasks' });
  }
});

app.post('/api/tasks/import', requireAuth, async (req, res) => {
  const format = req.headers['content-type'] && req.headers['content-type'].includes('csv') ? 'csv' : 'json';
  try {
    let tasks = [];
    if (format === 'csv') {
      tasks = fromCsv(req.body || '');
    } else if (Array.isArray(req.body)) {
      tasks = req.body;
    } else if (req.body && Array.isArray(req.body.tasks)) {
      tasks = req.body.tasks;
    }
    const created = [];
    for (const t of tasks) {
      if (!t.text) continue;
      const task = await db.createTask({
        text: t.text,
        dueDate: t.dueDate || null,
        priority: ['high', 'medium', 'low'].includes(t.priority) ? t.priority : 'medium',
        done: t.done === true || t.done === '1' || t.done === 'true',
        userId: req.session.userId,
        category: t.category || null,
        assignedTo: t.assignedTo || null,
        repeatInterval: t.repeatInterval || null
      });
      created.push(task);
    }
    res.status(201).json(created);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to import tasks' });
  }
});

app.get('/api/reminders', requireAuth, async (req, res) => {
  try {
    const tasks = await db.getDueSoonTasks(req.session.userId);
    const user = await db.getUserById(req.session.userId);
    if (user) {
      for (const t of tasks) {
        await email.sendEmail(
          `${user.username}@example.com`,
          'Task Reminder',
          `Task "${t.text}" is due on ${t.dueDate}`
        );
      }
    }
    res.json(tasks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load reminders' });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  const text = req.body.text;
  const dueDate = req.body.dueDate;
  const category = req.body.category;
  const assignedTo = req.body.assignedTo;
  const repeatInterval = req.body.repeatInterval;
  let priority = req.body.priority || 'medium';
  priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  if (dueDate && !isValidFutureDate(dueDate)) {
    return res.status(400).json({ error: 'Invalid due date' });
  }
  if (
    repeatInterval !== undefined &&
    repeatInterval !== null &&
    repeatInterval !== '' &&
    !['daily', 'weekly', 'monthly'].includes(repeatInterval)
  ) {
    return res.status(400).json({ error: 'Invalid repeat interval' });
  }
  try {
    let assigneeId = assignedTo;
    if (assigneeId !== undefined) {
      const user = await db.getUserById(assigneeId);
      if (!user) return res.status(400).json({ error: 'Assigned user not found' });
    }
    const task = await db.createTask({
      text,
      dueDate,
      priority,
      category,
      done: false,
      userId: req.session.userId,
      assignedTo: assigneeId,
      repeatInterval
    });
    await db.createHistory({
      taskId: task.id,
      userId: req.session.userId,
      action: 'created',
      details: null
    });
    res.status(201).json(task);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.post('/api/tasks/:id/assign', requireAuth, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  const username = req.body.username;
  if (!username) return res.status(400).json({ error: 'Username required' });
  try {
    const user = await db.getUserByUsername(username);
    if (!user) return res.status(400).json({ error: 'User not found' });
    const updated = await db.assignTask(id, user.id);
    if (!updated) return res.status(404).json({ error: 'Task not found' });
    await email.sendEmail(
      `${user.username}@example.com`,
      'Task Assigned',
      `You have been assigned the task "${updated.text}"`
    );
    await db.createHistory({
      taskId: updated.id,
      userId: req.session.userId,
      action: 'assigned',
      details: user.username
    });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to assign task' });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { text, dueDate, priority, done, category, repeatInterval } = req.body;
  if (text !== undefined && !text.trim()) {
    return res.status(400).json({ error: 'Task text cannot be empty' });
  }
  if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority value' });
  }
  if (dueDate !== undefined && dueDate !== null && dueDate !== '' && !isValidFutureDate(dueDate)) {
    return res.status(400).json({ error: 'Invalid due date' });
  }
  if (
    repeatInterval !== undefined &&
    repeatInterval !== null &&
    repeatInterval !== '' &&
    !['daily', 'weekly', 'monthly'].includes(repeatInterval)
  ) {
    return res.status(400).json({ error: 'Invalid repeat interval' });
  }
  try {
    const oldTask = await db.getTask(id, req.session.userId);
    const updated = await db.updateTask(
      id,
      { text, dueDate, priority, done, category, repeatInterval },
      req.session.userId
    );
    if (!updated) {
      return res.status(404).json({ error: 'Task not found' });
    }
    await db.createHistory({
      taskId: updated.id,
      userId: req.session.userId,
      action: 'updated',
      details: null
    });
    if (
      oldTask &&
      !oldTask.done &&
      updated.done &&
      updated.repeatInterval &&
      updated.dueDate
    ) {
      const date = new Date(updated.dueDate + 'T00:00:00Z');
      if (updated.repeatInterval === 'daily') {
        date.setUTCDate(date.getUTCDate() + 1);
      } else if (updated.repeatInterval === 'weekly') {
        date.setUTCDate(date.getUTCDate() + 7);
      } else if (updated.repeatInterval === 'monthly') {
        date.setUTCMonth(date.getUTCMonth() + 1);
      }
      const nextDue = date.toISOString().slice(0, 10);
      await db.createTask({
        text: updated.text,
        dueDate: nextDue,
        priority: updated.priority,
        category: updated.category,
        done: false,
        userId: updated.userId,
        assignedTo: updated.assignedTo,
        repeatInterval: updated.repeatInterval
      });
    }
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.put('/api/tasks/bulk', requireAuth, async (req, res) => {
  const { ids, done, priority } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'ids required' });
  }
  if (done === undefined && priority === undefined) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority value' });
  }
  try {
    const results = [];
    for (const id of ids) {
      const updated = await db.updateTask(
        id,
        { ...(done !== undefined ? { done } : {}), ...(priority !== undefined ? { priority } : {}) },
        req.session.userId
      );
      if (updated) results.push(updated);
    }
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update tasks' });
  }
});

app.post('/api/tasks/bulk-delete', requireAuth, requireAdmin, async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'ids required' });
  }
  try {
    const results = [];
    for (const id of ids) {
      const del = await db.deleteTask(id);
      if (del) results.push(del);
    }
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete tasks' });
  }
});

app.delete('/api/tasks/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const deleted = await db.deleteTask(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(deleted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.get('/api/tasks/:taskId/subtasks', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  try {
    const subs = await db.listSubtasks(taskId, req.session.userId);
    res.json(subs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load subtasks' });
  }
});

app.post('/api/tasks/:taskId/subtasks', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  const text = req.body.text;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: 'Subtask text is required' });
  }
  try {
    const sub = await db.createSubtask(taskId, { text, done: false }, req.session.userId);
    if (!sub) return res.status(404).json({ error: 'Task not found' });
    res.status(201).json(sub);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save subtask' });
  }
});

app.put('/api/subtasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { text, done } = req.body;
  if (text !== undefined && !text.trim()) {
    return res.status(400).json({ error: 'Subtask text cannot be empty' });
  }
  try {
    const updated = await db.updateSubtask(id, { text, done }, req.session.userId);
    if (!updated) return res.status(404).json({ error: 'Subtask not found' });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save subtask' });
  }
});

app.delete('/api/subtasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const deleted = await db.deleteSubtask(id, req.session.userId);
    if (!deleted) return res.status(404).json({ error: 'Subtask not found' });
    res.json(deleted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete subtask' });
  }
});

app.get('/api/tasks/:taskId/comments', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  try {
    const comments = await db.listComments(taskId, req.session.userId);
    res.json(comments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load comments' });
  }
});

app.post('/api/tasks/:taskId/comments', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  const text = req.body.text;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: 'Comment text is required' });
  }
  try {
    const comment = await db.createComment(taskId, text, req.session.userId);
    if (!comment) return res.status(404).json({ error: 'Task not found' });
    await db.createHistory({
      taskId: taskId,
      userId: req.session.userId,
      action: 'commented',
      details: text
    });
    const task = await db.getTask(taskId);
    if (task) {
      const recipients = new Set();
      if (task.userId && task.userId !== req.session.userId) {
        const owner = await db.getUserById(task.userId);
        if (owner) recipients.add(owner.username);
      }
      if (task.assignedTo && task.assignedTo !== req.session.userId) {
        const assignee = await db.getUserById(task.assignedTo);
        if (assignee) recipients.add(assignee.username);
      }
      for (const uname of recipients) {
        await email.sendEmail(
          `${uname}@example.com`,
          'New Comment',
          `A new comment was added to task "${task.text}": ${text}`
        );
      }
    }
    res.status(201).json(comment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save comment' });
  }
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const deleted = await db.deleteComment(id, req.session.userId);
    if (!deleted) return res.status(404).json({ error: 'Comment not found' });
    res.json(deleted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

app.get('/api/tasks/:id/history', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const task = await db.getTask(id, req.session.userId);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    const events = await db.listHistory(id, req.session.userId);
    res.json(events);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load history' });
  }
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next(err);
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
