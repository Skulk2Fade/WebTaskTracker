const express = require('express');
const path = require('path');
const db = require('./db');
const session = require('express-session');
const SQLiteStore = require('./sqliteStore');
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const app = express();

// Use a higher bcrypt work factor for stronger password hashing.
// Configurable via the BCRYPT_ROUNDS environment variable.
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

app.use(express.json());

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
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await db.createUser({ username, password: hashed });
    req.session.userId = user.id;
    res.json({ id: user.id, username: user.username });
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
  const { username, password } = req.body;
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
    req.session.userId = user.id;
    res.json({ id: user.id, username: user.username });
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

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = await db.getUserById(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({ user: { id: user.id, username: user.username } });
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

app.post('/api/tasks', requireAuth, async (req, res) => {
  const text = req.body.text;
  const dueDate = req.body.dueDate;
  const category = req.body.category;
  const assignedTo = req.body.assignedTo;
  let priority = req.body.priority || 'medium';
  priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  if (dueDate && !isValidFutureDate(dueDate)) {
    return res.status(400).json({ error: 'Invalid due date' });
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
      assignedTo: assigneeId
    });
    res.status(201).json(task);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.post('/api/tasks/:id/assign', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const username = req.body.username;
  if (!username) return res.status(400).json({ error: 'Username required' });
  try {
    const user = await db.getUserByUsername(username);
    if (!user) return res.status(400).json({ error: 'User not found' });
    const updated = await db.assignTask(id, user.id, req.session.userId);
    if (!updated) return res.status(404).json({ error: 'Task not found' });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to assign task' });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { text, dueDate, priority, done, category } = req.body;
  if (text !== undefined && !text.trim()) {
    return res.status(400).json({ error: 'Task text cannot be empty' });
  }
  if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority value' });
  }
  if (dueDate !== undefined && dueDate !== null && dueDate !== '' && !isValidFutureDate(dueDate)) {
    return res.status(400).json({ error: 'Invalid due date' });
  }
  try {
    const updated = await db.updateTask(id, { text, dueDate, priority, done, category }, req.session.userId);
    if (!updated) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const deleted = await db.deleteTask(id, req.session.userId);
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
