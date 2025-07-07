const express = require('express');
const path = require('path');
const fs = require('fs');
const db = require('./db');
const session = require('express-session');
const SQLiteStore = require('./sqliteStore');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const csurf = require('csurf');
const totp = require('./totp');
const email = require('./email');
const webhooks = require('./webhooks');
let passport;
let GoogleStrategy;
let GitHubStrategy;
const enableGoogle =
  process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;
const enableGithub =
  process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET;
if (enableGoogle || enableGithub) {
  try {
    passport = require('passport');
    if (enableGoogle) {
      GoogleStrategy = require('passport-google-oauth20').Strategy;
    }
    if (enableGithub) {
      GitHubStrategy = require('passport-github2').Strategy;
    }
  } catch (err) {
    console.warn('Passport modules not installed; OAuth disabled');
    passport = null;
  }
}
const app = express();

// Simple Server-Sent Events implementation
const sseClients = new Map();

function addSseClient(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);
  res.on('close', () => {
    const set = sseClients.get(userId);
    if (set) {
      set.delete(res);
      if (set.size === 0) sseClients.delete(userId);
    }
  });
}

function sendSse(userId, type, data) {
  const set = sseClients.get(userId);
  if (!set) return;
  const payload = `data:${JSON.stringify({ type, ...data })}\n\n`;
  for (const res of set) {
    res.write(payload);
  }
}

async function checkDueSoon() {
  for (const id of Array.from(sseClients.keys())) {
    const uid = parseInt(id, 10);
    try {
      const tasks = await db.getDueSoonTasks(uid);
      for (const t of tasks) {
        sendSse(uid, 'task_due', { taskId: t.id, text: t.text, dueDate: t.dueDate, dueTime: t.dueTime });
      }
    } catch (err) {
      console.error(err);
    }
  }
}

setInterval(checkDueSoon, 60000);

// Use a higher bcrypt work factor for stronger password hashing.
// Configurable via the BCRYPT_ROUNDS environment variable.
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

const ALLOWED_MIME_TYPES = new Set([
  'text/plain',
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
  'application/octet-stream'
]);

const ATTACHMENT_DIR = process.env.ATTACHMENT_DIR;
if (ATTACHMENT_DIR) {
  const resolved = path.resolve(ATTACHMENT_DIR);
  const publicDir = path.resolve(__dirname, 'public');
  if (resolved.startsWith(publicDir)) {
    console.warn('ATTACHMENT_DIR should not be inside the public directory');
  }
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
}

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

function isValidTime(str) {
  if (str === undefined || str === null || str === '') return true;
  if (!/^\d{2}:\d{2}$/.test(str)) return false;
  const [h, m] = str.split(':').map(Number);
  return h >= 0 && h < 24 && m >= 0 && m < 60;
}

function isValidFutureDateTime(dateStr, timeStr) {
  if (!isValidFutureDate(dateStr)) return false;
  if (!isValidTime(timeStr)) return false;
  if (!dateStr || !timeStr) return true;
  const due = new Date(dateStr + 'T' + timeStr + ':00Z');
  if (isNaN(due.getTime())) return false;
  const now = new Date();
  return due >= now;
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

function isAllowedMimeType(type) {
  return ALLOWED_MIME_TYPES.has(type);
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
if (passport) {
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await db.getUserById(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
}
app.use(express.static(path.join(__dirname, 'public')));
app.use(csurf());

if (passport) {
  if (enableGoogle) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: '/auth/google/callback'
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            let user = await db.getUserByGoogleId(profile.id);
            if (!user) {
              const username =
                (profile.emails && profile.emails[0] && profile.emails[0].value) ||
                `google_${profile.id}`;
              user = await db.getUserByUsername(username);
              if (user) {
                await db.setUserGoogleId(user.id, profile.id);
              } else {
                const count = await db.countUsers();
                const role = count === 0 ? 'admin' : 'member';
                const hash = await bcrypt.hash(
                  crypto.randomBytes(16).toString('hex'),
                  BCRYPT_ROUNDS
                );
                user = await db.createUser({
                  username,
                  password: hash,
                  role,
                  googleId: profile.id
                });
              }
            }
            done(null, user);
          } catch (err) {
            done(err);
          }
        }
      )
    );

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get(
      '/auth/google/callback',
      passport.authenticate('google', { failureRedirect: '/' }),
      (req, res) => {
        req.session.userId = req.user.id;
        res.redirect('/');
      }
    );
  }

  if (enableGithub) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
          callbackURL: '/auth/github/callback'
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            let user = await db.getUserByGithubId(profile.id);
            if (!user) {
              const username = profile.username || `github_${profile.id}`;
              user = await db.getUserByUsername(username);
              if (user) {
                await db.setUserGithubId(user.id, profile.id);
              } else {
                const count = await db.countUsers();
                const role = count === 0 ? 'admin' : 'member';
                const hash = await bcrypt.hash(
                  crypto.randomBytes(16).toString('hex'),
                  BCRYPT_ROUNDS
                );
                user = await db.createUser({
                  username,
                  password: hash,
                  role,
                  githubId: profile.id
                });
              }
            }
            done(null, user);
          } catch (err) {
            done(err);
          }
        }
      )
    );

    app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
    app.get(
      '/auth/github/callback',
      passport.authenticate('github', { failureRedirect: '/' }),
      (req, res) => {
        req.session.userId = req.user.id;
        res.redirect('/');
      }
    );
  }
}

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/api/events', requireAuth, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.flushHeaders();
  addSseClient(req.session.userId, res);
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

// Admin endpoints
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await db.listUsers();
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const ok = await db.deleteUser(id);
    if (!ok) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  try {
    const logs = await db.listActivity(limit);
    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load logs' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const stats = await db.getStats();
    res.json(stats);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

app.get('/api/admin/reports', requireAdmin, async (req, res) => {
  try {
    const reports = await db.getReports();
    res.json(reports);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

app.get('/api/preferences', requireAuth, async (req, res) => {
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      emailReminders: !!user.emailReminders,
      emailNotifications: !!user.emailNotifications
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load preferences' });
  }
});

app.put('/api/preferences', requireAuth, async (req, res) => {
  const { emailReminders, emailNotifications } = req.body;
  try {
    const user = await db.updateUserPreferences(req.session.userId, {
      emailReminders,
      emailNotifications
    });
    res.json({
      emailReminders: !!user.emailReminders,
      emailNotifications: !!user.emailNotifications
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update preferences' });
  }
});

app.post('/api/groups', requireAuth, async (req, res) => {
  const name = req.body.name;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const group = await db.createGroup(name);
    await db.addUserToGroup(group.id, req.session.userId);
    res.status(201).json(group);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

app.post('/api/groups/:id/join', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    await db.addUserToGroup(id, req.session.userId);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to join group' });
  }
});

app.get('/api/groups', requireAuth, async (req, res) => {
  try {
    const groups = await db.listUserGroups(req.session.userId);
    res.json(groups);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load groups' });
  }
});


app.get('/api/tasks', requireAuth, async (req, res) => {
  const { priority, done, sort, category, categories, search, startDate, endDate, page, pageSize } = req.query;
  const pg = parseInt(page, 10) >= 1 ? parseInt(page, 10) : 1;
  const size = parseInt(pageSize, 10) >= 1 ? parseInt(pageSize, 10) : 20;
  try {
    const tasks = await db.listTasks({
      priority,
      done: done === 'true' ? true : done === 'false' ? false : undefined,
      sort,
      userId: req.session.userId,
      category,
      categories: categories
        ? categories
            .split(',')
            .map(c => c.trim())
            .filter(c => c)
        : undefined,
      search,
      startDate,
      endDate,
      limit: size,
      offset: (pg - 1) * size
    });
    res.json(tasks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load tasks' });
  }
});

app.get('/api/tasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const task = await db.getTask(id, req.session.userId);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    const [subtasks, dependencies, comments] = await Promise.all([
      db.listSubtasks(id, req.session.userId),
      db.listDependencies(id, req.session.userId),
      db.listComments(id, req.session.userId)
    ]);
    res.json({ ...task, subtasks, dependencies, comments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load task' });
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
    'dueTime',
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
      escapeCsv(t.dueTime),
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

function toIcs(tasks) {
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//WebTaskTracker//EN'];
  const stamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  for (const t of tasks) {
    lines.push('BEGIN:VTODO');
    lines.push(`UID:${t.id}@webtasktracker`);
    lines.push('DTSTAMP:' + stamp);
    if (t.dueDate && t.dueTime) {
      const dt = new Date(`${t.dueDate}T${t.dueTime}:00Z`);
      const due = dt.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
      lines.push('DUE:' + due);
    } else if (t.dueDate) {
      lines.push('DUE;VALUE=DATE:' + t.dueDate.replace(/-/g, ''));
    }
    if (t.priority) {
      const p = t.priority === 'high' ? 1 : t.priority === 'medium' ? 5 : 9;
      lines.push('PRIORITY:' + p);
    }
    lines.push('STATUS:' + (t.done ? 'COMPLETED' : 'NEEDS-ACTION'));
    lines.push('SUMMARY:' + (t.text || '').replace(/\r?\n/g, ' '));
    lines.push('END:VTODO');
  }
  lines.push('END:VCALENDAR');
  return lines.join('\r\n');
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

app.get('/api/tasks/ics', requireAuth, async (req, res) => {
  try {
    const tasks = await db.listTasks({ userId: req.session.userId });
    res.setHeader('Content-Type', 'text/calendar');
    res.setHeader('Content-Disposition', 'attachment; filename="tasks.ics"');
    res.send(toIcs(tasks));
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
        dueTime: t.dueTime || null,
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
    if (user && user.emailReminders) {
      for (const t of tasks) {
        const dueStr = t.dueTime ? `${t.dueDate} ${t.dueTime}` : t.dueDate;
        await email.sendEmail(
          `${user.username}@example.com`,
          'Task Reminder',
          `Task "${t.text}" is due on ${dueStr}`
        );
      }
    }
    for (const t of tasks) {
      sendSse(req.session.userId, 'task_due', { taskId: t.id, text: t.text, dueDate: t.dueDate, dueTime: t.dueTime });
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
  const dueTime = req.body.dueTime;
  const category = req.body.category;
  const assignedTo = req.body.assignedTo;
  const groupId = req.body.groupId;
  const repeatInterval = req.body.repeatInterval;
  let priority = req.body.priority || 'medium';
  priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  if (dueTime && !dueDate) {
    return res.status(400).json({ error: 'dueTime requires dueDate' });
  }
  if (dueDate && !isValidFutureDateTime(dueDate, dueTime)) {
    return res.status(400).json({ error: 'Invalid due date/time' });
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
    if (groupId !== undefined && groupId !== null) {
      const groups = await db.listUserGroups(req.session.userId);
      if (!groups.some(g => g.id === groupId)) {
        return res.status(400).json({ error: 'Invalid group' });
      }
    }
    const task = await db.createTask({
      text,
      dueDate,
      dueTime,
      priority,
      category,
      done: false,
      userId: req.session.userId,
      assignedTo: assigneeId,
      groupId,
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
    if (user.emailNotifications) {
      await email.sendEmail(
        `${user.username}@example.com`,
        'Task Assigned',
        `You have been assigned the task "${updated.text}"`
      );
    }
    await db.createHistory({
      taskId: updated.id,
      userId: req.session.userId,
      action: 'assigned',
      details: user.username
    });
    await webhooks.sendWebhook('task_assigned', {
      taskId: updated.id,
      text: updated.text,
      assignedTo: user.username
    });
    sendSse(user.id, 'task_assigned', { taskId: updated.id, text: updated.text });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to assign task' });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { text, dueDate, dueTime, priority, done, category, repeatInterval } = req.body;
  if (text !== undefined && !text.trim()) {
    return res.status(400).json({ error: 'Task text cannot be empty' });
  }
  if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority value' });
  }
  if (dueTime && !dueDate) {
    return res.status(400).json({ error: 'dueTime requires dueDate' });
  }
  if (
    dueDate !== undefined &&
    dueDate !== null &&
    dueDate !== '' &&
    !isValidFutureDateTime(dueDate, dueTime)
  ) {
    return res.status(400).json({ error: 'Invalid due date/time' });
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
    if (!oldTask) {
      return res.status(404).json({ error: 'Task not found' });
    }
    if (done === true) {
      const subs = await db.listSubtasks(id, req.session.userId);
      if (subs.some(s => !s.done)) {
        return res.status(400).json({ error: 'Subtasks not completed' });
      }
      const deps = await db.listDependencies(id, req.session.userId);
      for (const depId of deps) {
        const dep = await db.getTask(depId, req.session.userId);
        if (!dep || !dep.done) {
          return res.status(400).json({ error: 'Dependencies not completed' });
        }
      }
    }
    const updated = await db.updateTask(
      id,
      { text, dueDate, dueTime, priority, done, category, repeatInterval },
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
    if (oldTask && !oldTask.done && updated.done) {
      await db.createHistory({
        taskId: updated.id,
        userId: req.session.userId,
        action: 'completed',
        details: null
      });
      await webhooks.sendWebhook('task_completed', {
        taskId: updated.id,
        text: updated.text
      });
    }
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
        dueTime: updated.dueTime,
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

app.get('/api/tasks/:taskId/dependencies', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  try {
    const deps = await db.listDependencies(taskId, req.session.userId);
    if (deps === null) return res.status(404).json({ error: 'Task not found' });
    const tasks = await Promise.all(deps.map(id => db.getTask(id, req.session.userId)));
    res.json(tasks.filter(t => t));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load dependencies' });
  }
});

app.post('/api/tasks/:taskId/dependencies', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  const dependsOn = parseInt(req.body.dependsOn);
  if (!dependsOn) {
    return res.status(400).json({ error: 'dependsOn required' });
  }
  try {
    const dep = await db.addDependency(taskId, dependsOn, req.session.userId);
    if (!dep) return res.status(404).json({ error: 'Task not found' });
    res.status(201).json(dep);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save dependency' });
  }
});

app.delete('/api/tasks/:taskId/dependencies/:depId', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  const depId = parseInt(req.params.depId);
  try {
    const dep = await db.removeDependency(taskId, depId, req.session.userId);
    if (!dep) return res.status(404).json({ error: 'Task not found' });
    res.json(dep);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete dependency' });
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
      const recipients = [];
      if (task.userId && task.userId !== req.session.userId) {
        const owner = await db.getUserById(task.userId);
        if (owner) recipients.push(owner);
      }
      if (task.assignedTo && task.assignedTo !== req.session.userId) {
        const assignee = await db.getUserById(task.assignedTo);
        if (assignee) recipients.push(assignee);
      }
      for (const user of recipients) {
        if (user.emailNotifications) {
          await email.sendEmail(
            `${user.username}@example.com`,
            'New Comment',
            `A new comment was added to task "${task.text}": ${text}`
          );
        }
        sendSse(user.id, 'task_commented', { taskId, text });
      }
    }
    await webhooks.sendWebhook('task_commented', {
      taskId,
      commentId: comment.id,
      text
    });
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

app.get('/api/tasks/:taskId/attachments', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  try {
    const files = await db.listTaskAttachments(taskId, req.session.userId);
    if (files === null) return res.status(404).json({ error: 'Task not found' });
    res.json(files);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load attachments' });
  }
});

app.post('/api/tasks/:taskId/attachments', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  const { filename, mimeType, content } = req.body;
  if (!filename || !mimeType || !content) {
    return res.status(400).json({ error: 'filename, mimeType and content required' });
  }
  if (!isAllowedMimeType(mimeType)) {
    return res.status(400).json({ error: 'Unsupported mime type' });
  }
  try {
    const att = await db.createTaskAttachment(
      taskId,
      { filename, mimeType, content },
      req.session.userId
    );
    if (!att) return res.status(404).json({ error: 'Task not found' });
    res.status(201).json(att);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save attachment' });
  }
});

app.post('/api/tasks/:taskId/attachments/upload', requireAuth, async (req, res) => {
  const taskId = parseInt(req.params.taskId);
  if (!ATTACHMENT_DIR) return res.status(500).json({ error: 'Attachment storage not configured' });
  const filename = req.headers['x-filename'];
  const mimeType = req.headers['content-type'] || 'application/octet-stream';
  if (!filename) return res.status(400).json({ error: 'X-Filename header required' });
  if (!isAllowedMimeType(mimeType)) {
    return res.status(400).json({ error: 'Unsupported mime type' });
  }
  const temp = path.join(ATTACHMENT_DIR, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`);
  const stream = fs.createWriteStream(temp, { mode: 0o600 });
  req.pipe(stream);
  stream.on('finish', async () => {
    try {
      const att = await db.createTaskAttachment(taskId, { filename, mimeType, filePath: temp }, req.session.userId);
      if (!att) {
        fs.unlink(temp, () => {});
        return res.status(404).json({ error: 'Task not found' });
      }
      res.status(201).json(att);
    } catch (err) {
      fs.unlink(temp, () => {});
      console.error(err);
      res.status(500).json({ error: 'Failed to save attachment' });
    }
  });
  stream.on('error', err => {
    fs.unlink(temp, () => {});
    console.error(err);
    res.status(500).json({ error: 'Failed to write file' });
  });
});

app.get('/api/comments/:commentId/attachments', requireAuth, async (req, res) => {
  const commentId = parseInt(req.params.commentId);
  try {
    const files = await db.listCommentAttachments(commentId, req.session.userId);
    if (files === null) return res.status(404).json({ error: 'Comment not found' });
    res.json(files);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load attachments' });
  }
});

app.post('/api/comments/:commentId/attachments', requireAuth, async (req, res) => {
  const commentId = parseInt(req.params.commentId);
  const { filename, mimeType, content } = req.body;
  if (!filename || !mimeType || !content) {
    return res.status(400).json({ error: 'filename, mimeType and content required' });
  }
  if (!isAllowedMimeType(mimeType)) {
    return res.status(400).json({ error: 'Unsupported mime type' });
  }
  try {
    const att = await db.createCommentAttachment(
      commentId,
      { filename, mimeType, content },
      req.session.userId
    );
    if (!att) return res.status(404).json({ error: 'Comment not found' });
    res.status(201).json(att);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save attachment' });
  }
});

app.post('/api/comments/:commentId/attachments/upload', requireAuth, async (req, res) => {
  const commentId = parseInt(req.params.commentId);
  if (!ATTACHMENT_DIR) return res.status(500).json({ error: 'Attachment storage not configured' });
  const filename = req.headers['x-filename'];
  const mimeType = req.headers['content-type'] || 'application/octet-stream';
  if (!filename) return res.status(400).json({ error: 'X-Filename header required' });
  if (!isAllowedMimeType(mimeType)) {
    return res.status(400).json({ error: 'Unsupported mime type' });
  }
  const temp = path.join(ATTACHMENT_DIR, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`);
  const stream = fs.createWriteStream(temp, { mode: 0o600 });
  req.pipe(stream);
  stream.on('finish', async () => {
    try {
      const att = await db.createCommentAttachment(commentId, { filename, mimeType, filePath: temp }, req.session.userId);
      if (!att) {
        fs.unlink(temp, () => {});
        return res.status(404).json({ error: 'Comment not found' });
      }
      res.status(201).json(att);
    } catch (err) {
      fs.unlink(temp, () => {});
      console.error(err);
      res.status(500).json({ error: 'Failed to save attachment' });
    }
  });
  stream.on('error', err => {
    fs.unlink(temp, () => {});
    console.error(err);
    res.status(500).json({ error: 'Failed to write file' });
  });
});

app.get('/api/attachments/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const att = await db.getAttachment(id, req.session.userId);
    if (!att) return res.status(404).json({ error: 'Attachment not found' });
    res.setHeader('Content-Type', att.mimeType);
    if (att.filePath) {
      res.sendFile(path.resolve(att.filePath));
    } else {
      res.send(att.data);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load attachment' });
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
