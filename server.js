const express = require('express');
const path = require('path');
const fs = require('fs');
const logger = require('./logger');
const db = require('./db');
const session = require('express-session');
const SQLiteStore = require('./sqliteStore');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const csurf = require('csurf');
const helmet = require('helmet');
const { encrypt, decrypt } = require('./cryptoUtil');
const totp = require('./totp');
const email = require('./email');
const sms = require('./sms');
const webhooks = require('./webhooks');
const { tasksToIcs, fromIcs } = require('./icsUtil');
const calendarSync = require('./calendarSync');
const config = require("./config");
const utils = require("./utils");

let passport;
let GoogleStrategy;
let GitHubStrategy;
const enableGoogle = Boolean(
  process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
);
const enableGithub = Boolean(
  process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET
);
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
    logger.error(
      err,
      'Required Passport modules are missing. Install them or remove OAuth environment variables.'
    );
    process.exit(1);
  }
} else {
  logger.warn('OAuth environment variables not set; skipping Passport initialization');
}
const app = express();
app.use(helmet());
app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "https://cdn.jsdelivr.net"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"] } }));

const isTestEnv = process.env.NODE_ENV === 'test';

function rateLimiter(windowMs, max, name) {
  return async (req, res, next) => {
    if (isTestEnv) return next();
    try {
      const key = `${name}:${req.ip}`;
      const { count } = await db.incrementRateLimit(key, windowMs);
      if (count > max) {
        return res.status(429).json({ error: 'Too many requests' });
      }
    } catch (err) {
      logger.error({ err }, 'Rate limit error');
    }
    next();
  };
}

const apiLimiter = rateLimiter(15 * 60 * 1000, 100, 'api');
const loginLimiter = rateLimiter(15 * 60 * 1000, 10, 'login');

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

function formatTemplate(template, vars) {
  if (!template) return null;
  return template.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] || '');
}

const DUE_SOON_CHECK_INTERVAL =
  parseInt(process.env.DUE_SOON_CHECK_INTERVAL, 10) || 60000;
const DUE_SOON_BATCH_SIZE =
  parseInt(process.env.DUE_SOON_BATCH_SIZE, 10) || 50;
let dueSoonOffset = 0;

async function checkDueSoon() {
  const ids = Array.from(sseClients.keys());
  if (ids.length === 0) return;
  const batchSize = Math.min(DUE_SOON_BATCH_SIZE, ids.length);
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
          dueTime: t.dueTime
        });
      }
    } catch (err) {
      logger.error(err);
    }
  }
}

setInterval(checkDueSoon, DUE_SOON_CHECK_INTERVAL);

// Use a higher bcrypt work factor for stronger password hashing.
// Configurable via the BCRYPT_ROUNDS environment variable.
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const TWO_FA_SECRET_TTL = parseInt(process.env.TWO_FA_SECRET_TTL, 10) || 10 * 60 * 1000;

const ALLOWED_MIME_TYPES = new Set([
  'text/plain',
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
  'application/octet-stream'
]);

const MAX_ATTACHMENT_SIZE =
  parseInt(process.env.MAX_ATTACHMENT_SIZE, 10) || 10 * 1024 * 1024; // 10MB

const ATTACHMENT_DIR = process.env.ATTACHMENT_DIR;
const ATTACHMENT_MIN_SPACE =
  parseInt(process.env.ATTACHMENT_MIN_SPACE, 10) || 0;
const ATTACHMENT_QUOTA =
  parseInt(process.env.ATTACHMENT_QUOTA, 10) || 0;

function getDirSize(dir) {
  let size = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const stat = fs.statSync(full);
    if (stat.isFile()) size += stat.size;
    else if (stat.isDirectory()) size += getDirSize(full);
  }
  return size;
}

function getFreeSpace(dir) {
  try {
    const { bavail, bsize } = fs.statfsSync(dir);
    return bavail * bsize;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

if (ATTACHMENT_DIR) {
  const resolved = path.resolve(ATTACHMENT_DIR);
  const publicDir = path.resolve(__dirname, 'public');
  if (resolved.startsWith(publicDir)) {
    logger.warn('ATTACHMENT_DIR should not be inside the public directory');
  }
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  if (ATTACHMENT_MIN_SPACE) {
    const free = getFreeSpace(resolved);
    if (free < ATTACHMENT_MIN_SPACE) {
      logger.warn(
        `ATTACHMENT_DIR has only ${free} bytes free (< ${ATTACHMENT_MIN_SPACE})`
      );
    }
  }
}

app.use(express.json());
app.use(
  express.text({ type: ['text/csv', 'application/csv', 'text/calendar'] })
);

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

function isValidRecurrenceRule(rule) {
  return (
    rule &&
    Number.isInteger(rule.weekday) &&
    rule.weekday >= 0 &&
    rule.weekday <= 6 &&
    Number.isInteger(rule.ordinal) &&
    rule.ordinal >= 1 &&
    rule.ordinal <= 5
  );
}

function nthWeekdayOfMonth(year, month, weekday, ordinal) {
  const first = new Date(Date.UTC(year, month, 1));
  const firstDow = first.getUTCDay();
  let day = 1 + ((7 + weekday - firstDow) % 7) + (ordinal - 1) * 7;
  const dim = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  if (day > dim) return null;
  return new Date(Date.UTC(year, month, day));
}

function getNextRepeatDate(dateStr, interval, rule) {
  if (!dateStr) return null;
  const date = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(date.getTime())) return null;
  if (interval === 'daily') {
    date.setUTCDate(date.getUTCDate() + 1);
  } else if (interval === 'weekly') {
    date.setUTCDate(date.getUTCDate() + 7);
  } else if (interval === 'monthly') {
    date.setUTCMonth(date.getUTCMonth() + 1);
  } else if (interval === 'weekday') {
    date.setUTCDate(date.getUTCDate() + 1);
    const day = date.getUTCDay();
    if (day === 6) {
      date.setUTCDate(date.getUTCDate() + 2);
    } else if (day === 0) {
      date.setUTCDate(date.getUTCDate() + 1);
    }
  } else if (interval === 'last_day') {
    const next = new Date(
      Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 2, 0)
    );
    return next.toISOString().slice(0, 10);
  } else if (interval === 'custom' && rule && isValidRecurrenceRule(rule)) {
    date.setUTCMonth(date.getUTCMonth() + 1);
    const next = nthWeekdayOfMonth(
      date.getUTCFullYear(),
      date.getUTCMonth(),
      rule.weekday,
      rule.ordinal
    );
    if (!next) return null;
    return next.toISOString().slice(0, 10);
  } else {
    return null;
  }
  return date.toISOString().slice(0, 10);
}

function isStrongPassword(pw) {
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw)
  );
}

function isAllowedMimeType(type) {
  return ALLOWED_MIME_TYPES.has(type);
}

function handleError(res, err, message) {
  logger.error(err);
  const body = { error: message };
  if (process.env.NODE_ENV !== 'production') {
    body.details = err.message;
  }
  res.status(500).json(body);
}
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  logger.error('SESSION_SECRET environment variable is required');
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
app.use('/api', apiLimiter);
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
require("./routes/auth")(app, loginLimiter);
require("./routes/admin")(app);
require("./routes/preferences")(app);
require("./routes/groups")(app);
require("./routes/tasks")(app);
require("./routes/reports")(app);



app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  if (res.headersSent) {
    return next(err);
  }
  handleError(res, err, 'Internal server error');
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
}

module.exports = app;
