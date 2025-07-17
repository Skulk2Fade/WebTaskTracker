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
const {
  rateLimiter,
  addSseClient,
  sendSse,
  getFreeSpace,
  handleError,
  getSseClientIds
} = require("./utils");

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

const apiLimiter = rateLimiter(15 * 60 * 1000, 100, 'api', db);
const loginLimiter = rateLimiter(15 * 60 * 1000, 10, 'login', db);

const DUE_SOON_CHECK_INTERVAL =
  parseInt(process.env.DUE_SOON_CHECK_INTERVAL, 10) || 60000;
const DUE_SOON_BATCH_SIZE =
  parseInt(process.env.DUE_SOON_BATCH_SIZE, 10) || 50;
let dueSoonOffset = 0;

async function checkDueSoon() {
  const ids = getSseClientIds();
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

const MAX_ATTACHMENT_SIZE =
  parseInt(process.env.MAX_ATTACHMENT_SIZE, 10) || 10 * 1024 * 1024; // 10MB

const ATTACHMENT_DIR = process.env.ATTACHMENT_DIR;
const ATTACHMENT_MIN_SPACE =
  parseInt(process.env.ATTACHMENT_MIN_SPACE, 10) || 0;
const ATTACHMENT_QUOTA =
  parseInt(process.env.ATTACHMENT_QUOTA, 10) || 0;

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
