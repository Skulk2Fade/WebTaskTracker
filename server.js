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
const config = require('./config');
const {
  rateLimiter,
  addSseClient,
  sendSse,
  getFreeSpace,
  handleError,
  getSseClientIds,
} = require('./utils');

let passport;
let GoogleStrategy;
let GitHubStrategy;
const enableGoogle = Boolean(
  config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET
);
const enableGithub = Boolean(
  config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET
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
  logger.warn(
    'OAuth environment variables not set; skipping Passport initialization'
  );
}
const app = express();
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
    },
  })
);

const apiLimiter = rateLimiter(15 * 60 * 1000, 100, 'api', db);
const loginLimiter = rateLimiter(15 * 60 * 1000, 10, 'login', db);

const {
  SESSION_SECRET,
  BCRYPT_ROUNDS,
  TWO_FA_SECRET_TTL,
  MAX_ATTACHMENT_SIZE,
  ATTACHMENT_DIR,
  ATTACHMENT_MIN_SPACE,
  ATTACHMENT_QUOTA,
  DUE_SOON_CHECK_INTERVAL,
  DUE_SOON_BATCH_SIZE,
  DB_FILE,
  PORT,
} = config;

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
          dueTime: t.dueTime,
        });
      }
    } catch (err) {
      logger.error(err);
    }
  }
}

setInterval(checkDueSoon, DUE_SOON_CHECK_INTERVAL);

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
const sessionSecret = SESSION_SECRET;
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      dbFile: DB_FILE,
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    },
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
          clientID: config.GOOGLE_CLIENT_ID,
          clientSecret: config.GOOGLE_CLIENT_SECRET,
          callbackURL: '/auth/google/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            let user = await db.getUserByGoogleId(profile.id);
            if (!user) {
              const username =
                (profile.emails &&
                  profile.emails[0] &&
                  profile.emails[0].value) ||
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
                  googleId: profile.id,
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

    app.get(
      '/auth/google',
      passport.authenticate('google', { scope: ['profile', 'email'] })
    );
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
          clientID: config.GITHUB_CLIENT_ID,
          clientSecret: config.GITHUB_CLIENT_SECRET,
          callbackURL: '/auth/github/callback',
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
                  githubId: profile.id,
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

    app.get(
      '/auth/github',
      passport.authenticate('github', { scope: ['user:email'] })
    );
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
    Connection: 'keep-alive',
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
require('./routes/auth')(app, loginLimiter);
require('./routes/admin')(app);
require('./routes/preferences')(app);
require('./routes/groups')(app);
require('./routes/tasks')(app);
require('./routes/reports')(app);

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
  app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
}

module.exports = app;
