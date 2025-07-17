const express = require('express');
const path = require('path');
const logger = require('./logger');
const db = require('./db');
const session = require('express-session');
const SQLiteStore = require('./sqliteStore');
const csurf = require('csurf');
const helmet = require('helmet');
const config = require('./config');
const {
  rateLimiter,
  handleError,
} = require('./utils');

const { initPassport } = require('./authSetup');
const setupAttachmentDir = require('./attachmentSetup');
const { setupSse } = require('./sse');
const {
  requireAuth,
  requireWriter,
  requireGroupAdmin,
  requireAdmin,
} = require('./middleware/auth');

let passport;
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
  DB_FILE,
  PORT,
} = config;

setupAttachmentDir();

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
passport = initPassport(app);
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', apiLimiter);
app.use(csurf());

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

setupSse(app, requireAuth);

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
