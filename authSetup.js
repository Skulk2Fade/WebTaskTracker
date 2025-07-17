const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const logger = require('./logger');
const db = require('./db');
const config = require('./config');

let passport;
let GoogleStrategy;
let GitHubStrategy;

const enableGoogle = Boolean(
  config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET
);
const enableGithub = Boolean(
  config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET
);

function initPassport(app) {
  if (!enableGoogle && !enableGithub) {
    logger.warn(
      'OAuth environment variables not set; skipping Passport initialization'
    );
    return null;
  }

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
                  config.BCRYPT_ROUNDS
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
                  config.BCRYPT_ROUNDS
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

  return passport;
}

module.exports = { initPassport };
