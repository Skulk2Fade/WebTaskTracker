const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { encrypt, decrypt } = require('../cryptoUtil');
const totp = require('../totp');
const db = require('../db');
const { handleError, isStrongPassword } = require('../utils');
const { BCRYPT_ROUNDS, TWO_FA_SECRET_TTL } = require('../config');
const {
  requireAuth,
  requireWriter
} = require('../middleware/auth');

const ALLOWED_ROLES = ['admin', 'member', 'group_admin', 'observer'];

module.exports = function(app, loginLimiter) {
  app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error:
          'Password must be at least 8 characters and include upper and lower case letters, a number and a special character'
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
      let newRole = userCount === 0 ? 'admin' : 'member';
      if (userCount > 0 && role && ALLOWED_ROLES.includes(role)) {
        newRole = role;
      }
      const user = await db.createUser({ username, password: hashed, role: newRole });
      if (userCount === 0) {
        req.session.userId = user.id;
      }
      res.json({ id: user.id, username: user.username, role: user.role });
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'Username taken' });
      }
      handleError(res, err, 'Failed to register');
    }
  });

  app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password, token } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    try {
      const user = await db.getUserByUsername(username);
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
        return res.status(403).json({ error: 'Account locked. Try again later' });
      }
      const match = await bcrypt.compare(password, user.password);
      let valid = match;
      if (valid && user.twofaSecret) {
        if (
          user.twofaSecretExpiresAt &&
          new Date(user.twofaSecretExpiresAt) < new Date()
        ) {
          await db.setUserTwoFactorSecret(user.id, null, null);
          return res.status(400).json({ error: '2FA setup expired' });
        }
        const decrypted = decrypt(user.twofaSecret);
        valid = totp.verifyToken(token, decrypted);
        if (valid && user.twofaSecretExpiresAt) {
          await db.setUserTwoFactorSecret(user.id, user.twofaSecret, null);
        }
      }
      if (!valid) {
        const updated = await db.incrementFailedLoginAttempts(user.id);
        if (updated.failedLoginAttempts >= 5) {
          const until = new Date(Date.now() + 15 * 60 * 1000).toISOString();
          await db.lockAccount(user.id, until);
          return res
            .status(429)
            .json({ error: 'Account locked. Too many failed attempts' });
        }
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      await db.resetFailedLoginAttempts(user.id);
      req.session.userId = user.id;
      res.json({ id: user.id, username: user.username, role: user.role });
    } catch (err) {
      handleError(res, err, 'Failed to login');
    }
  });

  app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
      res.json({ ok: true });
    });
  });

  app.post('/api/enable-2fa', requireAuth, requireWriter, async (req, res) => {
    try {
      const secret = totp.generateSecret();
      const encrypted = encrypt(secret);
      const expiresAt = new Date(Date.now() + TWO_FA_SECRET_TTL).toISOString();
      await db.setUserTwoFactorSecret(
        req.session.userId,
        encrypted,
        expiresAt
      );
      const user = await db.getUserById(req.session.userId);
      const base32 = totp.base32Encode(Buffer.from(secret, 'hex'));
      const otpauth = `otpauth://totp/WebTaskTracker:${encodeURIComponent(
        user.username
      )}?secret=${base32}&issuer=WebTaskTracker`;
      const qr =
        'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=' +
        encodeURIComponent(otpauth);
      res.json({ secret: base32, qr, expiresAt });
    } catch (err) {
      handleError(res, err, 'Failed to enable 2FA');
    }
  });

  app.post('/api/disable-2fa', requireAuth, requireWriter, async (req, res) => {
    try {
      await db.setUserTwoFactorSecret(req.session.userId, null, null);
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err, 'Failed to disable 2FA');
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
        res.json({ ok: true, token });
      } else {
        res.json({ ok: true });
      }
    } catch (err) {
      handleError(res, err, 'Failed to create reset token');
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
          'Password must be at least 8 characters and include upper and lower case letters, a number and a special character'
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
      handleError(res, err, 'Failed to reset password');
    }
  });

  app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ user: null });
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.json({ user: null });
    res.json({ user: { id: user.id, username: user.username, role: user.role } });
  });
};
