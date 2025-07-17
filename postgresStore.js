const session = require('express-session');
let Pool;
try {
  ({ Pool } = require('pg'));
} catch {
  Pool = null;
}

class PostgresStore extends session.Store {
  constructor(options = {}) {
    super();
    if (!Pool) throw new Error('pg module not installed');
    const url = options.dbUrl || process.env.DATABASE_URL;
    this.pool = new Pool({ connectionString: url });
    this.pool
      .query(`CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        expires BIGINT,
        data TEXT
      )`)
      .catch(() => {});
  }

  get(sid, cb) {
    this.pool
      .query('SELECT data, expires FROM sessions WHERE sid = $1', [sid])
      .then(res => {
        if (!res.rows.length) return cb();
        const row = res.rows[0];
        if (row.expires && row.expires < Date.now()) {
          return this.destroy(sid, cb);
        }
        try {
          cb(null, JSON.parse(row.data));
        } catch (e) {
          cb(e);
        }
      })
      .catch(err => cb(err));
  }

  set(sid, sessionData, cb) {
    const expires = sessionData.cookie && sessionData.cookie.expires
      ? new Date(sessionData.cookie.expires).getTime()
      : Date.now() + 86400000;
    const data = JSON.stringify(sessionData);
    this.pool
      .query(
        'INSERT INTO sessions (sid, expires, data) VALUES ($1, $2, $3) ON CONFLICT (sid) DO UPDATE SET expires = EXCLUDED.expires, data = EXCLUDED.data',
        [sid, expires, data]
      )
      .then(() => cb())
      .catch(err => cb(err));
  }

  destroy(sid, cb) {
    this.pool
      .query('DELETE FROM sessions WHERE sid = $1', [sid])
      .then(() => cb())
      .catch(err => cb(err));
  }

  touch(sid, sessionData, cb) {
    const expires = sessionData.cookie && sessionData.cookie.expires
      ? new Date(sessionData.cookie.expires).getTime()
      : Date.now() + 86400000;
    this.pool
      .query('UPDATE sessions SET expires = $1 WHERE sid = $2', [expires, sid])
      .then(() => cb())
      .catch(err => cb(err));
  }
}

module.exports = PostgresStore;
