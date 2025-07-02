const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');

class SQLiteStore extends session.Store {
  constructor(options = {}) {
    super();
    const dbFile =
      options.dbFile || process.env.DB_FILE || path.join(__dirname, 'tasks.db');
    this.db = new sqlite3.Database(dbFile);
    this.db.serialize(() => {
      this.db.run(`CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        expires INTEGER,
        data TEXT
      )`);
    });
  }

  get(sid, cb) {
    this.db.get('SELECT data, expires FROM sessions WHERE sid = ?', [sid], (err, row) => {
      if (err) return cb(err);
      if (!row) return cb();
      if (row.expires && row.expires < Date.now()) {
        return this.destroy(sid, cb);
      }
      try {
        const sess = JSON.parse(row.data);
        return cb(null, sess);
      } catch (e) {
        return cb(e);
      }
    });
  }

  set(sid, sessionData, cb) {
    const expires = sessionData.cookie && sessionData.cookie.expires
      ? new Date(sessionData.cookie.expires).getTime()
      : Date.now() + 86400000;
    const data = JSON.stringify(sessionData);
    this.db.run(
      'INSERT OR REPLACE INTO sessions (sid, expires, data) VALUES (?, ?, ?)',
      [sid, expires, data],
      cb
    );
  }

  destroy(sid, cb) {
    this.db.run('DELETE FROM sessions WHERE sid = ?', [sid], cb);
  }

  touch(sid, sessionData, cb) {
    const expires = sessionData.cookie && sessionData.cookie.expires
      ? new Date(sessionData.cookie.expires).getTime()
      : Date.now() + 86400000;
    this.db.run(
      'UPDATE sessions SET expires = ? WHERE sid = ?',
      [expires, sid],
      cb
    );
  }
}

module.exports = SQLiteStore;
