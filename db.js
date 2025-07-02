const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'tasks.db');
const db = new sqlite3.Database(DB_FILE);

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    dueDate TEXT,
    priority TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    userId INTEGER
  )`);

  db.all("PRAGMA table_info(tasks)", (err, cols) => {
    if (!err && !cols.some(c => c.name === 'userId')) {
      db.run('ALTER TABLE tasks ADD COLUMN userId INTEGER');
    }
  });
});

function listTasks({ priority, done, sort, userId } = {}) {
  return new Promise((resolve, reject) => {
    let query = 'SELECT * FROM tasks';
    const where = [];
    const params = [];

    if (userId !== undefined) {
      where.push('userId = ?');
      params.push(userId);
    }

    if (priority && ['high', 'medium', 'low'].includes(priority)) {
      where.push('priority = ?');
      params.push(priority);
    }

    if (done === true || done === false) {
      where.push('done = ?');
      params.push(done ? 1 : 0);
    }

    if (where.length) {
      query += ' WHERE ' + where.join(' AND ');
    }

    if (sort === 'dueDate') {
      query += " ORDER BY COALESCE(dueDate, '9999-12-31')";
    } else if (sort === 'priority') {
      query +=
        " ORDER BY CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END";
    }

    db.all(query, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function createTask({ text, dueDate, priority = 'medium', done = false, userId }) {
  return new Promise((resolve, reject) => {
    const stmt = db.run(
      `INSERT INTO tasks (text, dueDate, priority, done, userId) VALUES (?, ?, ?, ?, ?)`,
      [text, dueDate, priority, done ? 1 : 0, userId],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, text, dueDate, priority, done, userId });
      }
    );
  });
}

function getTask(id, userId) {
  return new Promise((resolve, reject) => {
    const params = [id];
    let sql = 'SELECT * FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND userId = ?';
      params.push(userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function updateTask(id, fields, userId) {
  return new Promise((resolve, reject) => {
    const updates = [];
    const params = [];
    if (fields.text !== undefined) {
      updates.push('text = ?');
      params.push(fields.text);
    }
    if (fields.dueDate !== undefined) {
      updates.push('dueDate = ?');
      params.push(fields.dueDate);
    }
    if (fields.priority !== undefined) {
      updates.push('priority = ?');
      params.push(fields.priority);
    }
    if (fields.done !== undefined) {
      updates.push('done = ?');
      params.push(fields.done ? 1 : 0);
    }
    if (!updates.length) {
      return getTask(id, userId).then(resolve).catch(reject);
    }
    params.push(id);
    let sql = `UPDATE tasks SET ${updates.join(', ')} WHERE id = ?`;
    if (userId !== undefined) {
      sql += ' AND userId = ?';
      params.push(userId);
    }
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      if (this.changes === 0) return resolve(null);
      getTask(id, userId).then(resolve).catch(reject);
    });
  });
}

function deleteTask(id, userId) {
  return new Promise((resolve, reject) => {
    getTask(id, userId)
      .then(row => {
        if (!row) return resolve(null);
        const params = [id];
        let sql = 'DELETE FROM tasks WHERE id = ?';
        if (userId !== undefined) {
          sql += ' AND userId = ?';
          params.push(userId);
        }
        db.run(sql, params, function (err) {
          if (err) return reject(err);
          resolve(row);
        });
      })
      .catch(reject);
  });
}

function createUser({ username, password }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, password],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username, password });
      }
    );
  });
}

function getUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

module.exports = {
  listTasks,
  createTask,
  updateTask,
  deleteTask,
  getTask,
  createUser,
  getUserByUsername,
  getUserById
};
