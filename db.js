const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const DB_FILE = path.join(__dirname, 'tasks.db');
const db = new sqlite3.Database(DB_FILE);

// Initialize table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    dueDate TEXT,
    priority TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0
  )`);
});

function listTasks({ priority, done, sort } = {}) {
  return new Promise((resolve, reject) => {
    let query = 'SELECT * FROM tasks';
    const where = [];
    const params = [];

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

function createTask({ text, dueDate, priority = 'medium', done = false }) {
  return new Promise((resolve, reject) => {
    const stmt = db.run(
      `INSERT INTO tasks (text, dueDate, priority, done) VALUES (?, ?, ?, ?)`,
      [text, dueDate, priority, done ? 1 : 0],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, text, dueDate, priority, done });
      }
    );
  });
}

function getTask(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM tasks WHERE id = ?', [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function updateTask(id, fields) {
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
      return getTask(id).then(resolve).catch(reject);
    }
    params.push(id);
    const sql = `UPDATE tasks SET ${updates.join(', ')} WHERE id = ?`;
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      if (this.changes === 0) return resolve(null);
      getTask(id).then(resolve).catch(reject);
    });
  });
}

function deleteTask(id) {
  return new Promise((resolve, reject) => {
    getTask(id)
      .then(row => {
        if (!row) return resolve(null);
        db.run('DELETE FROM tasks WHERE id = ?', [id], function (err) {
          if (err) return reject(err);
          resolve(row);
        });
      })
      .catch(reject);
  });
}

module.exports = {
  listTasks,
  createTask,
  updateTask,
  deleteTask,
  getTask
};
