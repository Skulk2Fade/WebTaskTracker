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
    userId INTEGER,
    category TEXT,
    assignedTo INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS subtasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER NOT NULL,
    text TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE
  )`);

  db.all("PRAGMA table_info(tasks)", (err, cols) => {
    if (err) return;
    if (!cols.some(c => c.name === 'userId')) {
      db.run('ALTER TABLE tasks ADD COLUMN userId INTEGER');
    }
    if (!cols.some(c => c.name === 'category')) {
      db.run('ALTER TABLE tasks ADD COLUMN category TEXT');
    }
    if (!cols.some(c => c.name === 'assignedTo')) {
      db.run('ALTER TABLE tasks ADD COLUMN assignedTo INTEGER');
    }
  });
});

function listTasks({ priority, done, sort, userId, category, search } = {}) {
  return new Promise((resolve, reject) => {
    let query = 'SELECT * FROM tasks';
    const where = [];
    const params = [];

    if (userId !== undefined) {
      where.push('(userId = ? OR assignedTo = ?)');
      params.push(userId, userId);
    }

    if (priority && ['high', 'medium', 'low'].includes(priority)) {
      where.push('priority = ?');
      params.push(priority);
    }

    if (category) {
      where.push('category = ?');
      params.push(category);
    }

    if (search) {
      where.push('text LIKE ?');
      params.push(`%${search}%`);
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

    db.all(query, params, async (err, rows) => {
      if (err) return reject(err);
      if (!rows) return resolve([]);
      const tasksWithSub = await Promise.all(
        rows.map(async r => ({ ...r, subtasks: await listSubtasks(r.id, userId) }))
      );
      resolve(tasksWithSub);
    });
  });
}

function createTask({ text, dueDate, priority = 'medium', done = false, userId, category, assignedTo }) {
  return new Promise((resolve, reject) => {
    const stmt = db.run(
      `INSERT INTO tasks (text, dueDate, priority, done, userId, category, assignedTo) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [text, dueDate, priority, done ? 1 : 0, userId, category, assignedTo],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, text, dueDate, priority, done, userId, category, assignedTo });
      }
    );
  });
}

function getTask(id, userId) {
  return new Promise((resolve, reject) => {
    const params = [id];
    let sql = 'SELECT * FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ?)';
      params.push(userId, userId);
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
    if (fields.category !== undefined) {
      updates.push('category = ?');
      params.push(fields.category);
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
      sql += ' AND (userId = ? OR assignedTo = ?)';
      params.push(userId, userId);
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
    if (userId === undefined) return resolve(null);
    const params = [id, userId];
    db.get('SELECT * FROM tasks WHERE id = ? AND userId = ?', params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.run('DELETE FROM tasks WHERE id = ? AND userId = ?', params, function (err) {
        if (err) return reject(err);
        resolve(row);
      });
    });
  });
}

function getSubtask(id, userId) {
  return new Promise((resolve, reject) => {
    const params = [id];
    let sql =
      'SELECT subtasks.* FROM subtasks JOIN tasks ON tasks.id = subtasks.taskId WHERE subtasks.id = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function listSubtasks(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql =
      'SELECT subtasks.* FROM subtasks JOIN tasks ON tasks.id = subtasks.taskId WHERE taskId = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function createSubtask(taskId, { text, done = false }, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ?)';
      params.push(userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.run(
        'INSERT INTO subtasks (taskId, text, done) VALUES (?, ?, ?)',
        [taskId, text, done ? 1 : 0],
        function (err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, taskId, text, done });
        }
      );
    });
  });
}

function updateSubtask(id, fields, userId) {
  return new Promise((resolve, reject) => {
    const updates = [];
    const params = [];
    if (fields.text !== undefined) {
      updates.push('text = ?');
      params.push(fields.text);
    }
    if (fields.done !== undefined) {
      updates.push('done = ?');
      params.push(fields.done ? 1 : 0);
    }
    if (!updates.length) {
      return getSubtask(id, userId).then(resolve).catch(reject);
    }
    params.push(id);
    let sql = `UPDATE subtasks SET ${updates.join(', ')} WHERE id = ?`;
    if (userId !== undefined) {
      sql += ' AND taskId IN (SELECT id FROM tasks WHERE userId = ? OR assignedTo = ?)';
      params.push(userId, userId);
    }
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      if (this.changes === 0) return resolve(null);
      getSubtask(id, userId).then(resolve).catch(reject);
    });
  });
}

function deleteSubtask(id, userId) {
  return new Promise((resolve, reject) => {
    getSubtask(id, userId)
      .then(row => {
        if (!row) return resolve(null);
        const params = [id];
        let sql = 'DELETE FROM subtasks WHERE id = ?';
        if (userId !== undefined) {
          sql += ' AND taskId IN (SELECT id FROM tasks WHERE userId = ? OR assignedTo = ?)';
          params.push(userId, userId);
        }
        db.run(sql, params, function (err) {
          if (err) return reject(err);
          resolve(row);
        });
      })
      .catch(reject);
  });
}

function assignTask(id, assignedTo, ownerId) {
  return new Promise((resolve, reject) => {
    const params = [assignedTo, id, ownerId];
    db.run(
      'UPDATE tasks SET assignedTo = ? WHERE id = ? AND userId = ?',
      params,
      function (err) {
        if (err) return reject(err);
        if (this.changes === 0) return resolve(null);
        getTask(id, ownerId).then(resolve).catch(reject);
      }
    );
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
  listSubtasks,
  createSubtask,
  updateSubtask,
  deleteSubtask,
  getSubtask,
  assignTask,
  createUser,
  getUserByUsername,
  getUserById
};
