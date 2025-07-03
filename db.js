const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'tasks.db');
const db = new sqlite3.Database(DB_FILE);

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    twofaSecret TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    dueDate TEXT,
    priority TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    userId INTEGER,
    category TEXT,
    assignedTo INTEGER,
    reminderSent INTEGER NOT NULL DEFAULT 0,
    lastReminderDate TEXT,
    repeatInterval TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS subtasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER NOT NULL,
    text TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    text TEXT NOT NULL,
    createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER,
    commentId INTEGER,
    filename TEXT NOT NULL,
    mimeType TEXT NOT NULL,
    data BLOB NOT NULL,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(commentId) REFERENCES comments(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    token TEXT NOT NULL,
    expiresAt TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS task_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER NOT NULL,
    userId INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
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
    if (!cols.some(c => c.name === 'reminderSent')) {
      db.run('ALTER TABLE tasks ADD COLUMN reminderSent INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some(c => c.name === 'lastReminderDate')) {
      db.run('ALTER TABLE tasks ADD COLUMN lastReminderDate TEXT');
    }
    if (!cols.some(c => c.name === 'repeatInterval')) {
      db.run('ALTER TABLE tasks ADD COLUMN repeatInterval TEXT');
    }
  });

  db.all("PRAGMA table_info(users)", (err, cols) => {
    if (err) return;
    if (!cols.some(c => c.name === 'twofaSecret')) {
      db.run('ALTER TABLE users ADD COLUMN twofaSecret TEXT');
    }
    if (!cols.some(c => c.name === 'role')) {
      db.run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'");
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

function createTask({ text, dueDate, priority = 'medium', done = false, userId, category, assignedTo, repeatInterval }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO tasks (text, dueDate, priority, done, userId, category, assignedTo, reminderSent, lastReminderDate, repeatInterval) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)`,
      [text, dueDate, priority, done ? 1 : 0, userId, category, assignedTo, repeatInterval],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, text, dueDate, priority, done, userId, category, assignedTo, repeatInterval, lastReminderDate: null });
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
      updates.push('reminderSent = 0');
      updates.push('lastReminderDate = NULL');
    }
    if (fields.priority !== undefined) {
      updates.push('priority = ?');
      params.push(fields.priority);
    }
    if (fields.category !== undefined) {
      updates.push('category = ?');
      params.push(fields.category);
    }
    if (fields.repeatInterval !== undefined) {
      updates.push('repeatInterval = ?');
      params.push(fields.repeatInterval);
    }
    if (fields.done !== undefined) {
      updates.push('done = ?');
      params.push(fields.done ? 1 : 0);
      if (!fields.done) {
        updates.push('reminderSent = 0');
        updates.push('lastReminderDate = NULL');
      }
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
    const params = [id];
    let sql = 'SELECT * FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND userId = ?';
      params.push(userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      const delParams = [id];
      let delSql = 'DELETE FROM tasks WHERE id = ?';
      if (userId !== undefined) {
        delSql += ' AND userId = ?';
        delParams.push(userId);
      }
      db.run(delSql, delParams, function (err) {
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

function listComments(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql =
      'SELECT comments.*, users.username FROM comments ' +
      'JOIN tasks ON tasks.id = comments.taskId ' +
      'JOIN users ON users.id = comments.userId WHERE comments.taskId = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    sql += ' ORDER BY comments.createdAt';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function createComment(taskId, text, userId) {
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
        'INSERT INTO comments (taskId, userId, text) VALUES (?, ?, ?)',
        [taskId, userId, text],
        function (err) {
          if (err) return reject(err);
          db.get(
            'SELECT comments.*, users.username FROM comments JOIN users ON users.id = comments.userId WHERE comments.id = ?',
            [this.lastID],
            (err, row) => {
              if (err) return reject(err);
              resolve(row);
            }
          );
        }
      );
    });
  });
}

function deleteComment(id, userId) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT * FROM comments WHERE id = ? AND userId = ?',
      [id, userId],
      (err, row) => {
        if (err) return reject(err);
        if (!row) return resolve(null);
        db.run('DELETE FROM comments WHERE id = ?', [id], function (err) {
          if (err) return reject(err);
          resolve(row);
        });
      }
    );
  });
}

function createTaskAttachment(taskId, { filename, mimeType, content }, userId) {
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
      const data = Buffer.from(content, 'base64');
      db.run(
        'INSERT INTO attachments (taskId, filename, mimeType, data) VALUES (?, ?, ?, ?)',
        [taskId, filename, mimeType, data],
        function (err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, taskId, filename, mimeType });
        }
      );
    });
  });
}

function createCommentAttachment(commentId, { filename, mimeType, content }, userId) {
  return new Promise((resolve, reject) => {
    const params = [commentId];
    let sql =
      'SELECT comments.id, tasks.userId, tasks.assignedTo FROM comments JOIN tasks ON tasks.id = comments.taskId WHERE comments.id = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      const data = Buffer.from(content, 'base64');
      db.run(
        'INSERT INTO attachments (commentId, filename, mimeType, data) VALUES (?, ?, ?, ?)',
        [commentId, filename, mimeType, data],
        function (err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, commentId, filename, mimeType });
        }
      );
    });
  });
}

function listTaskAttachments(taskId, userId) {
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
      db.all(
        'SELECT id, filename, mimeType FROM attachments WHERE taskId = ?',
        [taskId],
        (err, rows) => {
          if (err) return reject(err);
          resolve(rows);
        }
      );
    });
  });
}

function listCommentAttachments(commentId, userId) {
  return new Promise((resolve, reject) => {
    const params = [commentId];
    let sql =
      'SELECT comments.id FROM comments JOIN tasks ON tasks.id = comments.taskId WHERE comments.id = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.all(
        'SELECT id, filename, mimeType FROM attachments WHERE commentId = ?',
        [commentId],
        (err, rows) => {
          if (err) return reject(err);
          resolve(rows);
        }
      );
    });
  });
}

function getAttachment(id, userId) {
  return new Promise((resolve, reject) => {
    const params = [id];
    let sql =
      'SELECT attachments.*, tasks.userId as taskOwner, tasks.assignedTo, comments.taskId as cTaskId FROM attachments ' +
      'LEFT JOIN tasks ON tasks.id = attachments.taskId ' +
      'LEFT JOIN comments ON comments.id = attachments.commentId WHERE attachments.id = ?';
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      if (userId !== undefined) {
        const allowedTaskId = row.taskId || row.cTaskId;
        const allowed =
          (row.taskOwner === userId || row.assignedTo === userId) && allowedTaskId !== null;
        if (!allowed) return resolve(null);
      }
      resolve(row);
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
    const params = [assignedTo, id];
    let sql = 'UPDATE tasks SET assignedTo = ? WHERE id = ?';
    if (ownerId !== undefined) {
      sql += ' AND userId = ?';
      params.push(ownerId);
    }
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      if (this.changes === 0) return resolve(null);
      getTask(id, ownerId).then(resolve).catch(reject);
    });
  });
}

function createUser({ username, password, role = 'member', twofaSecret = null }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (username, password, role, twofaSecret) VALUES (?, ?, ?, ?)`,
      [username, password, role, twofaSecret],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username, password, role, twofaSecret });
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

function getDueSoonTasks(userId) {
  return new Promise((resolve, reject) => {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const limit = today.toISOString().slice(0, 10);
    const params = [limit, userId, userId, limit];
    const sql =
      'SELECT * FROM tasks WHERE dueDate IS NOT NULL AND dueDate <= ? AND done = 0 AND (userId = ? OR assignedTo = ?) AND (lastReminderDate IS NULL OR lastReminderDate < ?)';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      if (!rows || rows.length === 0) return resolve([]);
      const ids = rows.map(r => r.id);
      const placeholders = ids.map(() => '?').join(',');
      db.run(
        `UPDATE tasks SET lastReminderDate = ? WHERE id IN (${placeholders})`,
        [limit, ...ids],
        err2 => {
          if (err2) return reject(err2);
          resolve(rows);
        }
      );
    });
  });
}

function createHistory({ taskId, userId, action, details }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO task_history (taskId, userId, action, details) VALUES (?, ?, ?, ?)`,
      [taskId, userId, action, details],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, taskId, userId, action, details });
      }
    );
  });
}

function listHistory(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql =
      'SELECT task_history.*, users.username FROM task_history ' +
      'JOIN tasks ON tasks.id = task_history.taskId ' +
      'LEFT JOIN users ON users.id = task_history.userId WHERE task_history.taskId = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ?)';
      params.push(userId, userId);
    }
    sql += ' ORDER BY task_history.createdAt';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function createPasswordReset({ userId, token, expiresAt }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO password_resets (userId, token, expiresAt) VALUES (?, ?, ?)`,
      [userId, token, expiresAt],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, userId, token, expiresAt, used: 0 });
      }
    );
  });
}

function getPasswordReset(token) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM password_resets WHERE token = ?`,
      [token],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function markPasswordResetUsed(id) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE password_resets SET used = 1 WHERE id = ?`,
      [id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function updateUserPassword(id, password) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET password = ? WHERE id = ?`,
      [password, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function setUserTwoFactorSecret(id, secret) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET twofaSecret = ? WHERE id = ?`,
      [secret, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function countUsers() {
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
      if (err) return reject(err);
      resolve(row.count);
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
  listComments,
  createComment,
  deleteComment,
  createTaskAttachment,
  createCommentAttachment,
  listTaskAttachments,
  listCommentAttachments,
  getAttachment,
  assignTask,
  createUser,
  getUserByUsername,
  getUserById,
  getDueSoonTasks,
  createPasswordReset,
  getPasswordReset,
  markPasswordResetUsed,
  updateUserPassword,
  setUserTwoFactorSecret,
  countUsers,
  createHistory,
  listHistory
};
