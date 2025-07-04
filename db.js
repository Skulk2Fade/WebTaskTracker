const path = require('path');
const fs = require('fs');
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
    twofaSecret TEXT,
    emailReminders INTEGER NOT NULL DEFAULT 1,
    emailNotifications INTEGER NOT NULL DEFAULT 1,
    googleId TEXT UNIQUE,
    githubId TEXT UNIQUE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    dueDate TEXT,
    dueTime TEXT,
    priority TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    userId INTEGER,
    category TEXT,
    assignedTo INTEGER,
    groupId INTEGER,
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
    data BLOB,
    filePath TEXT,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(commentId) REFERENCES comments(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS task_dependencies (
    taskId INTEGER NOT NULL,
    dependsOn INTEGER NOT NULL,
    PRIMARY KEY(taskId, dependsOn),
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(dependsOn) REFERENCES tasks(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    groupId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    PRIMARY KEY(groupId, userId),
    FOREIGN KEY(groupId) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
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
    if (!cols.some(c => c.name === 'groupId')) {
      db.run('ALTER TABLE tasks ADD COLUMN groupId INTEGER');
    }
    if (!cols.some(c => c.name === 'dueTime')) {
      db.run('ALTER TABLE tasks ADD COLUMN dueTime TEXT');
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
    if (!cols.some(c => c.name === 'emailReminders')) {
      db.run('ALTER TABLE users ADD COLUMN emailReminders INTEGER NOT NULL DEFAULT 1');
    }
    if (!cols.some(c => c.name === 'emailNotifications')) {
      db.run('ALTER TABLE users ADD COLUMN emailNotifications INTEGER NOT NULL DEFAULT 1');
    }
    if (!cols.some(c => c.name === 'googleId')) {
      db.run('ALTER TABLE users ADD COLUMN googleId TEXT UNIQUE');
    }
    if (!cols.some(c => c.name === 'githubId')) {
      db.run('ALTER TABLE users ADD COLUMN githubId TEXT UNIQUE');
    }
  });
});

function listTasks({
  priority,
  done,
  sort,
  userId,
  category,
  categories,
  search,
  startDate,
  endDate,
  limit,
  offset
} = {}) {
  return new Promise((resolve, reject) => {
    let query =
      'SELECT DISTINCT tasks.* FROM tasks LEFT JOIN comments ON comments.taskId = tasks.id';
    const where = [];
    const params = [];

    if (userId !== undefined) {
      where.push('(userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))');
      params.push(userId, userId, userId);
    }

    if (priority && ['high', 'medium', 'low'].includes(priority)) {
      where.push('priority = ?');
      params.push(priority);
    }

    if (categories && categories.length) {
      where.push(
        'tasks.category IN (' + categories.map(() => '?').join(',') + ')'
      );
      params.push(...categories);
    } else if (category) {
      where.push('tasks.category = ?');
      params.push(category);
    }

    if (startDate) {
      where.push('tasks.dueDate >= ?');
      params.push(startDate);
    }

    if (endDate) {
      where.push('tasks.dueDate <= ?');
      params.push(endDate);
    }

    if (search) {
      where.push('(tasks.text LIKE ? OR comments.text LIKE ?)');
      params.push(`%${search}%`, `%${search}%`);
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

    if (limit !== undefined) {
      query += ' LIMIT ? OFFSET ?';
      params.push(limit, offset || 0);
    }

    db.all(query, params, async (err, rows) => {
      if (err) return reject(err);
      if (!rows) return resolve([]);
      const tasksWithSub = await Promise.all(
        rows.map(async r => ({
          ...r,
          subtasks: await listSubtasks(r.id, userId),
          dependencies: await listDependencies(r.id, userId)
        }))
      );
      resolve(tasksWithSub);
    });
  });
}

function createTask({ text, dueDate, dueTime, priority = 'medium', done = false, userId, category, assignedTo, groupId, repeatInterval }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO tasks (text, dueDate, dueTime, priority, done, userId, category, assignedTo, groupId, reminderSent, lastReminderDate, repeatInterval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)`,
      [text, dueDate, dueTime, priority, done ? 1 : 0, userId, category, assignedTo, groupId, repeatInterval],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, text, dueDate, dueTime, priority, done, userId, category, assignedTo, groupId, repeatInterval, lastReminderDate: null });
      }
    );
  });
}

function getTask(id, userId) {
  return new Promise((resolve, reject) => {
    const params = [id];
    let sql = 'SELECT * FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
    if (fields.dueTime !== undefined) {
      updates.push('dueTime = ?');
      params.push(fields.dueTime);
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
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
      db.all('SELECT filePath FROM attachments WHERE taskId = ? AND filePath IS NOT NULL', [id], (err, files) => {
        if (err) return reject(err);
        const delParams = [id];
        let delSql = 'DELETE FROM tasks WHERE id = ?';
        if (userId !== undefined) {
          delSql += ' AND userId = ?';
          delParams.push(userId);
        }
        db.run(delSql, delParams, function (err) {
          if (err) return reject(err);
          for (const f of files) {
            if (f.filePath) {
              fs.unlink(f.filePath, () => {});
            }
          }
          resolve(row);
        });
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
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
    }
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function listDependencies(taskId, userId) {
  return new Promise((resolve, reject) => {
    const checkParams = [taskId];
    let checkSql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      checkSql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      checkParams.push(userId, userId, userId);
    }
    db.get(checkSql, checkParams, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.all(
        'SELECT dependsOn FROM task_dependencies WHERE taskId = ?',
        [taskId],
        (err2, rows) => {
          if (err2) return reject(err2);
          resolve(rows.map(r => r.dependsOn));
        }
      );
    });
  });
}

function addDependency(taskId, dependsOn, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.get('SELECT id FROM tasks WHERE id = ?', [dependsOn], (err2, row2) => {
        if (err2) return reject(err2);
        if (!row2) return resolve(null);
        db.run(
          'INSERT OR IGNORE INTO task_dependencies (taskId, dependsOn) VALUES (?, ?)',
          [taskId, dependsOn],
          function (err3) {
            if (err3) return reject(err3);
            resolve({ taskId, dependsOn });
          }
        );
      });
    });
  });
}

function removeDependency(taskId, dependsOn, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.run(
        'DELETE FROM task_dependencies WHERE taskId = ? AND dependsOn = ?',
        [taskId, dependsOn],
        function (err2) {
          if (err2) return reject(err2);
          resolve({ taskId, dependsOn });
        }
      );
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
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
        db.all(
          'SELECT filePath FROM attachments WHERE commentId = ? AND filePath IS NOT NULL',
          [id],
          (err, files) => {
            if (err) return reject(err);
            db.run('DELETE FROM comments WHERE id = ?', [id], function (err) {
              if (err) return reject(err);
              for (const f of files) {
                if (f.filePath) {
                  fs.unlink(f.filePath, () => {});
                }
              }
              resolve(row);
            });
          }
        );
      }
    );
  });
}

function createTaskAttachment(taskId, { filename, mimeType, content, filePath }, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      let query, args;
      if (filePath) {
        query =
          'INSERT INTO attachments (taskId, filename, mimeType, filePath) VALUES (?, ?, ?, ?)';
        args = [taskId, filename, mimeType, filePath];
      } else {
        const data = Buffer.from(content, 'base64');
        query =
          'INSERT INTO attachments (taskId, filename, mimeType, data) VALUES (?, ?, ?, ?)';
        args = [taskId, filename, mimeType, data];
      }
      db.run(query, args, function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, taskId, filename, mimeType });
      });
    });
  });
}

function createCommentAttachment(commentId, { filename, mimeType, content, filePath }, userId) {
  return new Promise((resolve, reject) => {
    const params = [commentId];
    let sql =
      'SELECT comments.id, tasks.userId, tasks.assignedTo, tasks.groupId FROM comments JOIN tasks ON tasks.id = comments.taskId WHERE comments.id = ?';
    if (userId !== undefined) {
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      let query, args;
      if (filePath) {
        query =
          'INSERT INTO attachments (commentId, filename, mimeType, filePath) VALUES (?, ?, ?, ?)';
        args = [commentId, filename, mimeType, filePath];
      } else {
        const data = Buffer.from(content, 'base64');
        query =
          'INSERT INTO attachments (commentId, filename, mimeType, data) VALUES (?, ?, ?, ?)';
        args = [commentId, filename, mimeType, data];
      }
      db.run(query, args, function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, commentId, filename, mimeType });
      });
    });
  });
}

function listTaskAttachments(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
    const params = [];
    let sql =
      'SELECT attachments.*, tasks.userId as taskOwner, tasks.assignedTo, tasks.groupId, comments.taskId as cTaskId';
    if (userId !== undefined) {
      sql += ', gm.userId as memberId';
    }
    sql +=
      ' FROM attachments ' +
      'LEFT JOIN tasks ON tasks.id = attachments.taskId ' +
      'LEFT JOIN comments ON comments.id = attachments.commentId ';
    if (userId !== undefined) {
      sql += 'LEFT JOIN group_members gm ON gm.groupId = tasks.groupId AND gm.userId = ? ';
      params.push(userId);
    }
    sql += 'WHERE attachments.id = ?';
    params.push(id);
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      if (userId !== undefined) {
        const allowedTaskId = row.taskId || row.cTaskId;
        const allowed =
          (row.taskOwner === userId || row.assignedTo === userId || row.memberId) && allowedTaskId !== null;
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
      sql += ' AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
      sql += ' AND taskId IN (SELECT id FROM tasks WHERE userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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
          sql += ' AND taskId IN (SELECT id FROM tasks WHERE userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
          params.push(userId, userId, userId);
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

function createUser({
  username,
  password,
  role = 'member',
  twofaSecret = null,
  emailReminders = 1,
  emailNotifications = 1,
  googleId = null,
  githubId = null
}) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (username, password, role, twofaSecret, emailReminders, emailNotifications, googleId, githubId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        password,
        role,
        twofaSecret,
        emailReminders,
        emailNotifications,
        googleId,
        githubId
      ],
      function (err) {
        if (err) return reject(err);
        resolve({
          id: this.lastID,
          username,
          password,
          role,
          twofaSecret,
          emailReminders,
          emailNotifications,
          googleId,
          githubId
        });
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

function getUserByGoogleId(id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE googleId = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function getUserByGithubId(id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE githubId = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function setUserGoogleId(id, googleId) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET googleId = ? WHERE id = ?`,
      [googleId, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function setUserGithubId(id, githubId) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET githubId = ? WHERE id = ?`,
      [githubId, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function getDueSoonTasks(userId) {
  return new Promise((resolve, reject) => {
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10);
    const timeStr = now.toISOString().slice(11, 16);
    const params = [dateStr, dateStr, timeStr, userId, userId, userId, dateStr];
    const sql =
      'SELECT * FROM tasks WHERE dueDate IS NOT NULL AND done = 0 AND (dueDate < ? OR (dueDate = ? AND (dueTime IS NULL OR dueTime <= ?))) AND (userId = ? OR assignedTo = ? OR groupId IN (SELECT groupId FROM group_members WHERE userId = ?)) AND (lastReminderDate IS NULL OR lastReminderDate < ?)';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      if (!rows || rows.length === 0) return resolve([]);
      const ids = rows.map(r => r.id);
      const placeholders = ids.map(() => '?').join(',');
      db.run(
        `UPDATE tasks SET lastReminderDate = ? WHERE id IN (${placeholders})`,
        [dateStr, ...ids],
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
      sql += ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?))';
      params.push(userId, userId, userId);
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

function updateUserPreferences(id, { emailReminders, emailNotifications }) {
  return new Promise((resolve, reject) => {
    const fields = [];
    const params = [];
    if (emailReminders !== undefined) {
      fields.push('emailReminders = ?');
      params.push(emailReminders ? 1 : 0);
    }
    if (emailNotifications !== undefined) {
      fields.push('emailNotifications = ?');
      params.push(emailNotifications ? 1 : 0);
    }
    if (fields.length === 0) {
      return getUserById(id).then(resolve).catch(reject);
    }
    params.push(id);
    db.run(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      params,
      function (err) {
        if (err) return reject(err);
        getUserById(id).then(resolve).catch(reject);
      }
    );
  });
}

function createGroup(name) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO groups (name) VALUES (?)`,
      [name],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, name });
      }
    );
  });
}

function addUserToGroup(groupId, userId) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT OR IGNORE INTO group_members (groupId, userId) VALUES (?, ?)`,
      [groupId, userId],
      function (err) {
        if (err) return reject(err);
        resolve({ groupId, userId });
      }
    );
  });
}

function listUserGroups(userId) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT groups.id, groups.name FROM groups JOIN group_members ON group_members.groupId = groups.id WHERE group_members.userId = ?`,
      [userId],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
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

function listUsers() {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT id, username, role, emailReminders, emailNotifications FROM users`,
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function deleteUser(id) {
  return new Promise((resolve, reject) => {
    db.run(`DELETE FROM users WHERE id = ?`, [id], function (err) {
      if (err) return reject(err);
      resolve(this.changes > 0);
    });
  });
}

function listActivity(limit = 100) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT task_history.*, tasks.text as taskText, users.username FROM task_history
       LEFT JOIN tasks ON tasks.id = task_history.taskId
       LEFT JOIN users ON users.id = task_history.userId
       ORDER BY task_history.createdAt DESC
       LIMIT ?`,
      [limit],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function getStats() {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT
         (SELECT COUNT(*) FROM users) AS users,
         (SELECT COUNT(*) FROM tasks) AS tasks,
         (SELECT COUNT(*) FROM tasks WHERE done = 1) AS completed`,
      (err, row) => {
        if (err) return reject(err);
        resolve(row);
      }
    );
  });
}

function getReports() {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT strftime('%Y-%W', createdAt) AS week, COUNT(*) AS count
       FROM task_history
       WHERE action = 'completed'
       GROUP BY week
       ORDER BY week DESC
       LIMIT 4`,
      (err, rows) => {
        if (err) return reject(err);
        const completedPerWeek = rows || [];
        db.get(
          `SELECT COUNT(*) AS overdue
           FROM tasks
           WHERE done = 0
             AND dueDate IS NOT NULL
             AND (dueDate < DATE('now') OR (dueDate = DATE('now') AND (dueTime IS NULL OR dueTime <= TIME('now'))))`,
          (err2, row2) => {
            if (err2) return reject(err2);
            resolve({ completedPerWeek, overdue: row2.overdue });
          }
        );
      }
    );
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
  listDependencies,
  addDependency,
  removeDependency,
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
  updateUserPreferences,
  createGroup,
  addUserToGroup,
  listUserGroups,
  countUsers,
  listUsers,
  deleteUser,
  listActivity,
  getStats,
  getReports,
  createHistory,
  listHistory,
  getUserByGoogleId,
  getUserByGithubId,
  setUserGoogleId,
  setUserGithubId
};
