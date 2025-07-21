const fs = require('fs');
const crypto = require('crypto');
const { createDb } = require('./dbClient');
const { buildSearchClause, matchesTagQuery } = require('./searchUtil');

const db = createDb();
const prepared = {};

function formatTags(tags) {
  if (Array.isArray(tags)) return tags.join(',');
  if (typeof tags === 'string') return tags;
  return null;
}

function parseTags(str) {
  if (!str) return [];
  return str.split(',').filter(t => t);
}

function formatRecurrenceRule(rule) {
  if (!rule) return null;
  return JSON.stringify(rule);
}

function parseRecurrenceRule(str) {
  if (!str) return null;
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    twofaSecret TEXT,
    twofaSecretExpiresAt TEXT,
    emailReminders INTEGER NOT NULL DEFAULT 1,
    emailNotifications INTEGER NOT NULL DEFAULT 1,
    notifySms INTEGER NOT NULL DEFAULT 0,
    phoneNumber TEXT,
    notificationTemplate TEXT,
    pushToken TEXT,
    slackId TEXT,
    teamsId TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    googleId TEXT UNIQUE,
    githubId TEXT UNIQUE,
    failedLoginAttempts INTEGER NOT NULL DEFAULT 0,
    lockUntil TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    dueDate TEXT,
    dueTime TEXT,
    priority TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'todo',
    done INTEGER NOT NULL DEFAULT 0,
    userId INTEGER,
    category TEXT,
    assignedTo INTEGER,
    groupId INTEGER,
    reminderSent INTEGER NOT NULL DEFAULT 0,
    lastReminderDate TEXT,
    repeatInterval TEXT,
    recurrenceRule TEXT,
    tags TEXT
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

  db.run(`CREATE TABLE IF NOT EXISTS statuses (
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

  db.run(`CREATE TABLE IF NOT EXISTS time_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taskId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    minutes INTEGER NOT NULL,
    createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS task_permissions (
    taskId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    canEdit INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(taskId, userId),
    FOREIGN KEY(taskId) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    start INTEGER NOT NULL,
    count INTEGER NOT NULL
  )`);

  // Add indexes to speed up common queries
  db.run('CREATE INDEX IF NOT EXISTS idx_tasks_dueDate ON tasks(dueDate)');
  db.run('CREATE INDEX IF NOT EXISTS idx_tasks_userId ON tasks(userId)');
  db.run('CREATE INDEX IF NOT EXISTS idx_tasks_assignedTo ON tasks(assignedTo)');
  db.run('CREATE INDEX IF NOT EXISTS idx_tasks_text ON tasks(text)');
  db.run('CREATE INDEX IF NOT EXISTS idx_comments_text ON comments(text)');

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
    if (!cols.some(c => c.name === 'status')) {
      db.run("ALTER TABLE tasks ADD COLUMN status TEXT NOT NULL DEFAULT 'todo'");
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
    if (!cols.some(c => c.name === 'recurrenceRule')) {
      db.run('ALTER TABLE tasks ADD COLUMN recurrenceRule TEXT');
    }
    if (!cols.some(c => c.name === 'tags')) {
      db.run('ALTER TABLE tasks ADD COLUMN tags TEXT');
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
    if (!cols.some(c => c.name === 'notifySms')) {
      db.run('ALTER TABLE users ADD COLUMN notifySms INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some(c => c.name === 'phoneNumber')) {
      db.run('ALTER TABLE users ADD COLUMN phoneNumber TEXT');
    }
    if (!cols.some(c => c.name === 'notificationTemplate')) {
      db.run('ALTER TABLE users ADD COLUMN notificationTemplate TEXT');
    }
    if (!cols.some(c => c.name === 'pushToken')) {
      db.run('ALTER TABLE users ADD COLUMN pushToken TEXT');
    }
    if (!cols.some(c => c.name === 'slackId')) {
      db.run('ALTER TABLE users ADD COLUMN slackId TEXT');
    }
    if (!cols.some(c => c.name === 'teamsId')) {
      db.run('ALTER TABLE users ADD COLUMN teamsId TEXT');
    }
    if (!cols.some(c => c.name === 'googleId')) {
      db.run('ALTER TABLE users ADD COLUMN googleId TEXT UNIQUE');
    }
    if (!cols.some(c => c.name === 'githubId')) {
      db.run('ALTER TABLE users ADD COLUMN githubId TEXT UNIQUE');
    }
    if (!cols.some(c => c.name === 'timezone')) {
      db.run("ALTER TABLE users ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC'");
    }
    if (!cols.some(c => c.name === 'twofaSecretExpiresAt')) {
      db.run('ALTER TABLE users ADD COLUMN twofaSecretExpiresAt TEXT');
    }
    if (!cols.some(c => c.name === 'failedLoginAttempts')) {
      db.run('ALTER TABLE users ADD COLUMN failedLoginAttempts INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some(c => c.name === 'lockUntil')) {
      db.run('ALTER TABLE users ADD COLUMN lockUntil TEXT');
    }
  });

  db.get('SELECT COUNT(*) AS c FROM statuses', (err, row) => {
    if (!err && row && row.c === 0) {
      for (const name of ['todo', 'in progress', 'blocked', 'completed']) {
        db.run('INSERT INTO statuses (name) VALUES (?)', [name]);
      }
    }
  });
});

// Prepare commonly used statements for better performance
prepared.insertTask = db.prepare(
  `INSERT INTO tasks (text, dueDate, dueTime, priority, status, done, userId, category, tags, assignedTo, groupId, reminderSent, lastReminderDate, repeatInterval, recurrenceRule)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)`
);
prepared.getTask = db.prepare('SELECT * FROM tasks WHERE id = ?');
prepared.getTaskAuth = db.prepare(
  'SELECT * FROM tasks WHERE id = ? AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))'
);
prepared.insertComment = db.prepare(
  'INSERT INTO comments (taskId, userId, text) VALUES (?, ?, ?)'
);

/**
 * Retrieve tasks matching the provided filters.
 *
 * @param {Object} [options]
 * @param {'high'|'medium'|'low'} [options.priority]
 * @param {boolean} [options.done]
 * @param {string} [options.sort]
 * @param {number} [options.userId]
 * @param {string} [options.category]
 * @param {string[]} [options.categories]
 * @param {string[]} [options.tags]
 * @param {string} [options.tagQuery]
 * @param {string} [options.search]
 * @param {string} [options.startDate]
 * @param {string} [options.endDate]
 * @param {number} [options.limit]
 * @param {number} [options.offset]
 * @returns {Promise<Task[]>}
 */
function listTasks({
  priority,
  done,
  sort,
  userId,
  category,
  categories,
  tags,
  tagQuery,
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
      where.push(
        '(tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))'
      );
      params.push(userId, userId, userId, userId);
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
      const { clause, params: searchParams } = buildSearchClause(search, [
        'tasks.text',
        'comments.text'
      ]);
      if (clause) {
        where.push(`(${clause})`);
        params.push(...searchParams);
      }
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
      let tasksWithSub = await Promise.all(
        rows.map(async r => ({
          ...r,
          tags: parseTags(r.tags),
          recurrenceRule: parseRecurrenceRule(r.recurrenceRule),
          subtasks: await listSubtasks(r.id, userId),
          dependencies: await listDependencies(r.id, userId)
        }))
      );
      if (tags && tags.length) {
        tasksWithSub = tasksWithSub.filter(t =>
          tags.every(tag => t.tags.includes(tag))
        );
      }
      if (tagQuery) {
        tasksWithSub = tasksWithSub.filter(t => matchesTagQuery(t.tags, tagQuery));
      }
      resolve(tasksWithSub);
    });
  });
}

/**
 * Insert a new task into the database.
 *
 * @param {Omit<Task,'id'|'reminderSent'|'lastReminderDate'>} task
 * @returns {Promise<Task>}
 */
function createTask({
  text,
  dueDate,
  dueTime,
  priority = 'medium',
  status = 'todo',
  done = false,
  userId,
  category,
  tags,
  assignedTo,
  groupId,
  repeatInterval,
  recurrenceRule
}) {
  status = status || (done ? 'completed' : 'todo');
  return new Promise((resolve, reject) => {
    prepared.insertTask.run(
      [
        text,
        dueDate,
        dueTime,
        priority,
        status,
        done ? 1 : 0,
        userId,
        category,
        formatTags(tags),
        assignedTo,
        groupId,
        repeatInterval,
        formatRecurrenceRule(recurrenceRule)
      ],
      function (err) {
        if (err) return reject(err);
        resolve({
          id: this.lastID,
          text,
          dueDate,
          dueTime,
          priority,
          status,
          done,
          userId,
          category,
          tags: parseTags(formatTags(tags)),
          assignedTo,
          groupId,
          repeatInterval,
          recurrenceRule,
          lastReminderDate: null
        });
      }
    );
  });
}

/**
 * Retrieve a single task by id.
 *
 * @param {number} id
 * @param {number} [userId]
 * @returns {Promise<Task|null>}
 */
function getTask(id, userId) {
  return new Promise((resolve, reject) => {
    const handler = (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      row.tags = parseTags(row.tags);
      row.recurrenceRule = parseRecurrenceRule(row.recurrenceRule);
      resolve(row);
    };
    if (userId !== undefined) {
      prepared.getTaskAuth.get(id, userId, userId, userId, userId, handler);
    } else {
      prepared.getTask.get(id, handler);
    }
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
    if (fields.status !== undefined) {
      updates.push('status = ?');
      params.push(fields.status);
    }
    if (fields.category !== undefined) {
      updates.push('category = ?');
      params.push(fields.category);
    }
    if (fields.tags !== undefined) {
      updates.push('tags = ?');
      params.push(formatTags(fields.tags));
    }
    if (fields.repeatInterval !== undefined) {
      updates.push('repeatInterval = ?');
      params.push(fields.repeatInterval);
    }
    if (fields.recurrenceRule !== undefined) {
      updates.push('recurrenceRule = ?');
      params.push(formatRecurrenceRule(fields.recurrenceRule));
    }
    if (fields.done !== undefined) {
      updates.push('done = ?');
      params.push(fields.done ? 1 : 0);
      if (fields.status === undefined) {
        updates.push('status = ?');
        params.push(fields.done ? 'completed' : 'todo');
      }
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
      sql += ' AND (userId = ? OR id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
      params.push(userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.all('SELECT filePath FROM attachments WHERE taskId = ? AND filePath IS NOT NULL', [id], (err, files) => {
        if (err) return reject(err);
        const delParams = [id];
        let delSql = 'DELETE FROM tasks WHERE id = ?';
        if (userId !== undefined) {
          delSql += ' AND (userId = ? OR id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
          delParams.push(userId, userId);
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

/**
 * List all subtasks for a task.
 *
 * @param {number} taskId
 * @param {number} [userId]
 * @returns {Promise<Subtask[]>}
 */
function listSubtasks(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql =
      'SELECT subtasks.* FROM subtasks JOIN tasks ON tasks.id = subtasks.taskId WHERE taskId = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
      checkSql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      checkParams.push(userId, userId, userId, userId);
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
      params.push(userId, userId, userId, userId);
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
      params.push(userId, userId, userId, userId);
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

/**
 * List comments for a given task.
 *
 * @param {number} taskId
 * @param {number} [userId]
 * @returns {Promise<Comment[]>}
 */
function listComments(taskId, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql =
      'SELECT comments.*, users.username FROM comments ' +
      'JOIN tasks ON tasks.id = comments.taskId ' +
      'JOIN users ON users.id = comments.userId WHERE comments.taskId = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
    }
    sql += ' ORDER BY comments.createdAt';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

/**
 * Add a comment to a task.
 *
 * @param {number} taskId
 * @param {string} text
 * @param {number} userId
 * @returns {Promise<Comment|null>}
 */
function createComment(taskId, text, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      prepared.insertComment.run([taskId, userId, text], function (err) {
        if (err) return reject(err);
        db.get(
          'SELECT comments.*, users.username FROM comments JOIN users ON users.id = comments.userId WHERE comments.id = ?',
          [this.lastID],
          (err, row) => {
            if (err) return reject(err);
            resolve(row);
          }
        );
      });
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

/**
 * Store an attachment associated with a task.
 *
 * @param {number} taskId
 * @param {{filename: string, mimeType: string, content?: string, filePath?: string}} file
 * @param {number} [userId]
 * @returns {Promise<Attachment|null>}
 */
function createTaskAttachment(taskId, { filename, mimeType, content, filePath }, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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

/**
 * Store an attachment associated with a comment.
 *
 * @param {number} commentId
 * @param {{filename: string, mimeType: string, content?: string, filePath?: string}} file
 * @param {number} [userId]
 * @returns {Promise<Attachment|null>}
 */
function createCommentAttachment(commentId, { filename, mimeType, content, filePath }, userId) {
  return new Promise((resolve, reject) => {
    const params = [commentId];
    let sql =
      'SELECT comments.id, tasks.userId, tasks.assignedTo, tasks.groupId FROM comments JOIN tasks ON tasks.id = comments.taskId WHERE comments.id = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
    db.get(sql, params, async (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      if (userId !== undefined) {
        try {
          const allowedTaskId = row.taskId || row.cTaskId;
          if (!allowedTaskId) return resolve(null);
          const task = await getTask(allowedTaskId, userId);
          if (!task) return resolve(null);
        } catch (e) {
          return reject(e);
        }
      }
      resolve(row);
    });
  });
}

function createTimeEntry(taskId, userId, minutes, actingUserId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (actingUserId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(actingUserId, actingUserId, actingUserId, actingUserId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      db.run(
        'INSERT INTO time_entries (taskId, userId, minutes) VALUES (?, ?, ?)',
        [taskId, userId, minutes],
        function (err2) {
          if (err2) return reject(err2);
          db.get(
            'SELECT * FROM time_entries WHERE id = ?',
            [this.lastID],
            (err3, row2) => {
              if (err3) return reject(err3);
              resolve(row2);
            }
          );
        }
      );
    });
  });
}

function listTimeEntries(taskId, filterUserId, actingUserId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (actingUserId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(actingUserId, actingUserId, actingUserId, actingUserId);
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(null);
      const qParams = [taskId];
      let query =
        'SELECT time_entries.*, users.username FROM time_entries JOIN users ON users.id = time_entries.userId WHERE time_entries.taskId = ?';
      if (filterUserId !== undefined) {
        query += ' AND time_entries.userId = ?';
        qParams.push(filterUserId);
      }
      db.all(query, qParams, (err2, rows) => {
        if (err2) return reject(err2);
        resolve(rows);
      });
    });
  });
}

/**
 * Create a subtask for the given task.
 *
 * @param {number} taskId
 * @param {{text: string, done?: boolean}} subtask
 * @param {number} [userId]
 * @returns {Promise<Subtask|null>}
 */
function createSubtask(taskId, { text, done = false }, userId) {
  return new Promise((resolve, reject) => {
    const params = [taskId];
    let sql = 'SELECT id FROM tasks WHERE id = ?';
    if (userId !== undefined) {
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
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
      sql +=
        ' AND taskId IN (SELECT id FROM tasks WHERE tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
      params.push(userId, userId, userId, userId);
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
          sql +=
            ' AND taskId IN (SELECT id FROM tasks WHERE tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ? AND canEdit = 1))';
          params.push(userId, userId, userId, userId);
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

function setTaskPermission(taskId, userId, canEdit = false) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO task_permissions (taskId, userId, canEdit) VALUES (?, ?, ?)
       ON CONFLICT(taskId, userId) DO UPDATE SET canEdit = excluded.canEdit`,
      [taskId, userId, canEdit ? 1 : 0],
      function (err) {
        if (err) return reject(err);
        resolve({ taskId, userId, canEdit: !!canEdit });
      }
    );
  });
}

function removeTaskPermission(taskId, userId) {
  return new Promise((resolve, reject) => {
    db.run(
      `DELETE FROM task_permissions WHERE taskId = ? AND userId = ?`,
      [taskId, userId],
      function (err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      }
    );
  });
}

function getTaskPermission(taskId, userId) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM task_permissions WHERE taskId = ? AND userId = ?`,
      [taskId, userId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function createUser({
  username,
  password,
  role = 'member',
  twofaSecret = null,
  emailReminders = 1,
  emailNotifications = 1,
  notifySms = 0,
  phoneNumber = null,
  notificationTemplate = null,
  pushToken = null,
  slackId = null,
  teamsId = null,
  googleId = null,
  githubId = null,
  timezone = 'UTC'
}) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (username, password, role, twofaSecret, emailReminders, emailNotifications, notifySms, phoneNumber, notificationTemplate, pushToken, slackId, teamsId, googleId, githubId, timezone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        password,
        role,
        twofaSecret,
        emailReminders,
        emailNotifications,
        notifySms,
        phoneNumber,
        notificationTemplate,
        pushToken,
        slackId,
        teamsId,
        googleId,
        githubId,
        timezone
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
          notifySms,
          phoneNumber,
          notificationTemplate,
          pushToken,
          slackId,
          teamsId,
          googleId,
          githubId,
          timezone
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

function getDueSoonTasks(userId, timezone = 'UTC') {
  return new Promise((resolve, reject) => {
    const now = new Date();
    const dateStr = new Intl.DateTimeFormat('en-CA', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).format(now);
    const timeStr = new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }).format(now);
    const params = [dateStr, dateStr, timeStr, userId, userId, userId, dateStr];
    const sql =
      'SELECT * FROM tasks WHERE dueDate IS NOT NULL AND done = 0 AND (dueDate < ? OR (dueDate = ? AND (dueTime IS NULL OR dueTime <= ?))) AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?)) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?) AND (lastReminderDate IS NULL OR lastReminderDate < ?)';
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
      sql +=
        ' AND (tasks.userId = ? OR tasks.assignedTo = ? OR tasks.groupId IN (SELECT groupId FROM group_members WHERE userId = ?) OR tasks.id IN (SELECT taskId FROM task_permissions WHERE userId = ?))';
      params.push(userId, userId, userId, userId);
    }
    sql += ' ORDER BY task_history.createdAt';
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function createPasswordReset({ userId, token, expiresAt }) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO password_resets (userId, token, expiresAt) VALUES (?, ?, ?)`,
      [userId, hashedToken, expiresAt],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, userId, token, expiresAt, used: 0 });
      }
    );
  });
}

function getPasswordReset(token) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM password_resets WHERE token = ?`,
      [hashedToken],
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

function setUserTwoFactorSecret(id, secret, expiresAt = null) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET twofaSecret = ?, twofaSecretExpiresAt = ? WHERE id = ?`,
      [secret, expiresAt, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function updateUserPreferences(
  id,
  {
    emailReminders,
    emailNotifications,
    notifySms,
    phoneNumber,
    notificationTemplate,
    pushToken,
    slackId,
    teamsId,
    timezone
  }
) {
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
    if (notifySms !== undefined) {
      fields.push('notifySms = ?');
      params.push(notifySms ? 1 : 0);
    }
    if (phoneNumber !== undefined) {
      fields.push('phoneNumber = ?');
      params.push(phoneNumber);
    }
    if (notificationTemplate !== undefined) {
      fields.push('notificationTemplate = ?');
      params.push(notificationTemplate);
    }
    if (pushToken !== undefined) {
      fields.push('pushToken = ?');
      params.push(pushToken);
    }
    if (slackId !== undefined) {
      fields.push('slackId = ?');
      params.push(slackId);
    }
    if (teamsId !== undefined) {
      fields.push('teamsId = ?');
      params.push(teamsId);
    }
    if (timezone !== undefined) {
      fields.push('timezone = ?');
      params.push(timezone);
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

function incrementFailedLoginAttempts(id) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET failedLoginAttempts = failedLoginAttempts + 1 WHERE id = ?`,
      [id],
      function (err) {
        if (err) return reject(err);
        getUserById(id).then(resolve).catch(reject);
      }
    );
  });
}

function resetFailedLoginAttempts(id) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET failedLoginAttempts = 0 WHERE id = ?`,
      [id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function lockAccount(id, until) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET lockUntil = ?, failedLoginAttempts = 0 WHERE id = ?`,
      [until, id],
      function (err) {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function incrementRateLimit(key, windowMs) {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    db.get(
      `SELECT start, count FROM rate_limits WHERE key = ?`,
      [key],
      (err, row) => {
        if (err) return reject(err);
        if (!row || now - row.start > windowMs) {
          db.run(
            `REPLACE INTO rate_limits (key, start, count) VALUES (?, ?, 1)`,
            [key, now],
            err2 => {
              if (err2) return reject(err2);
              resolve({ count: 1 });
            }
          );
        } else {
          const newCount = row.count + 1;
          db.run(
            `UPDATE rate_limits SET count = ? WHERE key = ?`,
            [newCount, key],
            err2 => {
              if (err2) return reject(err2);
              resolve({ count: newCount });
            }
          );
        }
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

function listStatuses() {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM statuses ORDER BY id', (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function createStatus(name) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO statuses (name) VALUES (?)', [name], function (err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, name });
    });
  });
}

function updateStatus(id, name) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE statuses SET name = ? WHERE id = ?',
      [name, id],
      function (err) {
        if (err) return reject(err);
        if (this.changes === 0) return resolve(null);
        resolve({ id, name });
      }
    );
  });
}

function deleteStatus(id) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM statuses WHERE id = ?', [id], function (err) {
      if (err) return reject(err);
      resolve(this.changes > 0);
    });
  });
}

function statusExists(name) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id FROM statuses WHERE name = ?', [name], (err, row) => {
      if (err) return reject(err);
      resolve(!!row);
    });
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
      `SELECT id, username, role, emailReminders, emailNotifications, timezone FROM users`,
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

function getUserReports(userId) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT strftime('%Y-%W', createdAt) AS week, COUNT(*) AS count
       FROM task_history
       WHERE action = 'completed' AND userId = ?
       GROUP BY week
       ORDER BY week DESC
       LIMIT 4`,
      [userId],
      (err, rows) => {
        if (err) return reject(err);
        const completedPerWeek = rows || [];
        db.all(
          `SELECT COALESCE(groups.name, 'Unassigned') AS group, SUM(time_entries.minutes) AS minutes
           FROM time_entries
           JOIN tasks ON tasks.id = time_entries.taskId
           LEFT JOIN groups ON groups.id = tasks.groupId
           WHERE time_entries.userId = ?
           GROUP BY group
           ORDER BY minutes DESC`,
          [userId],
          (err2, rows2) => {
            if (err2) return reject(err2);
            resolve({ completedPerWeek, timePerGroup: rows2 || [] });
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
  createTimeEntry,
  listTimeEntries,
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
  getUserReports,
  createHistory,
  listHistory,
  incrementFailedLoginAttempts,
  resetFailedLoginAttempts,
  lockAccount,
  getUserByGoogleId,
  getUserByGithubId,
  setUserGoogleId,
  setUserGithubId,
  setTaskPermission,
  removeTaskPermission,
  getTaskPermission,
  incrementRateLimit,
  listStatuses,
  createStatus,
  updateStatus,
  deleteStatus,
  statusExists
};
