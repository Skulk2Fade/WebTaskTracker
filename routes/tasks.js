const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const email = require('../email');
const sms = require('../sms');
const webhooks = require('../webhooks');
const { tasksToIcs, fromIcs } = require('../icsUtil');
const calendarSync = require('../calendarSync');
const {
  handleError,
  isValidFutureDateTime,
  isValidRecurrenceRule,
  formatTemplate,
  isAllowedMimeType,
  addSseClient,
  sendSse,
  getDirSize,
  getFreeSpace
} = require('../utils');
const {
  requireAuth,
  requireWriter,
  requireAdmin
} = require('../middleware/auth');
const {
  checkAttachmentSpace,
  invalidateAttachmentCache
} = require('../middleware/attachmentQuota');
const {
  MAX_ATTACHMENT_SIZE,
  ATTACHMENT_DIR,
  ATTACHMENT_QUOTA
} = require('../config');

module.exports = function(app) {
  function escapeCsv(val) {
    if (val === undefined || val === null) return '';
    const str = String(val);
    if (/[,"\n]/.test(str)) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  }

  function toCsv(tasks) {
    const header = [
      'text',
      'dueDate',
      'dueTime',
      'priority',
      'done',
      'category',
      'tags',
      'assignedTo',
      'repeatInterval'
    ].join(',');
    const rows = tasks.map(t =>
      [
        escapeCsv(t.text),
        escapeCsv(t.dueDate),
        escapeCsv(t.dueTime),
        escapeCsv(t.priority),
        escapeCsv(t.done ? 1 : 0),
        escapeCsv(t.category),
        escapeCsv(Array.isArray(t.tags) ? t.tags.join(';') : t.tags),
        escapeCsv(t.assignedTo),
        escapeCsv(t.repeatInterval)
      ].join(',')
    );
    return [header, ...rows].join('\n');
  }

  function parseCsvLine(line) {
    const vals = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQ) {
        if (ch === '"') {
          if (line[i + 1] === '"') {
            cur += '"';
            i++;
          } else {
            inQ = false;
          }
        } else {
          cur += ch;
        }
      } else {
        if (ch === '"') {
          inQ = true;
        } else if (ch === ',') {
          vals.push(cur);
          cur = '';
        } else {
          cur += ch;
        }
      }
    }
    vals.push(cur);
    return vals;
  }

  function fromCsv(text) {
    const lines = text.trim().split(/\r?\n/);
    if (lines.length === 0) return [];
    const headers = parseCsvLine(lines[0]);
    const tasks = [];
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const vals = parseCsvLine(lines[i]);
      const obj = {};
      headers.forEach((h, idx) => {
        obj[h] = vals[idx];
      });
      if (obj.tags) {
        obj.tags = obj.tags.split(';').filter(t => t);
      }
      tasks.push(obj);
    }
    return tasks;
  }

  app.get('/api/tasks', requireAuth, async (req, res) => {
    const {
      priority,
      done,
      sort,
      category,
      categories,
      tags,
      tagQuery,
      search,
      startDate,
      endDate,
      page,
      pageSize
    } = req.query;
    const pg = parseInt(page, 10) >= 1 ? parseInt(page, 10) : 1;
    const size = parseInt(pageSize, 10) >= 1 ? parseInt(pageSize, 10) : 20;
    try {
      const tasks = await db.listTasks({
        priority,
        done: done === 'true' ? true : done === 'false' ? false : undefined,
        sort,
        userId: req.session.userId,
        category,
        categories: categories
          ? categories
              .split(',')
              .map(c => c.trim())
              .filter(c => c)
          : undefined,
        tags: tags
          ? tags
              .split(',')
              .map(t => t.trim())
              .filter(t => t)
          : undefined,
        tagQuery,
        search,
        startDate,
        endDate,
        limit: size,
        offset: (pg - 1) * size
      });
      res.json(tasks);
    } catch (err) {
      handleError(res, err, 'Failed to load tasks');
    }
  });

  app.get('/api/tasks/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const task = await db.getTask(id, req.session.userId);
      if (!task) {
        return res.status(404).json({ error: 'Task not found' });
      }
      const [subtasks, dependencies, comments] = await Promise.all([
        db.listSubtasks(id, req.session.userId),
        db.listDependencies(id, req.session.userId),
        db.listComments(id, req.session.userId)
      ]);
      res.json({ ...task, subtasks, dependencies, comments });
    } catch (err) {
      handleError(res, err, 'Failed to load task');
    }
  });

  app.get('/api/tasks/export', requireAuth, async (req, res) => {
    const format = req.query.format === 'csv' ? 'csv' : 'json';
    try {
      const tasks = await db.listTasks({ userId: req.session.userId });
      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="tasks.csv"');
        res.send(toCsv(tasks));
      } else {
        res.setHeader('Content-Disposition', 'attachment; filename="tasks.json"');
        res.json(tasks);
      }
    } catch (err) {
      handleError(res, err, 'Failed to export tasks');
    }
  });

  app.get('/api/tasks/ics', requireAuth, async (req, res) => {
    try {
      const tasks = await db.listTasks({ userId: req.session.userId });
      const user = await db.getUserById(req.session.userId);
      const tz = user && user.timezone ? user.timezone : 'UTC';
      res.setHeader('Content-Type', 'text/calendar');
      res.setHeader('Content-Disposition', 'attachment; filename="tasks.ics"');
      res.send(tasksToIcs(tasks, tz));
    } catch (err) {
      handleError(res, err, 'Failed to export tasks');
    }
  });

  app.post('/api/tasks/import', requireAuth, requireWriter, async (req, res) => {
    const ct = req.headers['content-type'] || '';
    let format = 'json';
    if (ct.includes('csv')) {
      format = 'csv';
    } else if (ct.includes('calendar') || ct.includes('ics')) {
      format = 'ics';
    }
    try {
      let tasks = [];
      if (format === 'csv') {
        tasks = fromCsv(req.body || '');
      } else if (format === 'ics') {
        tasks = fromIcs(req.body || '');
      } else if (Array.isArray(req.body)) {
        tasks = req.body;
      } else if (req.body && Array.isArray(req.body.tasks)) {
        tasks = req.body.tasks;
      }
      const created = [];
      for (const t of tasks) {
        if (!t.text) continue;
        const task = await db.createTask({
          text: t.text,
          dueDate: t.dueDate || null,
          dueTime: t.dueTime || null,
          priority: ['high', 'medium', 'low'].includes(t.priority) ? t.priority : 'medium',
          done: t.done === true || t.done === '1' || t.done === 'true',
          userId: req.session.userId,
          category: t.category || null,
          tags: Array.isArray(t.tags) ? t.tags : typeof t.tags === 'string' ? t.tags.split(';').map(x => x.trim()).filter(x => x) : undefined,
          assignedTo: t.assignedTo || null,
          repeatInterval: t.repeatInterval || null,
          recurrenceRule: t.recurrenceRule || null
        });
        await calendarSync.syncTask(task);
        created.push(task);
      }
      res.status(201).json(created);
    } catch (err) {
      handleError(res, err, 'Failed to import tasks');
    }
  });

  app.get('/api/reminders', requireAuth, async (req, res) => {
    try {
      const user = await db.getUserById(req.session.userId);
      const tz = user && user.timezone ? user.timezone : 'UTC';
      const tasks = await db.getDueSoonTasks(req.session.userId, tz);
      if (user) {
        for (const t of tasks) {
          const dueStr = t.dueTime ? `${t.dueDate} ${t.dueTime}` : t.dueDate;
          const body =
            formatTemplate(user.notificationTemplate, {
              event: 'task_due',
              text: t.text,
              due: dueStr,
              comment: '',
              username: user.username
            }) || `Task "${t.text}" is due on ${dueStr}`;
          if (user.emailReminders) {
            await email.sendEmail(
              `${user.username}@example.com`,
              'Task Reminder',
              body
            );
          }
          if (user.notifySms && user.phoneNumber) {
            await sms.sendSms(user.phoneNumber, body);
          }
        }
      }
      for (const t of tasks) {
        sendSse(req.session.userId, 'task_due', { taskId: t.id, text: t.text, dueDate: t.dueDate, dueTime: t.dueTime });
      }
      res.json(tasks);
    } catch (err) {
      handleError(res, err, 'Failed to load reminders');
    }
  });

  app.post('/api/tasks', requireAuth, requireWriter, async (req, res) => {
    const text = req.body.text;
    const dueDate = req.body.dueDate;
    const dueTime = req.body.dueTime;
    const category = req.body.category;
    const tags = req.body.tags;
    const assignedTo = req.body.assignedTo;
    const groupId = req.body.groupId;
    const repeatInterval = req.body.repeatInterval;
    const recurrenceRule = req.body.recurrenceRule;
    const status = req.body.status || 'todo';
    let priority = req.body.priority || 'medium';
    priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
    if (!text) {
      return res.status(400).json({ error: 'Task text is required' });
    }
    if (dueTime && !dueDate) {
      return res.status(400).json({ error: 'dueTime requires dueDate' });
    }
    if (dueDate && !isValidFutureDateTime(dueDate, dueTime)) {
      return res.status(400).json({ error: 'Invalid due date/time' });
    }
    if (
      repeatInterval !== undefined &&
      repeatInterval !== null &&
      repeatInterval !== '' &&
      !['daily', 'weekly', 'monthly', 'weekday', 'last_day', 'custom'].includes(
        repeatInterval
      )
    ) {
      return res.status(400).json({ error: 'Invalid repeat interval' });
    }
    if (repeatInterval === 'custom' && !isValidRecurrenceRule(recurrenceRule)) {
      return res.status(400).json({ error: 'Invalid recurrence rule' });
    }
    try {
      let assigneeId = assignedTo;
      if (assigneeId !== undefined) {
        const user = await db.getUserById(assigneeId);
        if (!user) return res.status(400).json({ error: 'Assigned user not found' });
      }
      if (groupId !== undefined && groupId !== null) {
        const groups = await db.listUserGroups(req.session.userId);
        if (!groups.some(g => g.id === groupId)) {
          return res.status(400).json({ error: 'Invalid group' });
        }
      }
      const task = await db.createTask({
        text,
        dueDate,
        dueTime,
        priority,
        status,
        category,
        tags: Array.isArray(tags)
          ? tags
          : typeof tags === 'string'
          ? tags.split(',').map(t => t.trim()).filter(t => t)
          : undefined,
        done: false,
        userId: req.session.userId,
        assignedTo: assigneeId,
        groupId,
        repeatInterval,
        recurrenceRule
      });
      await calendarSync.syncTask(task);
      await db.createHistory({
        taskId: task.id,
        userId: req.session.userId,
        action: 'created',
        details: null
      });
      res.status(201).json(task);
    } catch (err) {
      handleError(res, err, 'Failed to save task');
    }
  });

  app.post('/api/tasks/:id/assign', requireAuth, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    const username = req.body.username;
    if (!username) return res.status(400).json({ error: 'Username required' });
    try {
      const user = await db.getUserByUsername(username);
      if (!user) return res.status(400).json({ error: 'User not found' });
      const updated = await db.assignTask(id, user.id);
      if (!updated) return res.status(404).json({ error: 'Task not found' });
      const assignBody =
        formatTemplate(user.notificationTemplate, {
          event: 'task_assigned',
          text: updated.text,
          due: '',
          comment: '',
          username: user.username
        }) || `You have been assigned the task "${updated.text}"`;
      if (user.emailNotifications) {
        await email.sendEmail(
          `${user.username}@example.com`,
          'Task Assigned',
          assignBody
        );
      }
      if (user.notifySms && user.phoneNumber) {
        await sms.sendSms(user.phoneNumber, assignBody);
      }
      await db.createHistory({
        taskId: updated.id,
        userId: req.session.userId,
        action: 'assigned',
        details: user.username
      });
      await webhooks.sendWebhook('task_assigned', {
        taskId: updated.id,
        text: updated.text,
        assignedTo: user.username
      });
      sendSse(user.id, 'task_assigned', { taskId: updated.id, text: updated.text });
      res.json(updated);
    } catch (err) {
      handleError(res, err, 'Failed to assign task');
    }
  });

  app.post('/api/tasks/:id/permissions', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const { username, canEdit } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    try {
      const task = await db.getTask(id);
      if (!task) return res.status(404).json({ error: 'Task not found' });
      const current = await db.getUserById(req.session.userId);
      if (task.userId !== req.session.userId && (!current || current.role !== 'admin')) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const user = await db.getUserByUsername(username);
      if (!user) return res.status(400).json({ error: 'User not found' });
      const perm = await db.setTaskPermission(id, user.id, !!canEdit);
      res.json(perm);
    } catch (err) {
      handleError(res, err, 'Failed to set permission');
    }
  });

  app.delete('/api/tasks/:taskId/permissions/:userId', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const userId = parseInt(req.params.userId);
    try {
      const task = await db.getTask(taskId);
      if (!task) return res.status(404).json({ error: 'Task not found' });
      const current = await db.getUserById(req.session.userId);
      if (task.userId !== req.session.userId && (!current || current.role !== 'admin')) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await db.removeTaskPermission(taskId, userId);
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err, 'Failed to remove permission');
    }
  });

  app.put('/api/tasks/:id', requireAuth, requireWriter, async (req, res) => {
    const id = parseInt(req.params.id);
    const { text, dueDate, dueTime, priority, status, done, category, tags, repeatInterval, recurrenceRule } = req.body;
    if (text !== undefined && !text.trim()) {
      return res.status(400).json({ error: 'Task text cannot be empty' });
    }
    if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
      return res.status(400).json({ error: 'Invalid priority value' });
    }
    if (dueTime && !dueDate) {
      return res.status(400).json({ error: 'dueTime requires dueDate' });
    }
    if (
      dueDate !== undefined &&
      dueDate !== null &&
      dueDate !== '' &&
      !isValidFutureDateTime(dueDate, dueTime)
    ) {
      return res.status(400).json({ error: 'Invalid due date/time' });
    }
    if (
      repeatInterval !== undefined &&
      repeatInterval !== null &&
      repeatInterval !== '' &&
      !['daily', 'weekly', 'monthly', 'weekday', 'last_day', 'custom'].includes(
        repeatInterval
      )
    ) {
      return res.status(400).json({ error: 'Invalid repeat interval' });
    }
    if (repeatInterval === 'custom' && !isValidRecurrenceRule(recurrenceRule)) {
      return res.status(400).json({ error: 'Invalid recurrence rule' });
    }
    try {
      const oldTask = await db.getTask(id, req.session.userId);
      if (!oldTask) {
        return res.status(404).json({ error: 'Task not found' });
      }
      if (done === true) {
        const subs = await db.listSubtasks(id, req.session.userId);
        if (subs.some(s => !s.done)) {
          return res.status(400).json({ error: 'Subtasks not completed' });
        }
        const deps = await db.listDependencies(id, req.session.userId);
        for (const depId of deps) {
          const dep = await db.getTask(depId, req.session.userId);
          if (!dep || !dep.done) {
            return res.status(400).json({ error: 'Dependencies not completed' });
          }
        }
      }
      const updated = await db.updateTask(
        id,
        {
          text,
          dueDate,
          dueTime,
          priority,
          status,
          done,
          category,
          tags: Array.isArray(tags)
            ? tags
            : typeof tags === 'string'
            ? tags.split(',').map(t => t.trim()).filter(t => t)
            : undefined,
          repeatInterval,
          recurrenceRule
        },
        req.session.userId
      );
      if (!updated) {
        return res.status(404).json({ error: 'Task not found' });
      }
      if (done === true && oldTask.repeatInterval) {
        const nextDate = getNextRepeatDate(oldTask.dueDate, oldTask.repeatInterval, oldTask.recurrenceRule);
        if (nextDate) {
          await db.updateTask(
            id,
            {
              done: false,
              dueDate: nextDate
            },
            req.session.userId
          );
        }
      }
      await calendarSync.syncTask(updated);
      if (done === true && !oldTask.done) {
        await db.createHistory({
          taskId: updated.id,
          userId: req.session.userId,
          action: 'completed',
          details: null
        });
        await webhooks.sendWebhook('task_completed', {
          taskId: updated.id,
          text: updated.text
        });
        if (updated.userId) {
          sendSse(updated.userId, 'task_completed', {
            taskId: updated.id,
            text: updated.text
          });
        }
        if (updated.assignedTo && updated.assignedTo !== updated.userId) {
          sendSse(updated.assignedTo, 'task_completed', {
            taskId: updated.id,
            text: updated.text
          });
        }
      } else {
        await db.createHistory({
          taskId: updated.id,
          userId: req.session.userId,
          action: 'updated',
          details: null
        });
      }
      res.json(updated);
    } catch (err) {
      handleError(res, err, 'Failed to save task');
    }
  });

  app.put('/api/tasks/bulk', requireAuth, requireWriter, async (req, res) => {
    const updates = req.body.tasks || [];
    try {
      const tasks = await db.updateTasks(updates, req.session.userId);
      res.json(tasks);
    } catch (err) {
      handleError(res, err, 'Failed to update tasks');
    }
  });

  app.post('/api/tasks/bulk-delete', requireAuth, requireAdmin, async (req, res) => {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    try {
      const deleted = await db.deleteTasks(ids);
      res.json(deleted);
    } catch (err) {
      handleError(res, err, 'Failed to delete tasks');
    }
  });

  app.delete('/api/tasks/:id', requireAuth, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const task = await db.deleteTask(id);
      if (!task) return res.status(404).json({ error: 'Task not found' });
      res.json(task);
    } catch (err) {
      handleError(res, err, 'Failed to save task');
    }
  });

  app.get('/api/tasks/:taskId/subtasks', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    try {
      const subs = await db.listSubtasks(taskId, req.session.userId);
      if (subs === null) return res.status(404).json({ error: 'Task not found' });
      res.json(subs);
    } catch (err) {
      handleError(res, err, 'Failed to load subtasks');
    }
  });

  app.post('/api/tasks/:taskId/subtasks', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const text = req.body.text;
    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Subtask text is required' });
    }
    try {
      const sub = await db.createSubtask(taskId, text, req.session.userId);
      if (!sub) return res.status(404).json({ error: 'Task not found' });
      res.status(201).json(sub);
    } catch (err) {
      handleError(res, err, 'Failed to save subtask');
    }
  });

  app.put('/api/subtasks/:id', requireAuth, requireWriter, async (req, res) => {
    const id = parseInt(req.params.id);
    const { text, done } = req.body;
    if (text !== undefined && !text.trim()) {
      return res.status(400).json({ error: 'Subtask text cannot be empty' });
    }
    try {
      const updated = await db.updateSubtask(id, { text, done }, req.session.userId);
      if (!updated) return res.status(404).json({ error: 'Subtask not found' });
      res.json(updated);
    } catch (err) {
      handleError(res, err, 'Failed to save subtask');
    }
  });

  app.delete('/api/subtasks/:id', requireAuth, requireWriter, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const deleted = await db.deleteSubtask(id, req.session.userId);
      if (!deleted) return res.status(404).json({ error: 'Subtask not found' });
      res.json(deleted);
    } catch (err) {
      handleError(res, err, 'Failed to delete subtask');
    }
  });

  app.get('/api/tasks/:taskId/dependencies', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    try {
      const deps = await db.listDependencies(taskId, req.session.userId);
      if (deps === null) return res.status(404).json({ error: 'Task not found' });
      const tasks = await Promise.all(deps.map(id => db.getTask(id, req.session.userId)));
      res.json(tasks.filter(t => t));
    } catch (err) {
      handleError(res, err, 'Failed to load dependencies');
    }
  });

  app.post('/api/tasks/:taskId/dependencies', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const dependsOn = parseInt(req.body.dependsOn);
    if (!dependsOn) {
      return res.status(400).json({ error: 'dependsOn required' });
    }
    try {
      const dep = await db.addDependency(taskId, dependsOn, req.session.userId);
      if (!dep) return res.status(404).json({ error: 'Task not found' });
      res.status(201).json(dep);
    } catch (err) {
      handleError(res, err, 'Failed to save dependency');
    }
  });

  app.delete('/api/tasks/:taskId/dependencies/:depId', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const depId = parseInt(req.params.depId);
    try {
      const dep = await db.removeDependency(taskId, depId, req.session.userId);
      if (!dep) return res.status(404).json({ error: 'Task not found' });
      res.json(dep);
    } catch (err) {
      handleError(res, err, 'Failed to delete dependency');
    }
  });

  app.get('/api/tasks/:taskId/comments', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    try {
      const comments = await db.listComments(taskId, req.session.userId);
      res.json(comments);
    } catch (err) {
      handleError(res, err, 'Failed to load comments');
    }
  });

  app.post('/api/tasks/:taskId/comments', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const text = req.body.text;
    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Comment text is required' });
    }
    try {
      const comment = await db.createComment(taskId, text, req.session.userId);
      if (!comment) return res.status(404).json({ error: 'Task not found' });
      await db.createHistory({
        taskId: taskId,
        userId: req.session.userId,
        action: 'commented',
        details: text
      });
      const task = await db.getTask(taskId);
      if (task) {
        const recipients = [];
        if (task.userId && task.userId !== req.session.userId) {
          const owner = await db.getUserById(task.userId);
          if (owner) recipients.push(owner);
        }
        if (task.assignedTo && task.assignedTo !== req.session.userId) {
          const assignee = await db.getUserById(task.assignedTo);
          if (assignee) recipients.push(assignee);
        }
        for (const user of recipients) {
          const commentBody =
            formatTemplate(user.notificationTemplate, {
              event: 'task_commented',
              text: task.text,
              due: '',
              comment: text,
              username: user.username
            }) || `A new comment was added to task "${task.text}": ${text}`;
          if (user.emailNotifications) {
            await email.sendEmail(
              `${user.username}@example.com`,
              'New Comment',
              commentBody
            );
          }
          if (user.notifySms && user.phoneNumber) {
            await sms.sendSms(user.phoneNumber, commentBody);
          }
          sendSse(user.id, 'task_commented', { taskId, text });
        }
      }
      await webhooks.sendWebhook('task_commented', {
        taskId,
        commentId: comment.id,
        text
      });
      res.status(201).json(comment);
    } catch (err) {
      handleError(res, err, 'Failed to save comment');
    }
  });

  app.delete('/api/comments/:id', requireAuth, requireWriter, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const deleted = await db.deleteComment(id, req.session.userId);
      if (!deleted) return res.status(404).json({ error: 'Comment not found' });
      res.json(deleted);
    } catch (err) {
      handleError(res, err, 'Failed to delete comment');
    }
  });

  app.get('/api/tasks/:taskId/attachments', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    try {
      const files = await db.listTaskAttachments(taskId, req.session.userId);
      if (files === null) return res.status(404).json({ error: 'Task not found' });
      res.json(files);
    } catch (err) {
      handleError(res, err, 'Failed to load attachments');
    }
  });

  app.post('/api/tasks/:taskId/attachments', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const { filename, mimeType, content } = req.body;
    if (!filename || !mimeType || !content) {
      return res.status(400).json({ error: 'filename, mimeType and content required' });
    }
    if (!isAllowedMimeType(mimeType)) {
      return res.status(400).json({ error: 'Unsupported mime type' });
    }
    if (Buffer.byteLength(content, 'base64') > MAX_ATTACHMENT_SIZE) {
      return res.status(413).json({ error: 'Attachment exceeds size limit' });
    }
    try {
      const att = await db.createTaskAttachment(
        taskId,
        { filename, mimeType, content },
        req.session.userId
      );
      if (!att) return res.status(404).json({ error: 'Task not found' });
      res.status(201).json(att);
    } catch (err) {
      handleError(res, err, 'Failed to save attachment');
    }
  });

  app.post(
    '/api/tasks/:taskId/attachments/upload',
    requireAuth,
    requireWriter,
    checkAttachmentSpace,
    async (req, res) => {
      const taskId = parseInt(req.params.taskId);
      if (!ATTACHMENT_DIR) return res.status(500).json({ error: 'Attachment storage not configured' });
      const filename = req.headers['x-filename'];
      const mimeType = req.headers['content-type'] || 'application/octet-stream';
      if (!filename) return res.status(400).json({ error: 'X-Filename header required' });
      if (!isAllowedMimeType(mimeType)) {
        return res.status(400).json({ error: 'Unsupported mime type' });
      }
      const temp = path.join(ATTACHMENT_DIR, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`);
      const stream = fs.createWriteStream(temp, { mode: 0o600 });
      let uploaded = 0;
      let aborted = false;
    req.on('data', chunk => {
      uploaded += chunk.length;
      if (uploaded > MAX_ATTACHMENT_SIZE && !aborted) {
        aborted = true;
        req.unpipe(stream);
        stream.destroy();
        fs.unlink(temp, () => invalidateAttachmentCache());
        res.status(413).json({ error: 'Attachment exceeds size limit' });
        req.destroy();
      }
    });
    req.pipe(stream);
    stream.on('finish', async () => {
      if (aborted) return;
      if (ATTACHMENT_QUOTA) {
        const used = getDirSize(ATTACHMENT_DIR);
        if (used > ATTACHMENT_QUOTA) {
          fs.unlink(temp, () => {});
          invalidateAttachmentCache();
          return res.status(507).json({ error: 'Attachment quota exceeded' });
        }
      }
      try {
        const att = await db.createTaskAttachment(taskId, { filename, mimeType, filePath: temp }, req.session.userId);
        if (!att) {
          fs.unlink(temp, () => {});
          invalidateAttachmentCache();
          return res.status(404).json({ error: 'Task not found' });
        }
        res.status(201).json(att);
        invalidateAttachmentCache();
      } catch (err) {
        fs.unlink(temp, () => {});
        handleError(res, err, 'Failed to save attachment');
        invalidateAttachmentCache();
      }
    });
    stream.on('error', err => {
      fs.unlink(temp, () => {});
      invalidateAttachmentCache();
      handleError(res, err, 'Failed to write file');
    });
  });

  app.get('/api/attachments/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const att = await db.getAttachment(id, req.session.userId);
      if (!att) return res.status(404).json({ error: 'Attachment not found' });
      res.setHeader('Content-Type', att.mimeType);
      if (att.filePath) {
        res.sendFile(path.resolve(att.filePath));
      } else {
        res.send(att.data);
      }
    } catch (err) {
      handleError(res, err, 'Failed to load attachment');
    }
  });

  app.post('/api/tasks/:taskId/time', requireAuth, requireWriter, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const minutes = parseInt(req.body.minutes);
    if (!Number.isInteger(minutes) || minutes <= 0) {
      return res.status(400).json({ error: 'minutes must be a positive integer' });
    }
    try {
      const entry = await db.createTimeEntry(
        taskId,
        req.session.userId,
        minutes,
        req.session.userId
      );
      if (!entry) return res.status(404).json({ error: 'Task not found' });
      res.status(201).json(entry);
    } catch (err) {
      handleError(res, err, 'Failed to save time entry');
    }
  });

  app.get('/api/tasks/:taskId/time', requireAuth, async (req, res) => {
    const taskId = parseInt(req.params.taskId);
    const filterUser = req.query.userId ? parseInt(req.query.userId) : undefined;
    try {
      const entries = await db.listTimeEntries(
        taskId,
        filterUser,
        req.session.userId
      );
      if (entries === null)
        return res.status(404).json({ error: 'Task not found' });
      res.json(entries);
    } catch (err) {
      handleError(res, err, 'Failed to load time entries');
    }
  });

  app.get('/api/tasks/:id/history', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
      const task = await db.getTask(id, req.session.userId);
      if (!task) {
        return res.status(404).json({ error: 'Task not found' });
      }
      const events = await db.listHistory(id, req.session.userId);
      res.json(events);
    } catch (err) {
      handleError(res, err, 'Failed to load history');
    }
  });
};
