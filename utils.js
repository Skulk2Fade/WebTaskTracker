const fs = require('fs');
const path = require('path');
const logger = require('./logger');

function rateLimiter(windowMs, max, name, db) {
  const isTestEnv = process.env.NODE_ENV === 'test';
  return async (req, res, next) => {
    if (isTestEnv) return next();
    try {
      const key = `${name}:${req.ip}`;
      const { count } = await db.incrementRateLimit(key, windowMs);
      if (count > max) {
        return res.status(429).json({ error: 'Too many requests' });
      }
    } catch (err) {
      logger.error({ err }, 'Rate limit error');
    }
    next();
  };
}

// Server-Sent Events
const sseClients = new Map();
function addSseClient(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);
  res.on('close', () => {
    const set = sseClients.get(userId);
    if (set) {
      set.delete(res);
      if (set.size === 0) sseClients.delete(userId);
    }
  });
}
function sendSse(userId, type, data) {
  const set = sseClients.get(userId);
  if (!set) return;
  const payload = `data:${JSON.stringify({ type, ...data })}\n\n`;
  for (const res of set) {
    res.write(payload);
  }
}
function getSseClientIds() {
  return Array.from(sseClients.keys());
}

function formatTemplate(template, vars) {
  if (!template) return null;
  return template.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] || '');
}

const ALLOWED_MIME_TYPES = new Set([
  'text/plain',
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
  'application/octet-stream'
]);

function getDirSize(dir) {
  let size = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const stat = fs.statSync(full);
    if (stat.isFile()) size += stat.size;
    else if (stat.isDirectory()) size += getDirSize(full);
  }
  return size;
}

function getFreeSpace(dir) {
  try {
    const { bavail, bsize } = fs.statfsSync(dir);
    return bavail * bsize;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

function isValidFutureDate(str) {
  if (str === undefined || str === null || str === '') return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
  const date = new Date(str + 'T00:00:00Z');
  if (isNaN(date.getTime())) return false;
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  return date >= today;
}

function isValidTime(str) {
  if (str === undefined || str === null || str === '') return true;
  if (!/^\d{2}:\d{2}$/.test(str)) return false;
  const [h, m] = str.split(':').map(Number);
  return h >= 0 && h < 24 && m >= 0 && m < 60;
}

function isValidFutureDateTime(dateStr, timeStr) {
  if (!isValidFutureDate(dateStr)) return false;
  if (!isValidTime(timeStr)) return false;
  if (!dateStr || !timeStr) return true;
  const due = new Date(dateStr + 'T' + timeStr + ':00Z');
  if (isNaN(due.getTime())) return false;
  const now = new Date();
  return due >= now;
}

function isValidRecurrenceRule(rule) {
  return (
    rule &&
    Number.isInteger(rule.weekday) &&
    rule.weekday >= 0 &&
    rule.weekday <= 6 &&
    Number.isInteger(rule.ordinal) &&
    rule.ordinal >= 1 &&
    rule.ordinal <= 5
  );
}

function nthWeekdayOfMonth(year, month, weekday, ordinal) {
  const first = new Date(Date.UTC(year, month, 1));
  const firstDow = first.getUTCDay();
  let day = 1 + ((7 + weekday - firstDow) % 7) + (ordinal - 1) * 7;
  const dim = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  if (day > dim) return null;
  return new Date(Date.UTC(year, month, day));
}

function getNextRepeatDate(dateStr, interval, rule) {
  if (!dateStr) return null;
  const date = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(date.getTime())) return null;
  if (interval === 'daily') {
    date.setUTCDate(date.getUTCDate() + 1);
  } else if (interval === 'weekly') {
    date.setUTCDate(date.getUTCDate() + 7);
  } else if (interval === 'monthly') {
    date.setUTCMonth(date.getUTCMonth() + 1);
  } else if (interval === 'weekday') {
    date.setUTCDate(date.getUTCDate() + 1);
    const day = date.getUTCDay();
    if (day === 6) {
      date.setUTCDate(date.getUTCDate() + 2);
    } else if (day === 0) {
      date.setUTCDate(date.getUTCDate() + 1);
    }
  } else if (interval === 'last_day') {
    const next = new Date(
      Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 2, 0)
    );
    return next.toISOString().slice(0, 10);
  } else if (interval === 'custom' && rule && isValidRecurrenceRule(rule)) {
    date.setUTCMonth(date.getUTCMonth() + 1);
    const next = nthWeekdayOfMonth(
      date.getUTCFullYear(),
      date.getUTCMonth(),
      rule.weekday,
      rule.ordinal
    );
    if (!next) return null;
    return next.toISOString().slice(0, 10);
  } else {
    return null;
  }
  return date.toISOString().slice(0, 10);
}

function isStrongPassword(pw) {
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw)
  );
}

function isAllowedMimeType(type) {
  return ALLOWED_MIME_TYPES.has(type);
}

function handleError(res, err, message) {
  logger.error(err);
  const body = { error: message };
  if (process.env.NODE_ENV !== 'production') {
    body.details = err.message;
  }
  res.status(500).json(body);
}

module.exports = {
  rateLimiter,
  addSseClient,
  sendSse,
  getSseClientIds,
  formatTemplate,
  ALLOWED_MIME_TYPES,
  getDirSize,
  getFreeSpace,
  isValidFutureDate,
  isValidTime,
  isValidFutureDateTime,
  isValidRecurrenceRule,
  nthWeekdayOfMonth,
  getNextRepeatDate,
  isStrongPassword,
  isAllowedMimeType,
  handleError
};
