'use strict';
const https = require('https');

const googleToken = process.env.GOOGLE_SYNC_TOKEN;
const googleCalendar = process.env.GOOGLE_CALENDAR_ID;
const outlookToken = process.env.OUTLOOK_SYNC_TOKEN;
const outlookCalendar = process.env.OUTLOOK_CALENDAR_ID;

const googleMap = new Map();
const outlookMap = new Map();

function request(opts, data) {
  return new Promise((resolve, reject) => {
    const req = https.request(opts, res => {
      let body = '';
      res.on('data', chunk => (body += chunk));
      res.on('end', () => {
        if (!body) return resolve(null);
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(JSON.stringify(data));
    req.end();
  });
}

async function upsertGoogle(task) {
  if (!googleToken || !googleCalendar) return;
  const id = googleMap.get(task.id);
  const method = id ? 'PATCH' : 'POST';
  const path = `/calendar/v3/calendars/${encodeURIComponent(
    googleCalendar
  )}/events${id ? '/' + id : ''}`;
  const event = {
    summary: task.text
  };
  if (task.dueDate && task.dueTime) {
    const iso = new Date(`${task.dueDate}T${task.dueTime}:00Z`).toISOString();
    event.start = { dateTime: iso };
    event.end = { dateTime: iso };
  } else if (task.dueDate) {
    event.start = { date: task.dueDate };
    event.end = { date: task.dueDate };
  }
  const opts = {
    hostname: 'www.googleapis.com',
    method,
    path,
    headers: {
      Authorization: `Bearer ${googleToken}`,
      'Content-Type': 'application/json'
    }
  };
  const res = await request(opts, event).catch(() => null);
  if (res && res.id) googleMap.set(task.id, res.id);
}

async function removeGoogle(taskId) {
  if (!googleToken || !googleCalendar) return;
  const id = googleMap.get(taskId);
  if (!id) return;
  const opts = {
    hostname: 'www.googleapis.com',
    method: 'DELETE',
    path: `/calendar/v3/calendars/${encodeURIComponent(
      googleCalendar
    )}/events/${id}`,
    headers: {
      Authorization: `Bearer ${googleToken}`
    }
  };
  await request(opts).catch(() => null);
  googleMap.delete(taskId);
}

async function upsertOutlook(task) {
  if (!outlookToken || !outlookCalendar) return;
  const id = outlookMap.get(task.id);
  const method = id ? 'PATCH' : 'POST';
  const path = id
    ? `/v1.0/me/calendars/${encodeURIComponent(outlookCalendar)}/events/${id}`
    : `/v1.0/me/calendars/${encodeURIComponent(outlookCalendar)}/events`;
  const event = {
    subject: task.text
  };
  if (task.dueDate && task.dueTime) {
    const iso = new Date(`${task.dueDate}T${task.dueTime}:00Z`).toISOString();
    event.start = { dateTime: iso, timeZone: 'UTC' };
    event.end = { dateTime: iso, timeZone: 'UTC' };
  } else if (task.dueDate) {
    event.start = { dateTime: task.dueDate, timeZone: 'UTC' };
    event.end = { dateTime: task.dueDate, timeZone: 'UTC' };
  }
  const opts = {
    hostname: 'graph.microsoft.com',
    method,
    path,
    headers: {
      Authorization: `Bearer ${outlookToken}`,
      'Content-Type': 'application/json'
    }
  };
  const res = await request(opts, event).catch(() => null);
  if (res && res.id) outlookMap.set(task.id, res.id);
}

async function removeOutlook(taskId) {
  if (!outlookToken || !outlookCalendar) return;
  const id = outlookMap.get(taskId);
  if (!id) return;
  const opts = {
    hostname: 'graph.microsoft.com',
    method: 'DELETE',
    path: `/v1.0/me/calendars/${encodeURIComponent(outlookCalendar)}/events/${id}`,
    headers: {
      Authorization: `Bearer ${outlookToken}`
    }
  };
  await request(opts).catch(() => null);
  outlookMap.delete(taskId);
}

async function syncTask(task) {
  await Promise.all([upsertGoogle(task), upsertOutlook(task)]).catch(() => {});
}

async function deleteTask(taskId) {
  await Promise.all([removeGoogle(taskId), removeOutlook(taskId)]).catch(() => {});
}

async function syncFromCalendars() {
  // TODO: fetch remote changes and update local tasks
}

module.exports = { syncTask, deleteTask, syncFromCalendars };
