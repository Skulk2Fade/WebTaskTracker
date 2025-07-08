'use strict';

function escapeText(text) {
  return String(text || '')
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\r?\n/g, '\\n');
}

function foldLine(line) {
  const bytes = Buffer.from(line);
  if (bytes.length <= 75) return line;
  let out = '';
  let pos = 0;
  while (pos < bytes.length) {
    const chunk = bytes.slice(pos, pos + 75);
    out += chunk.toString();
    pos += 75;
    if (pos < bytes.length) out += '\r\n ';
  }
  return out;
}

function tzOffset(date, tz) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  const parts = fmt.formatToParts(date);
  const get = t => Number(parts.find(p => p.type === t).value);
  const asUtc = Date.UTC(
    get('year'),
    get('month') - 1,
    get('day'),
    get('hour'),
    get('minute'),
    get('second')
  );
  return (asUtc - date.getTime()) / 60000;
}

function localToUtc(dateStr, timeStr, tz) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const [hh, mm] = timeStr.split(':').map(Number);
  const asUtc = new Date(Date.UTC(y, m - 1, d, hh, mm));
  const offset = tzOffset(asUtc, tz);
  return new Date(asUtc.getTime() - offset * 60000);
}

function tasksToIcs(tasks, timezone = 'UTC') {
  const cal = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//WebTaskTracker//EN'];
  const stamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  for (const t of tasks) {
    cal.push('BEGIN:VTODO');
    cal.push(foldLine('UID:' + t.id + '@webtasktracker'));
    cal.push('DTSTAMP:' + stamp);
    if (t.dueDate && t.dueTime) {
      const dueUtc = localToUtc(t.dueDate, t.dueTime, timezone);
      const due = dueUtc.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
      cal.push('DUE:' + due);
    } else if (t.dueDate) {
      cal.push('DUE;VALUE=DATE:' + t.dueDate.replace(/-/g, ''));
    }
    if (t.priority) {
      const p = t.priority === 'high' ? 1 : t.priority === 'medium' ? 5 : 9;
      cal.push('PRIORITY:' + p);
    }
    cal.push('STATUS:' + (t.done ? 'COMPLETED' : 'NEEDS-ACTION'));
    cal.push(foldLine('SUMMARY:' + escapeText(t.text)));
    cal.push('END:VTODO');
  }
  cal.push('END:VCALENDAR');
  return cal.map(foldLine).join('\r\n');
}

module.exports = { tasksToIcs };
