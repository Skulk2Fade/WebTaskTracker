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

function tasksToIcs(tasks) {
  const cal = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//WebTaskTracker//EN'];
  const stamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  for (const t of tasks) {
    cal.push('BEGIN:VTODO');
    cal.push(foldLine('UID:' + t.id + '@webtasktracker'));
    cal.push('DTSTAMP:' + stamp);
    if (t.dueDate && t.dueTime) {
      const due = new Date(`${t.dueDate}T${t.dueTime}:00Z`).toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
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
