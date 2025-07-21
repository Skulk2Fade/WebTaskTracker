const db = require('../db');
const { handleError } = require('../utils');
const { requireAdmin } = require('../middleware/auth');

module.exports = function (app) {
  function escapeCsv(val) {
    if (val === undefined || val === null) return '';
    const str = String(val);
    if (/[,"\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
    return str;
  }

  function toCsv(data) {
    const lines = [];
    lines.push('category,avgMinutes');
    for (const row of data.avgCompletionMinutes) {
      lines.push(`${escapeCsv(row.category)},${row.avgMinutes}`);
    }
    lines.push('');
    lines.push('date,completed');
    for (const row of data.completedPerDay) {
      lines.push(`${escapeCsv(row.date)},${row.count}`);
    }
    return lines.join('\n');
  }

  function escapePdfText(str) {
    return str.replace(/[()]/g, x => '\\' + x);
  }

  function toPdf(data) {
    const lines = [];
    lines.push('Average completion minutes per category');
    for (const row of data.avgCompletionMinutes) {
      lines.push(`${row.category}: ${row.avgMinutes.toFixed(2)} min`);
    }
    lines.push('');
    lines.push('Completed tasks per day');
    for (const row of data.completedPerDay) {
      lines.push(`${row.date}: ${row.count}`);
    }
    const text = lines.join('\n');
    const objects = ['%PDF-1.1'];
    const xref = [];
    let offset = objects[0].length + 1;
    const push = (obj) => { xref.push(offset); objects.push(obj); offset += Buffer.byteLength(obj) + 1; };
    push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj');
    push('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj');
    push('3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj');
    push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj');
    const stream = `BT /F1 12 Tf 50 750 Td (${escapePdfText(text)}) Tj ET`;
    push(`5 0 obj\n<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream\nendobj`);
    const xrefStart = offset;
    objects.push('xref');
    objects.push('0 6');
    objects.push('0000000000 65535 f ');
    for (const o of xref) {
      objects.push(String(o).padStart(10, '0') + ' 00000 n ');
    }
    objects.push('trailer\n<< /Root 1 0 R /Size 6 >>');
    objects.push('startxref');
    objects.push(String(xrefStart));
    objects.push('%%EOF');
    return Buffer.from(objects.join('\n'), 'binary');
  }

  app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
    const { startDate, endDate, userId, groupId, format } = req.query;
    try {
      const report = await db.getAdvancedReport({
        startDate,
        endDate,
        userId: userId ? parseInt(userId, 10) : undefined,
        groupId: groupId ? parseInt(groupId, 10) : undefined,
      });
      if (format === 'csv') {
        res.type('text/csv').send(toCsv(report));
      } else if (format === 'pdf') {
        const pdf = toPdf(report);
        res.type('application/pdf').send(pdf);
      } else {
        res.json(report);
      }
    } catch (err) {
      handleError(res, err, 'Failed to load analytics');
    }
  });
};
