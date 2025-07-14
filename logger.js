const levels = { error: 0, warn: 1, info: 2 };
const levelName = process.env.LOG_LEVEL || 'info';
const level = levels[levelName] !== undefined ? levels[levelName] : levels.info;

function log(lvl, args) {
  if (levels[lvl] > level) return;
  const entry = { level: lvl, time: new Date().toISOString() };
  const messages = [];
  for (const arg of args) {
    if (arg instanceof Error) {
      entry.error = { message: arg.message, stack: arg.stack };
    } else if (typeof arg === 'object') {
      Object.assign(entry, arg);
    } else {
      messages.push(String(arg));
    }
  }
  if (messages.length) entry.msg = messages.join(' ');
  const out = JSON.stringify(entry);
  if (lvl === 'error') console.error(out);
  else if (lvl === 'warn') console.warn(out);
  else console.log(out);
}

module.exports = {
  info: (...args) => log('info', args),
  warn: (...args) => log('warn', args),
  error: (...args) => log('error', args)
};
