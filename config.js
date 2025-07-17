const path = require('path');

function requiredStr(name) {
  const val = process.env[name];
  if (!val) {
    throw new Error(`${name} environment variable is required`);
  }
  return val;
}

function str(name, def = '') {
  const val = process.env[name];
  return val !== undefined ? String(val) : def;
}

function num(name, def) {
  const val = process.env[name];
  if (val === undefined) return def;
  const n = parseInt(val, 10);
  if (Number.isNaN(n)) {
    throw new Error(`${name} must be a number`);
  }
  return n;
}

const config = {
  SESSION_SECRET: requiredStr('SESSION_SECRET'),
  PORT: num('PORT', 3000),
  DB_FILE: str('DB_FILE', path.join(__dirname, 'tasks.db')),
  BCRYPT_ROUNDS: num('BCRYPT_ROUNDS', 12),
  DUE_SOON_CHECK_INTERVAL: num('DUE_SOON_CHECK_INTERVAL', 60000),
  DUE_SOON_BATCH_SIZE: num('DUE_SOON_BATCH_SIZE', 50),
  TWO_FA_SECRET_TTL: num('TWO_FA_SECRET_TTL', 10 * 60 * 1000),
  TOTP_STEP: num('TOTP_STEP', 30),
  MAX_ATTACHMENT_SIZE: num('MAX_ATTACHMENT_SIZE', 10 * 1024 * 1024),
  ATTACHMENT_DIR: str('ATTACHMENT_DIR', ''),
  ATTACHMENT_MIN_SPACE: num('ATTACHMENT_MIN_SPACE', 0),
  ATTACHMENT_QUOTA: num('ATTACHMENT_QUOTA', 0),
  GOOGLE_CLIENT_ID: str('GOOGLE_CLIENT_ID', ''),
  GOOGLE_CLIENT_SECRET: str('GOOGLE_CLIENT_SECRET', ''),
  GITHUB_CLIENT_ID: str('GITHUB_CLIENT_ID', ''),
  GITHUB_CLIENT_SECRET: str('GITHUB_CLIENT_SECRET', ''),
  WEBHOOK_URLS: str('WEBHOOK_URLS', ''),
  GOOGLE_SYNC_TOKEN: str('GOOGLE_SYNC_TOKEN', ''),
  GOOGLE_CALENDAR_ID: str('GOOGLE_CALENDAR_ID', ''),
  OUTLOOK_SYNC_TOKEN: str('OUTLOOK_SYNC_TOKEN', ''),
  OUTLOOK_CALENDAR_ID: str('OUTLOOK_CALENDAR_ID', ''),
  SENDGRID_API_KEY: str('SENDGRID_API_KEY', ''),
  SENDGRID_FROM_EMAIL: str('SENDGRID_FROM_EMAIL', ''),
  TWILIO_ACCOUNT_SID: str('TWILIO_ACCOUNT_SID', ''),
  TWILIO_AUTH_TOKEN: str('TWILIO_AUTH_TOKEN', ''),
  TWILIO_FROM_NUMBER: str('TWILIO_FROM_NUMBER', ''),
  FCM_SERVER_KEY: str('FCM_SERVER_KEY', ''),
  SLACK_BOT_TOKEN: str('SLACK_BOT_TOKEN', ''),
  TEAMS_BOT_TOKEN: str('TEAMS_BOT_TOKEN', ''),
};

module.exports = config;
