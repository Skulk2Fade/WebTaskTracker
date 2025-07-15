const { getDirSize, getFreeSpace } = require('../utils');
const { ATTACHMENT_DIR, ATTACHMENT_QUOTA, MAX_ATTACHMENT_SIZE } = require('../config');

const CACHE_DURATION = 5000; // ms
let lastCheck = 0;
let cachedUsed = 0;
let cachedFree = Number.MAX_SAFE_INTEGER;

function refreshStats() {
  if (!ATTACHMENT_DIR) return;
  cachedUsed = getDirSize(ATTACHMENT_DIR);
  cachedFree = getFreeSpace(ATTACHMENT_DIR);
  lastCheck = Date.now();
}

function invalidateAttachmentCache() {
  lastCheck = 0;
}

function checkAttachmentSpace(req, res, next) {
  if (!ATTACHMENT_QUOTA) return next();
  const now = Date.now();
  if (now - lastCheck > CACHE_DURATION) {
    refreshStats();
  }
  if (cachedUsed >= ATTACHMENT_QUOTA || cachedFree < MAX_ATTACHMENT_SIZE) {
    return res.status(507).json({ error: 'Attachment storage full' });
  }
  next();
}

module.exports = {
  checkAttachmentSpace,
  invalidateAttachmentCache
};
