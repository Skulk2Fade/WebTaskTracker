const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const config = require('./config');
const { getFreeSpace } = require('./utils');

function setupAttachmentDir() {
  if (!config.ATTACHMENT_DIR) return;
  const resolved = path.resolve(config.ATTACHMENT_DIR);
  const publicDir = path.resolve(__dirname, 'public');
  if (resolved.startsWith(publicDir)) {
    logger.warn('ATTACHMENT_DIR should not be inside the public directory');
  }
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  if (config.ATTACHMENT_MIN_SPACE) {
    const free = getFreeSpace(resolved);
    if (free < config.ATTACHMENT_MIN_SPACE) {
      logger.warn(
        `ATTACHMENT_DIR has only ${free} bytes free (< ${config.ATTACHMENT_MIN_SPACE})`
      );
    }
  }
}

module.exports = setupAttachmentDir;
