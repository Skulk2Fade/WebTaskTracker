const path = require('path');
module.exports = {
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  TWO_FA_SECRET_TTL: parseInt(process.env.TWO_FA_SECRET_TTL, 10) || 10 * 60 * 1000,
  MAX_ATTACHMENT_SIZE: parseInt(process.env.MAX_ATTACHMENT_SIZE, 10) || 10 * 1024 * 1024,
  ATTACHMENT_DIR: process.env.ATTACHMENT_DIR,
  ATTACHMENT_MIN_SPACE: parseInt(process.env.ATTACHMENT_MIN_SPACE, 10) || 0,
  ATTACHMENT_QUOTA: parseInt(process.env.ATTACHMENT_QUOTA, 10) || 0
};
