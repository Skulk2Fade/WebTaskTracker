const crypto = require('crypto');

function generateSecret() {
  return crypto.randomBytes(20).toString('hex');
}

function totpToken(secret, step = 30, counterOffset = 0) {
  const counter = Math.floor(Date.now() / 1000 / step) + counterOffset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'hex'))
    .update(buf)
    .digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyToken(token, secret) {
  for (let i = -1; i <= 1; i++) {
    if (totpToken(secret, 30, i) === String(token)) return true;
  }
  return false;
}

function generateToken(secret) {
  return totpToken(secret);
}

module.exports = { generateSecret, verifyToken, generateToken };
