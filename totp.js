const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_STEP = parseInt(process.env.TOTP_STEP, 10) || 30;

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const input = str.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const output = [];
  for (const ch of input) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateSecret() {
  return crypto.randomBytes(20).toString('hex');
}

function totpToken(secret, step = TOTP_STEP, counterOffset = 0) {
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

function verifyToken(token, secret, step = TOTP_STEP) {
  for (let i = -1; i <= 1; i++) {
    if (totpToken(secret, step, i) === String(token)) return true;
  }
  return false;
}

function generateToken(secret, step = TOTP_STEP) {
  return totpToken(secret, step);
}

module.exports = {
  generateSecret,
  verifyToken,
  generateToken,
  base32Encode,
  base32Decode,
  TOTP_STEP
};
