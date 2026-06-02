const crypto = require('crypto');

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error('Invalid base32 character');
    bits += value.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function currentTotp(secret, now = Date.now()) {
  const key = base32Decode(secret);
  if (!key.length) throw new Error('OTP secret is empty');
  const step = 30;
  const counter = Math.floor(now / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const codeInt = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return {
    code: String(codeInt % 1000000).padStart(6, '0'),
    secondsRemaining: step - (Math.floor(now / 1000) % step)
  };
}

module.exports = { currentTotp };
