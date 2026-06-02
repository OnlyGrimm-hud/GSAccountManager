const crypto = require('crypto');

const passwordAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

function generatePassword(length = 9) {
  const size = Math.max(4, Math.min(Number(length) || 9, 64));
  let value = '';
  for (let i = 0; i < size; i += 1) {
    value += passwordAlphabet[crypto.randomInt(0, passwordAlphabet.length)];
  }
  return value;
}

module.exports = { generatePassword };
