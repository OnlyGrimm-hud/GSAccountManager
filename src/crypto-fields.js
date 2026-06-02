const crypto = require('crypto');
const config = require('./config');

function encrypt(value) {
  if (value === undefined || value === null || value === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decrypt(value) {
  if (!value) return '';
  const [version, ivB64, tagB64, encryptedB64] = String(value).split(':');
  if (version !== 'v1' || !ivB64 || !tagB64 || !encryptedB64) return '';
  const decipher = crypto.createDecipheriv('aes-256-gcm', config.encryptionKey, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedB64, 'base64')),
    decipher.final()
  ]).toString('utf8');
}

function mask(value, visible = 3) {
  if (!value) return '';
  const text = String(value);
  if (text.length <= visible) return '*'.repeat(text.length);
  return `${text.slice(0, visible)}${'*'.repeat(Math.min(10, text.length - visible))}`;
}

module.exports = { encrypt, decrypt, mask };
