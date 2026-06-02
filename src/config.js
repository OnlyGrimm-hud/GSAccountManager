const crypto = require('crypto');
const path = require('path');
require('dotenv').config();
const pkg = require('../package.json');

function required(name) {
  const value = process.env[name];
  if (!value || !String(value).trim()) {
    throw new Error(`${name} is required. Set it in your environment before starting GS Account Manager.`);
  }
  return value;
}

function encryptionKey() {
  const raw = required('ENCRYPTION_KEY').trim();
  let key;
  if (/^[a-f0-9]{64}$/i.test(raw)) key = Buffer.from(raw, 'hex');
  else key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must decode to exactly 32 bytes. Use base64 from crypto.randomBytes(32).');
  }
  return key;
}

module.exports = {
  appName: process.env.APP_NAME || 'GS Account Manager',
  port: Number(process.env.PORT || 3000),
  databaseUrl: required('DATABASE_URL'),
  encryptionKey: encryptionKey(),
  sessionSecret: required('SESSION_SECRET'),
  adminUsername: required('ADMIN_USERNAME'),
  adminPassword: required('ADMIN_PASSWORD'),
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  nodeEnv: process.env.NODE_ENV || 'development',
  cookieSecure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  autoMigrate: process.env.AUTO_MIGRATE !== 'false',
  appVersion: pkg.version,
  rootDirectory: process.env.RENDER_ROOT_DIRECTORY || path.basename(path.join(__dirname, '..')),
  discord: {
    clientId: process.env.DISCORD_CLIENT_ID || '',
    clientSecret: process.env.DISCORD_CLIENT_SECRET || '',
    redirectUri: process.env.DISCORD_REDIRECT_URI || ''
  },
  randomId: () => crypto.randomBytes(16).toString('hex')
};
