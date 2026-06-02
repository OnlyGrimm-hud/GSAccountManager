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

const adminUsername = process.env.ADMIN_USERNAME || '';
const adminPassword = process.env.ADMIN_PASSWORD || '';
const adminDiscordIds = String(process.env.ADMIN_DISCORD_IDS || '')
  .split(',')
  .map(item => item.trim())
  .filter(Boolean);
const authMode = (process.env.AUTH_MODE || 'discord').toLowerCase();
const appBaseUrl = (process.env.APP_BASE_URL || '').replace(/\/+$/, '');
const discordCallbackUrl = process.env.DISCORD_CALLBACK_URL || (appBaseUrl ? `${appBaseUrl}/auth/discord/callback` : '');
const discord = {
  clientId: process.env.DISCORD_CLIENT_ID || '',
  clientSecret: process.env.DISCORD_CLIENT_SECRET || '',
  callbackUrl: discordCallbackUrl
};
discord.configured = Boolean(discord.clientId && discord.clientSecret && discord.callbackUrl);

module.exports = {
  appName: process.env.APP_NAME || 'GS Account Manager',
  appBaseUrl,
  authMode,
  port: Number(process.env.PORT || 3000),
  databaseUrl: required('DATABASE_URL'),
  encryptionKey: encryptionKey(),
  sessionSecret: required('SESSION_SECRET'),
  adminUsername,
  adminPassword,
  adminDiscordIds,
  adminDiscordIdSet: new Set(adminDiscordIds),
  adminFallbackEnabled: Boolean(adminUsername && adminPassword),
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  nodeEnv: process.env.NODE_ENV || 'development',
  cookieSecure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  autoMigrate: process.env.AUTO_MIGRATE !== 'false',
  appVersion: pkg.version,
  rootDirectory: process.env.RENDER_ROOT_DIRECTORY || path.basename(path.join(__dirname, '..')),
  discord,
  randomId: () => crypto.randomBytes(16).toString('hex')
};
