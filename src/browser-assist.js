const db = require('./db');

const commandTypes = Object.freeze({
  OPEN_URL: 'open_url',
  OPEN_EMAIL_SIGNUP: 'open_email_signup',
  OPEN_EMAIL_LOGIN: 'open_email_login',
  OPEN_JAGEX_LOGIN: 'open_jagex_login',
  OPEN_JAGEX_UPGRADE: 'open_jagex_upgrade',
  FILL_VISIBLE_LOGIN_FIELDS: 'fill_visible_login_fields',
  FILL_VISIBLE_EMAIL_FIELDS: 'fill_visible_email_fields',
  FILL_VISIBLE_UPGRADE_FIELDS: 'fill_visible_upgrade_fields',
  COPY_OTP_CODE: 'copy_otp_code',
  BROWSER_BACK: 'browser_back',
  BROWSER_FORWARD: 'browser_forward',
  CLOSE_BROWSER: 'close_browser'
});

async function createOpenUrlCommand(userId, accountId, proxyId, url) {
  const safeUrl = normalizeWebUrl(url);
  const ownedAccountId = await ownedAccount(userId, accountId, false);
  const ownedProxyId = await ownedProxy(userId, proxyId, false);
  return createHelperCommand(userId, commandTypes.OPEN_URL, {
    accountId: ownedAccountId,
    proxyId: ownedProxyId,
    payload: {
      url: safeUrl,
      requires_user_click: true,
      user_stays_in_control: true
    }
  });
}

async function createFillLoginCommand(userId, accountId) {
  return createAccountCommand(userId, accountId, commandTypes.FILL_VISIBLE_LOGIN_FIELDS);
}

async function createFillEmailCommand(userId, accountId) {
  return createAccountCommand(userId, accountId, commandTypes.FILL_VISIBLE_EMAIL_FIELDS);
}

async function createFillUpgradeCommand(userId, accountId) {
  return createAccountCommand(userId, accountId, commandTypes.FILL_VISIBLE_UPGRADE_FIELDS);
}

async function createCopyOtpCommand(userId, accountId) {
  return createAccountCommand(userId, accountId, commandTypes.COPY_OTP_CODE);
}

async function createAccountCommand(userId, accountId, commandType) {
  const ownedAccountId = await ownedAccount(userId, accountId, true);
  return createHelperCommand(userId, commandType, {
    accountId: ownedAccountId,
    proxyId: null,
    payload: {
      requires_user_click: true,
      user_stays_in_control: true
    }
  });
}

async function createHelperCommand(userId, commandType, options = {}) {
  const normalizedUserId = positiveId(userId, 'userId');
  if (!Object.values(commandTypes).includes(commandType)) {
    throw new Error('Unsupported helper command type.');
  }
  const result = await db.query(
    `INSERT INTO helper_commands (user_id, command_type, account_id, proxy_id, status, payload_json)
     VALUES ($1, $2, $3, $4, 'pending', $5)
     RETURNING id, user_id, command_type, account_id, proxy_id, status, created_at`,
    [
      normalizedUserId,
      commandType,
      options.accountId || null,
      options.proxyId || null,
      safePayload(options.payload || {})
    ]
  );
  return result.rows[0];
}

async function ownedAccount(userId, accountId, required) {
  if (!accountId && !required) return null;
  const normalizedUserId = positiveId(userId, 'userId');
  const normalizedAccountId = positiveId(accountId, 'accountId');
  const result = await db.query(
    'SELECT id FROM accounts WHERE id=$1 AND user_id=$2',
    [normalizedAccountId, normalizedUserId]
  );
  if (!result.rows[0]) throw new Error('Account not found for this user.');
  return Number(result.rows[0].id);
}

async function ownedProxy(userId, proxyId, required) {
  if (!proxyId && !required) return null;
  const normalizedUserId = positiveId(userId, 'userId');
  const normalizedProxyId = positiveId(proxyId, 'proxyId');
  const result = await db.query(
    'SELECT id FROM proxies WHERE id=$1 AND user_id=$2',
    [normalizedProxyId, normalizedUserId]
  );
  if (!result.rows[0]) throw new Error('Proxy not found for this user.');
  return Number(result.rows[0].id);
}

function normalizeWebUrl(url) {
  const parsed = new URL(String(url || ''));
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Helper open URL commands only support http and https URLs.');
  }
  parsed.username = '';
  parsed.password = '';
  return parsed.toString();
}

function safePayload(payload) {
  return {
    ...payload,
    sensitive_values_included: false,
    helper_required: true
  };
}

function positiveId(value, name) {
  const id = Number(value);
  if (!Number.isInteger(id) || id <= 0) throw new Error(`${name} must be a positive integer.`);
  return id;
}

module.exports = {
  commandTypes,
  createOpenUrlCommand,
  createFillLoginCommand,
  createFillEmailCommand,
  createFillUpgradeCommand,
  createCopyOtpCommand
};
