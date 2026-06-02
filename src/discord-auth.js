const crypto = require('crypto');
const config = require('./config');
const db = require('./db');

const DISCORD_API = 'https://discord.com/api/v10';
const DISCORD_AUTH = 'https://discord.com/oauth2/authorize';
const DISCORD_TOKEN = `${DISCORD_API}/oauth2/token`;

function localCallbackUrl(req) {
  const host = req.get('host') || '';
  if (host.startsWith('localhost') || host.startsWith('127.0.0.1')) {
    return 'http://localhost:3000/auth/discord/callback';
  }
  return config.discord.callbackUrl;
}

function discordAvatarUrl(profile) {
  if (!profile.avatar) return '';
  return `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=64`;
}

function sessionUser(user) {
  return {
    id: user.id,
    discordId: user.discord_id,
    username: user.username || user.discord_username,
    globalName: user.global_name || user.discord_global_name || '',
    avatar: user.avatar || user.discord_avatar || '',
    email: user.email || user.discord_email || '',
    role: user.role || 'user',
    subscriptionStatus: user.subscription_status || 'inactive',
    provider: String(user.discord_id || '').startsWith('emergency:') ? 'admin' : 'discord'
  };
}

function authorizationUrl(req) {
  if (!config.discord.configured) {
    throw new Error('Discord OAuth is not configured. Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, and DISCORD_CALLBACK_URL.');
  }
  const state = crypto.randomBytes(24).toString('hex');
  const redirectUri = localCallbackUrl(req);
  req.session.discordOAuthState = state;
  req.session.discordRedirectUri = redirectUri;
  const url = new URL(DISCORD_AUTH);
  url.searchParams.set('client_id', config.discord.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'identify email');
  url.searchParams.set('state', state);
  return url.toString();
}

async function exchangeCode(code, redirectUri) {
  const body = new URLSearchParams({
    client_id: config.discord.clientId,
    client_secret: config.discord.clientSecret,
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri
  });
  const response = await fetch(DISCORD_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error_description || data.error || 'Discord token exchange failed.');
  return data;
}

async function fetchDiscordProfile(accessToken) {
  const response = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Could not fetch Discord profile.');
  return data;
}

async function upsertDiscordUser(profile) {
  const result = await db.query(
    `INSERT INTO users (discord_id, username, global_name, avatar, email, discord_username, discord_global_name, discord_avatar, discord_email, subscription_status, last_login_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $2, $3, $4, $5, 'inactive', NOW(), NOW())
     ON CONFLICT (discord_id) DO UPDATE SET
       username=EXCLUDED.username,
       global_name=EXCLUDED.global_name,
       avatar=EXCLUDED.avatar,
       email=EXCLUDED.email,
       discord_username=EXCLUDED.discord_username,
       discord_global_name=EXCLUDED.discord_global_name,
       discord_avatar=EXCLUDED.discord_avatar,
       discord_email=EXCLUDED.discord_email,
       last_login_at=NOW(),
       updated_at=NOW()
     RETURNING *`,
    [
      profile.id,
      profile.username || profile.global_name || 'discord-user',
      profile.global_name || null,
      discordAvatarUrl(profile) || null,
      profile.email || null
    ]
  );
  const user = result.rows[0];
  await claimFirstOwnerData(user);
  return user;
}

async function upsertEmergencyAdminUser(username) {
  const discordId = `emergency:${username}`;
  const result = await db.query(
    `INSERT INTO users (discord_id, username, discord_username, role, subscription_status, last_login_at, updated_at)
     VALUES ($1, $2, $2, 'admin', 'active', NOW(), NOW())
     ON CONFLICT (discord_id) DO UPDATE SET
       username=EXCLUDED.username,
       discord_username=EXCLUDED.discord_username,
       subscription_status='active',
       last_login_at=NOW(),
       updated_at=NOW()
     RETURNING *`,
    [discordId, username || 'admin']
  );
  return result.rows[0];
}

async function claimFirstOwnerData(user) {
  if (String(user.discord_id || '').startsWith('emergency:')) return;
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const ownership = await client.query(
      `SELECT
        (SELECT COUNT(*)::int FROM users WHERE id <> $1 AND discord_id NOT LIKE 'emergency:%') other_discord_users,
        (SELECT COUNT(*)::int FROM accounts WHERE user_id IS NOT NULL) owned_accounts,
        (SELECT COUNT(*)::int FROM proxies WHERE user_id IS NOT NULL) owned_proxies,
        (SELECT COUNT(*)::int FROM settings WHERE user_id IS NOT NULL) owned_settings,
        (SELECT COUNT(*)::int FROM activity_logs WHERE user_id IS NOT NULL) owned_logs,
        (SELECT COUNT(*)::int FROM accounts WHERE user_id IS NULL) unowned_accounts,
        (SELECT COUNT(*)::int FROM proxies WHERE user_id IS NULL) unowned_proxies,
        (SELECT COUNT(*)::int FROM settings WHERE user_id IS NULL) unowned_settings,
        (SELECT COUNT(*)::int FROM activity_logs WHERE user_id IS NULL) unowned_logs`,
      [user.id]
    );
    const counts = ownership.rows[0];
    const hasOtherDiscordUser = counts.other_discord_users > 0;
    const hasOwner = counts.owned_accounts + counts.owned_proxies + counts.owned_settings + counts.owned_logs > 0;
    const hasUnowned = counts.unowned_accounts + counts.unowned_proxies + counts.unowned_settings + counts.unowned_logs > 0;
    if (hasOtherDiscordUser || hasOwner || !hasUnowned) {
      await client.query('COMMIT');
      return;
    }
    await client.query('UPDATE accounts SET user_id=$1 WHERE user_id IS NULL', [user.id]);
    await client.query('UPDATE proxies SET user_id=$1 WHERE user_id IS NULL', [user.id]);
    await client.query('UPDATE activity_logs SET user_id=$1 WHERE user_id IS NULL', [user.id]);
    await client.query(
      `UPDATE settings s
       SET user_id=$1
       WHERE s.user_id IS NULL
         AND NOT EXISTS (
           SELECT 1 FROM settings owned
           WHERE owned.user_id=$1 AND owned.key=s.key
         )`,
      [user.id]
    );
    await client.query(
      `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, message, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        user.id,
        'setup_unowned_data_claimed',
        'user',
        user.id,
        'Setup warning: unowned legacy records were assigned to the first Discord user because no prior owner existed.',
        {
          unowned_accounts: counts.unowned_accounts,
          unowned_proxies: counts.unowned_proxies,
          unowned_settings: counts.unowned_settings,
          unowned_logs: counts.unowned_logs
        }
      ]
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  authorizationUrl,
  exchangeCode,
  fetchDiscordProfile,
  sessionUser,
  upsertDiscordUser,
  upsertEmergencyAdminUser
};
