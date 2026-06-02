CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  discord_id TEXT UNIQUE NOT NULL,
  username TEXT,
  global_name TEXT,
  avatar TEXT,
  email TEXT,
  discord_username TEXT NOT NULL,
  discord_global_name TEXT,
  discord_avatar TEXT,
  discord_email TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  subscription_status TEXT NOT NULL DEFAULT 'inactive',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  disabled_by_user_id BIGINT
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT NOT NULL DEFAULT 'inactive';
ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS global_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_global_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_avatar TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_by_user_id BIGINT;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
    ALTER TABLE users DROP CONSTRAINT users_role_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_subscription_status_check') THEN
    ALTER TABLE users DROP CONSTRAINT users_subscription_status_check;
  END IF;
END $$;

UPDATE users SET username = discord_username WHERE username IS NULL;
UPDATE users SET global_name = discord_global_name WHERE global_name IS NULL;
UPDATE users SET avatar = discord_avatar WHERE avatar IS NULL;
UPDATE users SET email = discord_email WHERE email IS NULL;
UPDATE users SET role = 'admin' WHERE role = 'owner';
UPDATE users SET role = 'user' WHERE role NOT IN ('admin', 'staff', 'user');
UPDATE users SET subscription_status = 'trial' WHERE subscription_status = 'trialing';
UPDATE users SET subscription_status = 'inactive' WHERE subscription_status IN ('past_due', 'cancelled');
UPDATE users SET subscription_status = 'banned' WHERE subscription_status = 'suspended';
UPDATE users SET subscription_status = 'inactive' WHERE subscription_status NOT IN ('active', 'inactive', 'trial', 'expired', 'banned');
UPDATE users SET disabled_at = COALESCE(disabled_at, NOW()) WHERE subscription_status = 'banned';

CREATE TABLE IF NOT EXISTS proxies (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT,
  proxy_type TEXT NOT NULL DEFAULT 'HTTP',
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
  username_encrypted TEXT,
  password_encrypted TEXT,
  category TEXT,
  country_code TEXT,
  status TEXT NOT NULL DEFAULT 'untested',
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT,
  username TEXT NOT NULL UNIQUE,
  password_encrypted TEXT NOT NULL,
  account_type TEXT NOT NULL DEFAULT 'legacy',
  bank_pin_encrypted TEXT,
  otp_secret_encrypted TEXT,
  display_name TEXT,
  category TEXT,
  country_code TEXT,
  notes TEXT,
  recovery_email_encrypted TEXT,
  recovery_email_password_encrypted TEXT,
  target_email_encrypted TEXT,
  target_email_password_encrypted TEXT,
  jagex_password_encrypted TEXT,
  proxy_id BIGINT,
  status TEXT NOT NULL DEFAULT 'pending',
  legacy_archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE proxies ADD COLUMN IF NOT EXISTS user_id BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS user_id BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS legacy_login TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS legacy_password_encrypted TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email_password_encrypted TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS jagex_email_encrypted TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS jagex_name TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS first_name TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_name TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS birth_month INTEGER;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS birth_day INTEGER;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS birth_year INTEGER;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS assigned_http_proxy_id BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS assigned_socks5_proxy_id BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS credential_status TEXT NOT NULL DEFAULT 'partial';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS upgrade_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email_creation_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS exported_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS login_email_encrypted TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS login_password_encrypted TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS verified TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS membership_status TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS tags TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS private_notes_encrypted TEXT;

UPDATE accounts SET legacy_login = username WHERE legacy_login IS NULL;
UPDATE accounts SET legacy_password_encrypted = password_encrypted WHERE legacy_password_encrypted IS NULL;
UPDATE accounts SET login_email_encrypted = target_email_encrypted WHERE login_email_encrypted IS NULL AND target_email_encrypted IS NOT NULL;
UPDATE accounts SET login_password_encrypted = password_encrypted WHERE login_password_encrypted IS NULL AND password_encrypted IS NOT NULL;
UPDATE accounts SET target_email_encrypted = jagex_email_encrypted WHERE target_email_encrypted IS NULL AND jagex_email_encrypted IS NOT NULL;
UPDATE accounts SET assigned_http_proxy_id = proxy_id WHERE assigned_http_proxy_id IS NULL AND proxy_id IS NOT NULL;
UPDATE accounts SET credential_status = 'ready' WHERE credential_status = 'partial' AND password_encrypted IS NOT NULL AND username IS NOT NULL;
UPDATE accounts SET upgrade_status = 'complete' WHERE upgrade_status = 'pending' AND status = 'upgraded';
UPDATE accounts SET archived_at = legacy_archived_at WHERE archived_at IS NULL AND legacy_archived_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS helper_devices (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  device_name TEXT,
  device_token_hash TEXT NOT NULL,
  helper_version TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS helper_commands (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  helper_device_id BIGINT,
  command_type TEXT NOT NULL,
  account_id BIGINT,
  proxy_id BIGINT,
  status TEXT NOT NULL DEFAULT 'pending',
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS helper_pairing_codes (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_devices (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  device_name TEXT,
  device_token_hash TEXT NOT NULL,
  companion_version TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  allow_screenshots BOOLEAN NOT NULL DEFAULT FALSE,
  last_seen_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  selected_account_id BIGINT,
  selected_proxy_id BIGINT,
  browser_status TEXT NOT NULL DEFAULT 'idle',
  current_url TEXT,
  current_domain TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_client_status (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  process_name TEXT,
  window_title TEXT,
  matched_account_id BIGINT,
  running BOOLEAN NOT NULL DEFAULT TRUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS live_snapshots (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  companion_session_id BIGINT,
  window_title TEXT,
  content_type TEXT NOT NULL DEFAULT 'image/png',
  image_data BYTEA,
  image_size INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_account_type_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_account_type_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_status_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_credential_status_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_credential_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_upgrade_status_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_upgrade_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_email_creation_status_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_email_creation_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_verified_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_verified_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_membership_status_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_membership_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxies_proxy_type_check') THEN
    ALTER TABLE proxies DROP CONSTRAINT proxies_proxy_type_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxies_status_check') THEN
    ALTER TABLE proxies DROP CONSTRAINT proxies_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_devices_status_check') THEN
    ALTER TABLE helper_devices DROP CONSTRAINT helper_devices_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_commands_status_check') THEN
    ALTER TABLE helper_commands DROP CONSTRAINT helper_commands_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_devices_status_check') THEN
    ALTER TABLE companion_devices DROP CONSTRAINT companion_devices_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_sessions_browser_status_check') THEN
    ALTER TABLE companion_sessions DROP CONSTRAINT companion_sessions_browser_status_check;
  END IF;
END $$;

ALTER TABLE accounts
  ADD CONSTRAINT accounts_account_type_check CHECK (account_type IN ('legacy', 'jagex', 'email_only', 'other', 'unknown'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_status_check CHECK (status IN ('available', 'pending', 'in_progress', 'completed', 'upgraded', 'skipped', 'blocked', 'needs_review', 'exported', 'archived', 'banned_temp', 'banned_perm', 'locked', 'invalid', 'unknown'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_credential_status_check CHECK (credential_status IN ('missing', 'partial', 'ready', 'needs_review'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_upgrade_status_check CHECK (upgrade_status IN ('pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_email_creation_status_check CHECK (email_creation_status IN ('pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_verified_check CHECK (verified IN ('yes', 'no', 'unknown'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_membership_status_check CHECK (membership_status IN ('f2p', 'p2p', 'unknown'));
ALTER TABLE proxies
  ADD CONSTRAINT proxies_proxy_type_check CHECK (proxy_type IN ('HTTP', 'SOCKS5'));
ALTER TABLE proxies
  ADD CONSTRAINT proxies_status_check CHECK (status IN ('unchecked', 'working', 'failed', 'banned', 'unknown', 'untested', 'online', 'works', 'blocked', 'review'));
ALTER TABLE helper_devices
  ADD CONSTRAINT helper_devices_status_check CHECK (status IN ('connected', 'disconnected', 'revoked'));
ALTER TABLE helper_commands
  ADD CONSTRAINT helper_commands_status_check CHECK (status IN ('pending', 'accepted', 'running', 'completed', 'failed', 'cancelled'));
ALTER TABLE companion_devices
  ADD CONSTRAINT companion_devices_status_check CHECK (status IN ('connected', 'disconnected', 'revoked'));
ALTER TABLE companion_sessions
  ADD CONSTRAINT companion_sessions_browser_status_check CHECK (browser_status IN ('idle', 'opening', 'running', 'paused', 'closed', 'error'));

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_proxy_id_fkey') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_assigned_http_proxy_id_fkey') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_assigned_http_proxy_id_fkey
      FOREIGN KEY (assigned_http_proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_assigned_socks5_proxy_id_fkey') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_assigned_socks5_proxy_id_fkey
      FOREIGN KEY (assigned_socks5_proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS activity_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT,
  actor TEXT NOT NULL DEFAULT 'local-admin',
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id BIGINT,
  message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS user_id BIGINT;

CREATE TABLE IF NOT EXISTS import_export_runs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  run_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed',
  item_count INTEGER NOT NULL DEFAULT 0,
  format TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_settings (
  user_id BIGINT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, key)
);

CREATE TABLE IF NOT EXISTS import_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  item_count INTEGER NOT NULL DEFAULT 0,
  format TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS export_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  item_count INTEGER NOT NULL DEFAULT 0,
  format TEXT,
  deleted_after_export BOOLEAN NOT NULL DEFAULT FALSE,
  archived_after_export BOOLEAN NOT NULL DEFAULT FALSE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT,
  actor_user_id BIGINT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id BIGINT,
  message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_devices (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  device_name TEXT,
  device_token_hash TEXT NOT NULL,
  companion_version TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  allow_screenshots BOOLEAN NOT NULL DEFAULT FALSE,
  last_seen_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  selected_account_id BIGINT,
  selected_proxy_id BIGINT,
  browser_status TEXT NOT NULL DEFAULT 'idle',
  current_url TEXT,
  current_domain TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_client_status (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  process_name TEXT,
  window_title TEXT,
  matched_account_id BIGINT,
  running BOOLEAN NOT NULL DEFAULT TRUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS live_snapshots (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  companion_session_id BIGINT,
  window_title TEXT,
  content_type TEXT NOT NULL DEFAULT 'image/png',
  image_data BYTEA,
  image_size INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settings (
  user_id BIGINT,
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE settings ADD COLUMN IF NOT EXISTS user_id BIGINT;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
    ALTER TABLE users DROP CONSTRAINT users_role_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_subscription_status_check') THEN
    ALTER TABLE users DROP CONSTRAINT users_subscription_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_username_key') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_username_key;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'settings_pkey') THEN
    ALTER TABLE settings DROP CONSTRAINT settings_pkey;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'staff', 'admin'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_subscription_status_check') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_subscription_status_check CHECK (subscription_status IN ('inactive', 'active', 'trial', 'expired', 'banned'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_user_username_unique') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_user_username_unique UNIQUE (user_id, username);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'settings_user_key_unique') THEN
    ALTER TABLE settings
      ADD CONSTRAINT settings_user_key_unique UNIQUE (user_id, key);
  END IF;
END $$;

INSERT INTO settings (key, value)
SELECT defaults.key, defaults.value
FROM (VALUES
  ('app_name', 'GS Account Manager'),
  ('default_account_type', 'legacy'),
  ('default_proxy_type', 'HTTP'),
  ('default_email_provider', 'Outlook'),
  ('email_signup_url', 'https://signup.live.com/'),
  ('email_signin_url', 'https://outlook.live.com/'),
  ('account_settings_url', 'https://account.jagex.com/'),
  ('upgrade_url', 'https://account.jagex.com/'),
  ('password_length', '9'),
  ('max_accounts_per_proxy', '5'),
  ('preferred_export_format', 'legacy_user_pass'),
  ('export_format_default', 'legacy_user_pass'),
  ('workflow_mode', 'manual'),
  ('dense_table_mode', 'false'),
  ('screenshot_interval_seconds', '30'),
  ('payment_method_ltc_enabled', 'false'),
  ('payment_method_btc_enabled', 'false'),
  ('payment_method_eth_enabled', 'false'),
  ('manual_admin_activation_enabled', 'true'),
  ('export_behavior_default', 'keep'),
  ('mask_sensitive_values', 'true'),
  ('otp_refresh_interval', '30'),
  ('require_helper_for_proxy_actions', 'true'),
  ('allow_website_only_browser_open', 'true'),
  ('warn_before_opening_without_helper', 'true'),
  ('require_confirmation_before_direct_open', 'true'),
  ('show_proxy_mode_before_open', 'true'),
  ('enable_assisted_fill_buttons', 'false'),
  ('theme_name', 'Premium Dark'),
  ('app_version', '0.1.0')
) AS defaults(key, value)
WHERE NOT EXISTS (
  SELECT 1 FROM settings s
  WHERE s.user_id IS NULL AND s.key = defaults.key
);

CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON users(subscription_status);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(account_type);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category);
CREATE INDEX IF NOT EXISTS idx_accounts_proxy ON accounts(proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_http_proxy ON accounts(assigned_http_proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_upgrade_status ON accounts(upgrade_status);
CREATE INDEX IF NOT EXISTS idx_accounts_exported_at ON accounts(exported_at);
CREATE INDEX IF NOT EXISTS idx_accounts_archived_at ON accounts(archived_at);
CREATE INDEX IF NOT EXISTS idx_proxies_user ON proxies(user_id);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);
CREATE INDEX IF NOT EXISTS idx_settings_user ON settings(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_import_export_runs_user ON import_export_runs(user_id);
CREATE INDEX IF NOT EXISTS idx_import_export_runs_created ON import_export_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_settings_user ON user_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_import_logs_user ON import_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_export_logs_user ON export_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_companion_devices_user ON companion_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_companion_devices_status ON companion_devices(status);
CREATE INDEX IF NOT EXISTS idx_companion_sessions_user ON companion_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_companion_client_status_user ON companion_client_status(user_id);
CREATE INDEX IF NOT EXISTS idx_live_snapshots_user ON live_snapshots(user_id);
CREATE INDEX IF NOT EXISTS idx_helper_devices_user ON helper_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_helper_devices_status ON helper_devices(status);
CREATE INDEX IF NOT EXISTS idx_helper_commands_user ON helper_commands(user_id);
CREATE INDEX IF NOT EXISTS idx_helper_commands_device ON helper_commands(helper_device_id);
CREATE INDEX IF NOT EXISTS idx_helper_commands_status ON helper_commands(status);
CREATE INDEX IF NOT EXISTS idx_helper_pairing_codes_user ON helper_pairing_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_helper_pairing_codes_expires ON helper_pairing_codes(expires_at);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_user_id_fkey') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxies_user_id_fkey') THEN
    ALTER TABLE proxies
      ADD CONSTRAINT proxies_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'settings_user_id_fkey') THEN
    ALTER TABLE settings
      ADD CONSTRAINT settings_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'activity_logs_user_id_fkey') THEN
    ALTER TABLE activity_logs
      ADD CONSTRAINT activity_logs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_disabled_by_user_id_fkey') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_disabled_by_user_id_fkey
      FOREIGN KEY (disabled_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'import_export_runs_user_id_fkey') THEN
    ALTER TABLE import_export_runs
      ADD CONSTRAINT import_export_runs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_settings_user_id_fkey') THEN
    ALTER TABLE user_settings
      ADD CONSTRAINT user_settings_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'import_logs_user_id_fkey') THEN
    ALTER TABLE import_logs
      ADD CONSTRAINT import_logs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'export_logs_user_id_fkey') THEN
    ALTER TABLE export_logs
      ADD CONSTRAINT export_logs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_logs_user_id_fkey') THEN
    ALTER TABLE audit_logs
      ADD CONSTRAINT audit_logs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_logs_actor_user_id_fkey') THEN
    ALTER TABLE audit_logs
      ADD CONSTRAINT audit_logs_actor_user_id_fkey
      FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_devices_user_id_fkey') THEN
    ALTER TABLE companion_devices
      ADD CONSTRAINT companion_devices_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_sessions_user_id_fkey') THEN
    ALTER TABLE companion_sessions
      ADD CONSTRAINT companion_sessions_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_sessions_device_id_fkey') THEN
    ALTER TABLE companion_sessions
      ADD CONSTRAINT companion_sessions_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_sessions_account_id_fkey') THEN
    ALTER TABLE companion_sessions
      ADD CONSTRAINT companion_sessions_account_id_fkey
      FOREIGN KEY (selected_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_sessions_proxy_id_fkey') THEN
    ALTER TABLE companion_sessions
      ADD CONSTRAINT companion_sessions_proxy_id_fkey
      FOREIGN KEY (selected_proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_client_status_user_id_fkey') THEN
    ALTER TABLE companion_client_status
      ADD CONSTRAINT companion_client_status_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_client_status_device_id_fkey') THEN
    ALTER TABLE companion_client_status
      ADD CONSTRAINT companion_client_status_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_client_status_account_id_fkey') THEN
    ALTER TABLE companion_client_status
      ADD CONSTRAINT companion_client_status_account_id_fkey
      FOREIGN KEY (matched_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'live_snapshots_user_id_fkey') THEN
    ALTER TABLE live_snapshots
      ADD CONSTRAINT live_snapshots_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'live_snapshots_device_id_fkey') THEN
    ALTER TABLE live_snapshots
      ADD CONSTRAINT live_snapshots_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'live_snapshots_session_id_fkey') THEN
    ALTER TABLE live_snapshots
      ADD CONSTRAINT live_snapshots_session_id_fkey
      FOREIGN KEY (companion_session_id) REFERENCES companion_sessions(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_devices_user_id_fkey') THEN
    ALTER TABLE helper_devices
      ADD CONSTRAINT helper_devices_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_commands_user_id_fkey') THEN
    ALTER TABLE helper_commands
      ADD CONSTRAINT helper_commands_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_commands_device_id_fkey') THEN
    ALTER TABLE helper_commands
      ADD CONSTRAINT helper_commands_device_id_fkey
      FOREIGN KEY (helper_device_id) REFERENCES helper_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_commands_account_id_fkey') THEN
    ALTER TABLE helper_commands
      ADD CONSTRAINT helper_commands_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_commands_proxy_id_fkey') THEN
    ALTER TABLE helper_commands
      ADD CONSTRAINT helper_commands_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'helper_pairing_codes_user_id_fkey') THEN
    ALTER TABLE helper_pairing_codes
      ADD CONSTRAINT helper_pairing_codes_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
DECLARE
  first_admin_user_id BIGINT;
BEGIN
  SELECT id INTO first_admin_user_id
  FROM users
  WHERE role = 'admin'
  ORDER BY created_at ASC, id ASC
  LIMIT 1;

  IF first_admin_user_id IS NOT NULL THEN
    UPDATE accounts SET user_id = first_admin_user_id WHERE user_id IS NULL;
    UPDATE proxies SET user_id = first_admin_user_id WHERE user_id IS NULL;
    UPDATE activity_logs SET user_id = first_admin_user_id WHERE user_id IS NULL AND action <> 'app_started';
    UPDATE settings s
    SET user_id = first_admin_user_id
    WHERE s.user_id IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM settings owned
        WHERE owned.user_id = first_admin_user_id AND owned.key = s.key
      );
  END IF;
END $$;
