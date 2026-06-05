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
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_tier_id BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_started_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS manually_paid_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_method TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_note TEXT;

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

CREATE TABLE IF NOT EXISTS subscription_tiers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT,
  max_devices INTEGER,
  daily_successful_browser_task_limit INTEGER,
  max_accounts INTEGER,
  max_proxies INTEGER,
  snapshots_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  client_launcher_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  browser_automator_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  price_label TEXT,
  payment_notes TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO subscription_tiers (
  name, slug, description, max_devices, daily_successful_browser_task_limit,
  max_accounts, max_proxies, snapshots_enabled, client_launcher_enabled,
  browser_automator_enabled, price_label, payment_notes, active, sort_order
) VALUES
  ('Starter', 'starter', 'Tier 1 starter plan for basic account/proxy storage, client monitor, and browser automator access.', 1, 50, NULL, NULL, FALSE, FALSE, TRUE, 'Tier 1', 'Payment setup coming soon.', TRUE, 10),
  ('Standard', 'standard', 'Tier 2 plan with two local app devices, live session snapshots, and client launcher foundation.', 2, 200, NULL, NULL, TRUE, TRUE, TRUE, 'Tier 2', 'Payment setup coming soon.', TRUE, 20),
  ('Pro', 'pro', 'Tier 3 plan with higher device, job, snapshot, and automator limits.', 5, 1000, NULL, NULL, TRUE, TRUE, TRUE, 'Tier 3', 'Payment setup coming soon.', TRUE, 30),
  ('Admin / Owner', 'admin-owner', 'Unlimited admin/testing tier.', NULL, NULL, NULL, NULL, TRUE, TRUE, TRUE, 'Admin', 'Admin users bypass limits.', TRUE, 100)
ON CONFLICT (slug) DO UPDATE SET
  name=EXCLUDED.name,
  description=EXCLUDED.description,
  max_devices=EXCLUDED.max_devices,
  daily_successful_browser_task_limit=EXCLUDED.daily_successful_browser_task_limit,
  snapshots_enabled=EXCLUDED.snapshots_enabled,
  client_launcher_enabled=EXCLUDED.client_launcher_enabled,
  browser_automator_enabled=EXCLUDED.browser_automator_enabled,
  price_label=EXCLUDED.price_label,
  payment_notes=EXCLUDED.payment_notes,
  active=EXCLUDED.active,
  sort_order=EXCLUDED.sort_order,
  updated_at=NOW();

UPDATE users
SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE slug='starter')
WHERE subscription_tier_id IS NULL AND role <> 'admin';

UPDATE users
SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE slug='admin-owner')
WHERE role = 'admin' AND subscription_tier_id IS NULL;

CREATE TABLE IF NOT EXISTS browser_task_usage (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  date DATE NOT NULL,
  successful_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, date)
);

CREATE TABLE IF NOT EXISTS download_items (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  category TEXT NOT NULL,
  description TEXT,
  version TEXT,
  download_url TEXT,
  status TEXT NOT NULL DEFAULT 'coming_soon',
  public_notes TEXT,
  admin_notes TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO download_items (title, slug, category, description, version, download_url, status, public_notes, admin_notes, sort_order) VALUES
  ('GS Agent', 'gs-local-app', 'local_app', 'Windows test build for pairing this PC, launching configured clients, monitoring local status, and running visible GS Browser Automator jobs.', '0.1.0', NULL, 'coming_soon', 'Package companion/dist/GS Agent Setup.exe for local testing, then use this Downloads card to serve or link the installer.', 'Set download_url for a hosted installer or package the EXE on the deployment host.', 10),
  ('Browser Runtime / GS Browser Automator', 'browser-runtime', 'browser_runtime', 'Required for browser automation tasks and controlled locally on the user PC by GS Agent.', NULL, NULL, 'coming_soon', 'GS Agent will install or manage the Playwright/Chromium browser runtime locally.', 'No server-side browser runtime is required on Render.', 20),
  ('RuneLite', 'runelite', 'client_tool', 'Optional RuneLite setup link for users who want to monitor or launch RuneLite locally.', NULL, 'https://runelite.net/', 'available', 'Install from the official RuneLite website. GS does not redistribute this installer.', 'Third-party link only; do not bundle.', 30),
  ('Jagex Launcher', 'jagex-launcher', 'client_tool', 'Optional Jagex Launcher setup link.', NULL, 'https://www.jagex.com/en-GB/launcher', 'available', 'Install from the official Jagex website. GS does not redistribute this installer.', 'Third-party link only; do not bundle.', 40),
  ('Official Client', 'official-client', 'client_tool', 'Optional official OSRS client setup link.', NULL, 'https://oldschool.runescape.com/', 'available', 'Use the official Old School RuneScape website for client setup.', 'Third-party link only; do not bundle.', 50),
  ('DreamBot', 'dreambot', 'client_tool', 'Optional DreamBot setup link for local client detection/launch profile configuration.', NULL, 'https://dreambot.org/', 'available', 'Install from DreamBot directly if you use it locally. GS does not redistribute this installer.', 'Third-party link only; do not bundle.', 60),
  ('Custom Client', 'custom-client', 'client_tool', 'Custom local client path configured by the user in GS Agent settings.', NULL, NULL, 'coming_soon', 'Add custom executable paths inside GS Agent settings.', 'Local paths are stored locally, not on the website.', 70),
  ('Setup Guide', 'setup-guide', 'guide', 'GS Agent setup, pairing, client profile, and safety guide.', NULL, NULL, 'coming_soon', 'Setup guide content is being prepared.', 'Add documentation URL when ready.', 80)
ON CONFLICT (slug) DO UPDATE SET
  title=EXCLUDED.title,
  category=EXCLUDED.category,
  description=EXCLUDED.description,
  version=COALESCE(download_items.version, EXCLUDED.version),
  download_url=COALESCE(download_items.download_url, EXCLUDED.download_url),
  status=download_items.status,
  public_notes=EXCLUDED.public_notes,
  admin_notes=EXCLUDED.admin_notes,
  sort_order=EXCLUDED.sort_order,
  updated_at=NOW();

CREATE TABLE IF NOT EXISTS payment_settings (
  id BIGSERIAL PRIMARY KEY,
  method TEXT UNIQUE NOT NULL,
  address_encrypted TEXT,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  public_label TEXT,
  instructions TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO payment_settings (method, enabled, public_label, instructions) VALUES
  ('LTC', FALSE, 'Litecoin', 'Payment setup coming soon.'),
  ('BTC', FALSE, 'Bitcoin', 'Payment setup coming soon.'),
  ('ETH', FALSE, 'Ethereum', 'Payment setup coming soon.')
ON CONFLICT (method) DO UPDATE SET
  public_label=EXCLUDED.public_label,
  instructions=COALESCE(payment_settings.instructions, EXCLUDED.instructions),
  updated_at=NOW();

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
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS max_accounts_per_proxy INTEGER;
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
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS character_type TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS gp_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS platinum_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS wealth_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS ban_status TEXT NOT NULL DEFAULT 'none';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS completed_tutorial BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS total_level INTEGER;

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
  device_install_id_hash TEXT,
  device_role TEXT NOT NULL DEFAULT 'agent_browser',
  companion_version TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  allow_screenshots BOOLEAN NOT NULL DEFAULT FALSE,
  paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  trusted_until_at TIMESTAMPTZ,
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

ALTER TABLE companion_devices ADD COLUMN IF NOT EXISTS device_install_id_hash TEXT;
ALTER TABLE companion_devices ADD COLUMN IF NOT EXISTS device_role TEXT NOT NULL DEFAULT 'agent_browser';
ALTER TABLE companion_devices ADD COLUMN IF NOT EXISTS paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE companion_devices ADD COLUMN IF NOT EXISTS trusted_until_at TIMESTAMPTZ;
UPDATE companion_devices SET device_role='agent_browser' WHERE device_role IS NULL OR device_role = '';
UPDATE companion_devices SET paired_at=created_at WHERE paired_at IS NULL;

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
  device_install_id_hash TEXT,
  device_role TEXT NOT NULL DEFAULT 'agent_browser',
  companion_version TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  allow_screenshots BOOLEAN NOT NULL DEFAULT FALSE,
  paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  trusted_until_at TIMESTAMPTZ,
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

CREATE TABLE IF NOT EXISTS client_profiles (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  client_type TEXT NOT NULL DEFAULT 'custom',
  executable_path_encrypted TEXT,
  launch_args_encrypted TEXT,
  default_account_id BIGINT,
  default_proxy_id BIGINT,
  default_workflow_id BIGINT,
  notes TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS client_instances (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  client_profile_id BIGINT,
  account_id BIGINT,
  proxy_id BIGINT,
  instance_name TEXT,
  process_name TEXT,
  process_id INTEGER,
  window_title TEXT,
  status TEXT NOT NULL DEFAULT 'unknown',
  current_activity TEXT,
  last_seen_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  stopped_at TIMESTAMPTZ,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS client_instance_events (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  client_instance_id BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT,
  safe_metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS client_instance_id BIGINT;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS account_id BIGINT;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS storage_ref TEXT;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS mime_type TEXT;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS width INTEGER;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS height INTEGER;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS file_size INTEGER;
ALTER TABLE live_snapshots ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
UPDATE live_snapshots SET mime_type = content_type WHERE mime_type IS NULL AND content_type IS NOT NULL;
UPDATE live_snapshots SET file_size = image_size WHERE file_size IS NULL AND image_size IS NOT NULL;

ALTER TABLE client_profiles ADD COLUMN IF NOT EXISTS default_account_id BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS combat_level INTEGER;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_stats_sync_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS stats_sync_status TEXT NOT NULL DEFAULT 'never';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS stats_sync_error TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS bank_value BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS wealth_value BIGINT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS wealth_source TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS wealth_updated_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS client_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS client_last_seen_at TIMESTAMPTZ;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS match_confidence TEXT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS match_reason TEXT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS suggested_account_id BIGINT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS client_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS reported_display_name TEXT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS reported_gp_amount BIGINT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS reported_bank_value BIGINT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS reported_wealth_value BIGINT;
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS wealth_source TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE client_instances ADD COLUMN IF NOT EXISTS wealth_updated_at TIMESTAMPTZ;

UPDATE accounts
SET wealth_value = wealth_amount,
    wealth_source = CASE WHEN wealth_source = 'unknown' THEN 'manual' ELSE wealth_source END,
    wealth_updated_at = COALESCE(wealth_updated_at, updated_at)
WHERE wealth_amount > 0 AND (wealth_value IS NULL OR wealth_value = 0);

UPDATE accounts
SET wealth_source = CASE WHEN wealth_source = 'unknown' THEN 'manual' ELSE wealth_source END,
    wealth_updated_at = COALESCE(wealth_updated_at, updated_at)
WHERE gp_amount > 0 AND wealth_updated_at IS NULL;

CREATE TABLE IF NOT EXISTS account_stats (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  account_id BIGINT NOT NULL,
  display_name TEXT NOT NULL,
  total_level INTEGER,
  combat_level INTEGER,
  attack INTEGER,
  strength INTEGER,
  defence INTEGER,
  ranged INTEGER,
  prayer INTEGER,
  magic INTEGER,
  hitpoints INTEGER,
  total_xp BIGINT,
  other_skills JSONB NOT NULL DEFAULT '{}'::jsonb,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source TEXT NOT NULL DEFAULT 'osrs_hiscores',
  status TEXT NOT NULL DEFAULT 'ok',
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflows (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  type TEXT NOT NULL DEFAULT 'custom',
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_steps (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  workflow_id BIGINT NOT NULL,
  step_order INTEGER NOT NULL DEFAULT 1,
  step_type TEXT NOT NULL,
  label TEXT,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  manual_pause BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_runs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  workflow_id BIGINT,
  account_id BIGINT,
  proxy_id BIGINT,
  companion_device_id BIGINT,
  status TEXT NOT NULL DEFAULT 'queued',
  current_step_order INTEGER,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_run_events (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  workflow_run_id BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companion_jobs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_device_id BIGINT,
  workflow_id BIGINT,
  workflow_run_id BIGINT,
  client_profile_id BIGINT,
  client_instance_id BIGINT,
  account_id BIGINT,
  proxy_id BIGINT,
  job_type TEXT NOT NULL DEFAULT 'workflow_run',
  status TEXT NOT NULL DEFAULT 'queued',
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  accepted_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

ALTER TABLE companion_jobs ADD COLUMN IF NOT EXISTS client_profile_id BIGINT;
ALTER TABLE companion_jobs ADD COLUMN IF NOT EXISTS client_instance_id BIGINT;
ALTER TABLE companion_jobs ADD COLUMN IF NOT EXISTS safe_payload_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE companion_jobs ADD COLUMN IF NOT EXISTS safe_result_json JSONB NOT NULL DEFAULT '{}'::jsonb;
UPDATE companion_jobs SET safe_payload_json = payload WHERE safe_payload_json = '{}'::jsonb AND payload <> '{}'::jsonb;
UPDATE companion_jobs SET safe_result_json = result WHERE safe_result_json = '{}'::jsonb AND result <> '{}'::jsonb;

CREATE TABLE IF NOT EXISTS companion_job_events (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  companion_job_id BIGINT NOT NULL,
  workflow_run_id BIGINT,
  event_type TEXT NOT NULL,
  message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
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
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_status_check') THEN
    ALTER TABLE client_instances DROP CONSTRAINT client_instances_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_status_check') THEN
    ALTER TABLE companion_jobs DROP CONSTRAINT companion_jobs_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_job_type_check') THEN
    ALTER TABLE companion_jobs DROP CONSTRAINT companion_jobs_job_type_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'account_stats_status_check') THEN
    ALTER TABLE account_stats DROP CONSTRAINT account_stats_status_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_wealth_source_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_wealth_source_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_client_state_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_client_state_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_client_state_check') THEN
    ALTER TABLE client_instances DROP CONSTRAINT client_instances_client_state_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_wealth_source_check') THEN
    ALTER TABLE client_instances DROP CONSTRAINT client_instances_wealth_source_check;
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
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_status_check') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_status_check CHECK (status IN ('pending', 'detected', 'launching', 'running', 'scanning', 'stopped', 'crashed', 'unknown'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_status_check') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_status_check CHECK (status IN ('queued', 'accepted', 'running', 'paused', 'waiting_for_user', 'completed', 'failed', 'cancelled'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_job_type_check') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_job_type_check CHECK (job_type IN ('workflow_run', 'run_workflow', 'launch_client', 'stop_client', 'detect_clients', 'request_snapshot', 'open_browser', 'fill_visible_fields', 'pause_workflow', 'resume_workflow', 'cancel_workflow'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'account_stats_status_check') THEN
    ALTER TABLE account_stats
      ADD CONSTRAINT account_stats_status_check CHECK (status IN ('ok', 'not_found', 'failed'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'account_stats_user_account_unique') THEN
    ALTER TABLE account_stats
      ADD CONSTRAINT account_stats_user_account_unique UNIQUE (user_id, account_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_wealth_source_check') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_wealth_source_check CHECK (wealth_source IN ('manual', 'companion_reported', 'client_reported', 'unknown'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_client_state_check') THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_client_state_check CHECK (client_state IN ('active', 'idle', 'offline', 'unknown', 'error'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_client_state_check') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_client_state_check CHECK (client_state IN ('active', 'idle', 'offline', 'unknown', 'error'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_wealth_source_check') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_wealth_source_check CHECK (wealth_source IN ('manual', 'companion_reported', 'client_reported', 'unknown'));
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
  ('default_export_delimiter', ':'),
  ('workflow_mode', 'manual'),
  ('dense_table_mode', 'false'),
  ('screenshot_interval_seconds', '30'),
  ('companion_heartbeat_interval_seconds', '30'),
  ('client_detection_process_names', 'RuneLite,JagexLauncher,Jagex Launcher,osclient,DreamBot'),
  ('enable_local_client_detection', 'false'),
  ('auto_sync_stats_on_client_detected', 'false'),
  ('stats_refresh_cooldown_minutes', '30'),
  ('custom_client_process_names', 'RuneLite,JagexLauncher,Jagex Launcher,osclient,DreamBot'),
  ('client_snapshot_retention_hours', '24'),
  ('client_launcher_requires_confirmation', 'true'),
  ('default_browser_type', 'chromium'),
  ('require_confirmation_before_export_delete', 'true'),
  ('allow_companion_snapshots', 'false'),
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
CREATE INDEX IF NOT EXISTS idx_users_subscription_tier ON users(subscription_tier_id);
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_slug ON subscription_tiers(slug);
CREATE INDEX IF NOT EXISTS idx_subscription_tiers_active ON subscription_tiers(active, sort_order);
CREATE INDEX IF NOT EXISTS idx_browser_task_usage_user_date ON browser_task_usage(user_id, date);
CREATE INDEX IF NOT EXISTS idx_download_items_category ON download_items(category, sort_order);
CREATE INDEX IF NOT EXISTS idx_download_items_status ON download_items(status);
CREATE INDEX IF NOT EXISTS idx_payment_settings_method ON payment_settings(method);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(account_type);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category);
CREATE INDEX IF NOT EXISTS idx_accounts_proxy ON accounts(proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_http_proxy ON accounts(assigned_http_proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_upgrade_status ON accounts(upgrade_status);
CREATE INDEX IF NOT EXISTS idx_accounts_exported_at ON accounts(exported_at);
CREATE INDEX IF NOT EXISTS idx_accounts_archived_at ON accounts(archived_at);
CREATE INDEX IF NOT EXISTS idx_accounts_character_type ON accounts(character_type);
CREATE INDEX IF NOT EXISTS idx_accounts_total_level ON accounts(user_id, total_level);
CREATE INDEX IF NOT EXISTS idx_accounts_combat_level ON accounts(user_id, combat_level);
CREATE INDEX IF NOT EXISTS idx_accounts_stats_sync ON accounts(user_id, last_stats_sync_at DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_client_state ON accounts(user_id, client_state);
CREATE INDEX IF NOT EXISTS idx_accounts_client_last_seen ON accounts(user_id, client_last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_completed_tutorial ON accounts(user_id, completed_tutorial);
CREATE INDEX IF NOT EXISTS idx_proxies_user ON proxies(user_id);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);
CREATE INDEX IF NOT EXISTS idx_proxies_category ON proxies(category);
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_companion_devices_install_hash
  ON companion_devices(user_id, device_install_id_hash)
  WHERE device_install_id_hash IS NOT NULL AND status <> 'revoked';
CREATE INDEX IF NOT EXISTS idx_companion_sessions_user ON companion_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_companion_client_status_user ON companion_client_status(user_id);
CREATE INDEX IF NOT EXISTS idx_live_snapshots_user ON live_snapshots(user_id);
CREATE INDEX IF NOT EXISTS idx_live_snapshots_instance ON live_snapshots(client_instance_id);
CREATE INDEX IF NOT EXISTS idx_client_profiles_user ON client_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_client_profiles_enabled ON client_profiles(user_id, enabled);
CREATE INDEX IF NOT EXISTS idx_client_profiles_default_account ON client_profiles(default_account_id);
CREATE INDEX IF NOT EXISTS idx_client_instances_user ON client_instances(user_id);
CREATE INDEX IF NOT EXISTS idx_client_instances_device ON client_instances(companion_device_id);
CREATE INDEX IF NOT EXISTS idx_client_instances_status ON client_instances(user_id, status);
CREATE INDEX IF NOT EXISTS idx_client_instances_last_seen ON client_instances(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_client_instances_client_state ON client_instances(user_id, client_state);
CREATE INDEX IF NOT EXISTS idx_client_instances_suggested_account ON client_instances(suggested_account_id);
CREATE INDEX IF NOT EXISTS idx_client_instance_events_user ON client_instance_events(user_id);
CREATE INDEX IF NOT EXISTS idx_client_instance_events_instance ON client_instance_events(client_instance_id);
CREATE INDEX IF NOT EXISTS idx_account_stats_user ON account_stats(user_id);
CREATE INDEX IF NOT EXISTS idx_account_stats_account ON account_stats(account_id);
CREATE INDEX IF NOT EXISTS idx_account_stats_fetched ON account_stats(user_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflows_user ON workflows(user_id);
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflow_steps_workflow ON workflow_steps(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_user ON workflow_runs(user_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_status ON workflow_runs(status);
CREATE INDEX IF NOT EXISTS idx_workflow_run_events_run ON workflow_run_events(workflow_run_id);
CREATE INDEX IF NOT EXISTS idx_companion_jobs_user ON companion_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_companion_jobs_device_status ON companion_jobs(companion_device_id, status);
CREATE INDEX IF NOT EXISTS idx_companion_jobs_status ON companion_jobs(status);
CREATE INDEX IF NOT EXISTS idx_companion_jobs_client ON companion_jobs(user_id, client_profile_id, client_instance_id);
CREATE INDEX IF NOT EXISTS idx_companion_job_events_job ON companion_job_events(companion_job_id);
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
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_subscription_tier_id_fkey') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_subscription_tier_id_fkey
      FOREIGN KEY (subscription_tier_id) REFERENCES subscription_tiers(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'browser_task_usage_user_id_fkey') THEN
    ALTER TABLE browser_task_usage
      ADD CONSTRAINT browser_task_usage_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
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
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'live_snapshots_client_instance_id_fkey') THEN
    ALTER TABLE live_snapshots
      ADD CONSTRAINT live_snapshots_client_instance_id_fkey
      FOREIGN KEY (client_instance_id) REFERENCES client_instances(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'live_snapshots_account_id_fkey') THEN
    ALTER TABLE live_snapshots
      ADD CONSTRAINT live_snapshots_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_profiles_user_id_fkey') THEN
    ALTER TABLE client_profiles
      ADD CONSTRAINT client_profiles_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_profiles_proxy_id_fkey') THEN
    ALTER TABLE client_profiles
      ADD CONSTRAINT client_profiles_proxy_id_fkey
      FOREIGN KEY (default_proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_profiles_default_account_id_fkey') THEN
    ALTER TABLE client_profiles
      ADD CONSTRAINT client_profiles_default_account_id_fkey
      FOREIGN KEY (default_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_profiles_workflow_id_fkey') THEN
    ALTER TABLE client_profiles
      ADD CONSTRAINT client_profiles_workflow_id_fkey
      FOREIGN KEY (default_workflow_id) REFERENCES workflows(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_user_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_device_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_profile_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_profile_id_fkey
      FOREIGN KEY (client_profile_id) REFERENCES client_profiles(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_account_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_proxy_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instances_suggested_account_id_fkey') THEN
    ALTER TABLE client_instances
      ADD CONSTRAINT client_instances_suggested_account_id_fkey
      FOREIGN KEY (suggested_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instance_events_user_id_fkey') THEN
    ALTER TABLE client_instance_events
      ADD CONSTRAINT client_instance_events_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_instance_events_instance_id_fkey') THEN
    ALTER TABLE client_instance_events
      ADD CONSTRAINT client_instance_events_instance_id_fkey
      FOREIGN KEY (client_instance_id) REFERENCES client_instances(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'account_stats_user_id_fkey') THEN
    ALTER TABLE account_stats
      ADD CONSTRAINT account_stats_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'account_stats_account_id_fkey') THEN
    ALTER TABLE account_stats
      ADD CONSTRAINT account_stats_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflows_user_id_fkey') THEN
    ALTER TABLE workflows
      ADD CONSTRAINT workflows_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_steps_user_id_fkey') THEN
    ALTER TABLE workflow_steps
      ADD CONSTRAINT workflow_steps_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_steps_workflow_id_fkey') THEN
    ALTER TABLE workflow_steps
      ADD CONSTRAINT workflow_steps_workflow_id_fkey
      FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_runs_user_id_fkey') THEN
    ALTER TABLE workflow_runs
      ADD CONSTRAINT workflow_runs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_runs_workflow_id_fkey') THEN
    ALTER TABLE workflow_runs
      ADD CONSTRAINT workflow_runs_workflow_id_fkey
      FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_runs_account_id_fkey') THEN
    ALTER TABLE workflow_runs
      ADD CONSTRAINT workflow_runs_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_runs_proxy_id_fkey') THEN
    ALTER TABLE workflow_runs
      ADD CONSTRAINT workflow_runs_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_runs_companion_device_id_fkey') THEN
    ALTER TABLE workflow_runs
      ADD CONSTRAINT workflow_runs_companion_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_run_events_user_id_fkey') THEN
    ALTER TABLE workflow_run_events
      ADD CONSTRAINT workflow_run_events_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workflow_run_events_run_id_fkey') THEN
    ALTER TABLE workflow_run_events
      ADD CONSTRAINT workflow_run_events_run_id_fkey
      FOREIGN KEY (workflow_run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_user_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_device_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_device_id_fkey
      FOREIGN KEY (companion_device_id) REFERENCES companion_devices(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_workflow_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_workflow_id_fkey
      FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_run_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_run_id_fkey
      FOREIGN KEY (workflow_run_id) REFERENCES workflow_runs(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_client_profile_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_client_profile_id_fkey
      FOREIGN KEY (client_profile_id) REFERENCES client_profiles(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_client_instance_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_client_instance_id_fkey
      FOREIGN KEY (client_instance_id) REFERENCES client_instances(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_account_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_account_id_fkey
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_jobs_proxy_id_fkey') THEN
    ALTER TABLE companion_jobs
      ADD CONSTRAINT companion_jobs_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_job_events_user_id_fkey') THEN
    ALTER TABLE companion_job_events
      ADD CONSTRAINT companion_job_events_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_job_events_job_id_fkey') THEN
    ALTER TABLE companion_job_events
      ADD CONSTRAINT companion_job_events_job_id_fkey
      FOREIGN KEY (companion_job_id) REFERENCES companion_jobs(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'companion_job_events_run_id_fkey') THEN
    ALTER TABLE companion_job_events
      ADD CONSTRAINT companion_job_events_run_id_fkey
      FOREIGN KEY (workflow_run_id) REFERENCES workflow_runs(id) ON DELETE SET NULL;
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
