CREATE TABLE IF NOT EXISTS proxies (
  id BIGSERIAL PRIMARY KEY,
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

UPDATE accounts SET legacy_login = username WHERE legacy_login IS NULL;
UPDATE accounts SET legacy_password_encrypted = password_encrypted WHERE legacy_password_encrypted IS NULL;
UPDATE accounts SET assigned_http_proxy_id = proxy_id WHERE assigned_http_proxy_id IS NULL AND proxy_id IS NOT NULL;
UPDATE accounts SET credential_status = 'ready' WHERE credential_status = 'partial' AND password_encrypted IS NOT NULL AND username IS NOT NULL;
UPDATE accounts SET upgrade_status = 'complete' WHERE upgrade_status = 'pending' AND status = 'upgraded';
UPDATE accounts SET archived_at = legacy_archived_at WHERE archived_at IS NULL AND legacy_archived_at IS NOT NULL;

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
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxies_proxy_type_check') THEN
    ALTER TABLE proxies DROP CONSTRAINT proxies_proxy_type_check;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxies_status_check') THEN
    ALTER TABLE proxies DROP CONSTRAINT proxies_status_check;
  END IF;
END $$;

ALTER TABLE accounts
  ADD CONSTRAINT accounts_account_type_check CHECK (account_type IN ('legacy', 'jagex', 'unknown'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_status_check CHECK (status IN ('pending', 'in_progress', 'upgraded', 'skipped', 'blocked', 'needs_review', 'exported', 'archived'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_credential_status_check CHECK (credential_status IN ('missing', 'partial', 'ready', 'needs_review'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_upgrade_status_check CHECK (upgrade_status IN ('pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'));
ALTER TABLE accounts
  ADD CONSTRAINT accounts_email_creation_status_check CHECK (email_creation_status IN ('pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'));
ALTER TABLE proxies
  ADD CONSTRAINT proxies_proxy_type_check CHECK (proxy_type IN ('HTTP', 'SOCKS5'));
ALTER TABLE proxies
  ADD CONSTRAINT proxies_status_check CHECK (status IN ('untested', 'online', 'works', 'blocked', 'review'));

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
  actor TEXT NOT NULL DEFAULT 'local-admin',
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id BIGINT,
  message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO settings (key, value) VALUES
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
  ('export_format_default', 'legacy_user_pass'),
  ('export_behavior_default', 'keep'),
  ('mask_sensitive_values', 'true'),
  ('otp_refresh_interval', '30'),
  ('theme_name', 'Premium Dark'),
  ('app_version', '0.1.0')
ON CONFLICT (key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(account_type);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category);
CREATE INDEX IF NOT EXISTS idx_accounts_proxy ON accounts(proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_http_proxy ON accounts(assigned_http_proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_upgrade_status ON accounts(upgrade_status);
CREATE INDEX IF NOT EXISTS idx_accounts_exported_at ON accounts(exported_at);
CREATE INDEX IF NOT EXISTS idx_accounts_archived_at ON accounts(archived_at);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);
