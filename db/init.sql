CREATE TABLE IF NOT EXISTS accounts (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_encrypted TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK (account_type IN ('legacy', 'jagex')),
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
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'upgraded', 'skipped', 'blocked', 'needs_review')),
  legacy_archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxies (
  id BIGSERIAL PRIMARY KEY,
  proxy_type TEXT NOT NULL DEFAULT 'HTTP' CHECK (proxy_type IN ('HTTP', 'SOCKS5')),
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
  username_encrypted TEXT,
  password_encrypted TEXT,
  category TEXT,
  country_code TEXT,
  status TEXT NOT NULL DEFAULT 'untested' CHECK (status IN ('untested', 'works', 'blocked', 'review')),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'accounts_proxy_id_fkey'
  ) THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_proxy_id_fkey
      FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE SET NULL;
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
  ('max_accounts_per_proxy', '5'),
  ('export_format_default', 'USERNAME:PASSWORD'),
  ('mask_sensitive_values', 'true')
ON CONFLICT (key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(account_type);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category);
CREATE INDEX IF NOT EXISTS idx_accounts_proxy ON accounts(proxy_id);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);
