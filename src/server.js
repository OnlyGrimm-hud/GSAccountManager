const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const config = require('./config');
const db = require('./db');
const { encrypt, decrypt, mask } = require('./crypto-fields');
const { currentTotp } = require('./otp');
const { csrf, requireAuth, escapeText, oneOf } = require('./security');
const activity = require('./activity');

const app = express();
const accountTypes = ['legacy', 'jagex'];
const accountStatuses = ['pending', 'in_progress', 'upgraded', 'skipped', 'blocked', 'needs_review'];
const proxyTypes = ['HTTP', 'SOCKS5'];
const proxyStatuses = ['untested', 'works', 'blocked', 'review'];
const sensitiveFields = [
  'password', 'bank_pin', 'otp_secret', 'recovery_email', 'recovery_email_password',
  'target_email', 'target_email_password', 'jagex_password'
];

app.set('view engine', 'ejs');
app.set('views', `${__dirname}/../views`);
app.disable('x-powered-by');
app.use(express.static(`${__dirname}/../public`));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  store: new PgSession({ pool: db.pool, createTableIfMissing: true }),
  name: 'gsam.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.cookieSecure,
    maxAge: 1000 * 60 * 60 * 8
  }
}));
app.use((req, res, next) => {
  res.locals.appName = config.appName;
  res.locals.path = req.path;
  res.locals.user = req.session.authenticated ? config.adminUsername : null;
  res.locals.accountStatuses = accountStatuses;
  res.locals.accountTypes = accountTypes;
  res.locals.proxyTypes = proxyTypes;
  res.locals.proxyStatuses = proxyStatuses;
  next();
});
app.use(csrf);

app.get('/healthz', (req, res) => res.status(200).send('OK'));

app.get('/login', (req, res) => res.render('login', { title: 'Login', error: null }));
app.post('/login', (req, res) => {
  const ok = req.body.username === config.adminUsername && req.body.password === config.adminPassword;
  if (!ok) return res.status(401).render('login', { title: 'Login', error: 'Invalid admin username or password.' });
  req.session.authenticated = true;
  req.session.csrfToken = null;
  res.redirect('/');
});
app.post('/logout', requireAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/', requireAuth, async (req, res, next) => {
  try {
    const [counts, recent, proxies] = await Promise.all([
      db.query(`SELECT status, COUNT(*)::int count FROM accounts GROUP BY status`),
      db.query(`SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 8`),
      db.query(`SELECT status, COUNT(*)::int count FROM proxies GROUP BY status`)
    ]);
    res.render('dashboard', { title: 'Dashboard', counts: counts.rows, recent: recent.rows, proxyCounts: proxies.rows });
  } catch (err) { next(err); }
});

app.get('/accounts', requireAuth, async (req, res, next) => {
  try {
    const filters = {
      q: escapeText(req.query.q),
      account_type: escapeText(req.query.account_type),
      status: escapeText(req.query.status),
      category: escapeText(req.query.category),
      country_code: escapeText(req.query.country_code),
      has_proxy: escapeText(req.query.has_proxy),
      has_otp: escapeText(req.query.has_otp)
    };
    const clauses = [];
    const params = [];
    function add(sql, value) { params.push(value); clauses.push(sql.replace('?', `$${params.length}`)); }
    if (filters.q) {
      params.push(`%${filters.q}%`, `%${filters.q}%`);
      clauses.push(`(a.username ILIKE $${params.length - 1} OR a.display_name ILIKE $${params.length})`);
    }
    if (accountTypes.includes(filters.account_type)) add('a.account_type = ?', filters.account_type);
    if (accountStatuses.includes(filters.status)) add('a.status = ?', filters.status);
    if (filters.category) add('a.category ILIKE ?', filters.category);
    if (filters.country_code) add('a.country_code ILIKE ?', filters.country_code);
    if (filters.has_proxy === 'yes') clauses.push('a.proxy_id IS NOT NULL');
    if (filters.has_proxy === 'no') clauses.push('a.proxy_id IS NULL');
    if (filters.has_otp === 'yes') clauses.push('a.otp_secret_encrypted IS NOT NULL');
    if (filters.has_otp === 'no') clauses.push('a.otp_secret_encrypted IS NULL');
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await db.query(
      `SELECT a.*, p.host proxy_host, p.port proxy_port
       FROM accounts a LEFT JOIN proxies p ON p.id = a.proxy_id
       ${where} ORDER BY a.updated_at DESC LIMIT 300`, params
    );
    res.render('accounts/index', { title: 'Accounts', accounts: rows.rows, filters, mask });
  } catch (err) { next(err); }
});

app.get('/accounts/new', requireAuth, async (req, res, next) => {
  try {
    const proxies = await db.query('SELECT id, host, port FROM proxies ORDER BY host');
    res.render('accounts/form', { title: 'New Account', account: {}, decrypted: {}, proxies: proxies.rows, errors: [] });
  } catch (err) { next(err); }
});

app.post('/accounts', requireAuth, async (req, res, next) => {
  try {
    const account = accountFromBody(req.body);
    if (!account.username || !account.password) throw new Error('Username and password are required.');
    const result = await db.query(
      `INSERT INTO accounts
       (username, password_encrypted, account_type, bank_pin_encrypted, otp_secret_encrypted, display_name, category, country_code, notes,
        recovery_email_encrypted, recovery_email_password_encrypted, target_email_encrypted, target_email_password_encrypted, jagex_password_encrypted, proxy_id, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
      accountInsertParams(account)
    );
    await activity.log('account_created', 'account', result.rows[0].id, `Created account ${account.username}`);
    res.redirect(`/accounts/${result.rows[0].id}`);
  } catch (err) { next(err); }
});

app.get('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const { account, decrypted } = await loadAccount(req.params.id);
    const proxies = await db.query('SELECT id, host, port FROM proxies ORDER BY host');
    let otp = null;
    if (decrypted.otp_secret) {
      try { otp = currentTotp(decrypted.otp_secret); } catch (error) { otp = { error: 'Invalid OTP secret' }; }
    }
    res.render('accounts/form', { title: 'Edit Account', account, decrypted, proxies: proxies.rows, otp, errors: [] });
  } catch (err) { next(err); }
});

app.post('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const existing = await loadAccount(req.params.id);
    const account = accountFromBody(req.body, existing.decrypted);
    if (!account.username || !account.password) throw new Error('Username and password are required.');
    const archive = existing.account.status !== 'upgraded' && account.status === 'upgraded';
    await db.query(
      `UPDATE accounts SET
       username=$1, password_encrypted=$2, account_type=$3, bank_pin_encrypted=$4, otp_secret_encrypted=$5, display_name=$6,
       category=$7, country_code=$8, notes=$9, recovery_email_encrypted=$10, recovery_email_password_encrypted=$11,
       target_email_encrypted=$12, target_email_password_encrypted=$13, jagex_password_encrypted=$14, proxy_id=$15,
       status=$16, legacy_archived_at=CASE WHEN $17 THEN NOW() ELSE legacy_archived_at END, updated_at=NOW()
       WHERE id=$18`,
      [...accountInsertParams(account), archive, req.params.id]
    );
    await activity.log('account_updated', 'account', req.params.id, `Updated account ${account.username}`, { status: account.status });
    res.redirect(`/accounts/${req.params.id}`);
  } catch (err) { next(err); }
});

app.get('/accounts/:id/copy/:field', requireAuth, async (req, res, next) => {
  try {
    const { account, decrypted } = await loadAccount(req.params.id);
    const field = req.params.field;
    if (field === 'username') return res.json({ value: account.username });
    if (field === 'otp_code') {
      if (!decrypted.otp_secret) return res.status(404).json({ error: 'No OTP secret saved.' });
      return res.json({ value: currentTotp(decrypted.otp_secret).code });
    }
    if (!sensitiveFields.includes(field)) return res.status(404).json({ error: 'Unsupported field.' });
    res.json({ value: decrypted[field] || '' });
  } catch (err) { next(err); }
});

app.get('/workflow', requireAuth, async (req, res, next) => {
  try {
    const id = req.query.account_id;
    const accounts = await db.query(`SELECT id, username, display_name, status, account_type FROM accounts ORDER BY updated_at DESC LIMIT 100`);
    let selected = null;
    let decrypted = {};
    if (id) ({ account: selected, decrypted } = await loadAccount(id));
    else if (accounts.rows[0]) ({ account: selected, decrypted } = await loadAccount(accounts.rows[0].id));
    res.render('workflow', { title: 'Upgrade Workflow', accounts: accounts.rows, selected, decrypted, mask });
  } catch (err) { next(err); }
});

app.post('/workflow/:id/status', requireAuth, async (req, res, next) => {
  try {
    const status = oneOf(req.body.status, accountStatuses, 'needs_review');
    await db.query('UPDATE accounts SET status=$1, updated_at=NOW() WHERE id=$2', [status, req.params.id]);
    await activity.log('workflow_status_changed', 'account', req.params.id, `Workflow status changed to ${status}`, { status });
    res.redirect(`/workflow?account_id=${req.params.id}`);
  } catch (err) { next(err); }
});

app.get('/proxies', requireAuth, async (req, res, next) => {
  try {
    const rows = await db.query(`SELECT p.*, COUNT(a.id)::int assigned_count FROM proxies p LEFT JOIN accounts a ON a.proxy_id=p.id GROUP BY p.id ORDER BY p.updated_at DESC`);
    res.render('proxies', { title: 'Proxies', proxies: rows.rows, mask });
  } catch (err) { next(err); }
});

app.post('/proxies', requireAuth, async (req, res, next) => {
  try {
    if (req.body.bulk) {
      const lines = req.body.bulk.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      for (const line of lines) {
        const [host, port, username, password] = line.split(':');
        if (host && port) await insertProxy({ ...req.body, host, port, username, password });
      }
      await activity.log('proxies_imported', 'proxy', null, `Imported ${lines.length} proxy line(s)`);
    } else {
      const result = await insertProxy(req.body);
      await activity.log('proxy_created', 'proxy', result.rows[0].id, `Created proxy ${req.body.host}:${req.body.port}`);
    }
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.get('/imports-exports', requireAuth, (req, res) => {
  res.render('imports-exports', { title: 'Imports / Exports', preview: null, exportRows: null, options: {} });
});

app.post('/imports/preview', requireAuth, (req, res) => {
  const preview = parseImport(req.body.accounts_text || '');
  res.render('imports-exports', { title: 'Imports / Exports', preview, exportRows: null, options: req.body });
});

app.post('/imports/commit', requireAuth, async (req, res, next) => {
  try {
    const rows = parseImport(req.body.accounts_text || '').filter(row => row.valid);
    let imported = 0;
    for (const row of rows) {
      const account = accountFromImport(row, req.body);
      const params = accountInsertParams(account);
      if (req.body.duplicate_mode === 'update') {
        await db.query(
          `INSERT INTO accounts
           (username, password_encrypted, account_type, bank_pin_encrypted, otp_secret_encrypted, display_name, category, country_code, notes,
            recovery_email_encrypted, recovery_email_password_encrypted, target_email_encrypted, target_email_password_encrypted, jagex_password_encrypted, proxy_id, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
           ON CONFLICT (username) DO UPDATE SET password_encrypted=EXCLUDED.password_encrypted, account_type=EXCLUDED.account_type,
           bank_pin_encrypted=EXCLUDED.bank_pin_encrypted, otp_secret_encrypted=EXCLUDED.otp_secret_encrypted,
           recovery_email_encrypted=EXCLUDED.recovery_email_encrypted, recovery_email_password_encrypted=EXCLUDED.recovery_email_password_encrypted,
           category=EXCLUDED.category, country_code=EXCLUDED.country_code, status=EXCLUDED.status, updated_at=NOW()`,
          params
        );
      } else {
        await db.query(
          `INSERT INTO accounts
           (username, password_encrypted, account_type, bank_pin_encrypted, otp_secret_encrypted, display_name, category, country_code, notes,
            recovery_email_encrypted, recovery_email_password_encrypted, target_email_encrypted, target_email_password_encrypted, jagex_password_encrypted, proxy_id, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (username) DO NOTHING`,
          params
        );
      }
      imported += 1;
    }
    await activity.log('accounts_imported', 'account', null, `Imported ${imported} account line(s)`, { duplicate_mode: req.body.duplicate_mode || 'skip' });
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.post('/exports/preview', requireAuth, async (req, res, next) => {
  try {
    const rows = await exportRows(req.body);
    await activity.log('accounts_export_previewed', 'account', null, `Prepared ${rows.length} account(s) for export`, { full: req.body.full_export === 'yes' });
    res.render('imports-exports', { title: 'Imports / Exports', preview: null, exportRows: rows, options: req.body });
  } catch (err) { next(err); }
});

app.get('/settings', requireAuth, async (req, res, next) => {
  try {
    const rows = await db.query('SELECT key, value FROM settings ORDER BY key');
    res.render('settings', { title: 'Settings', settings: Object.fromEntries(rows.rows.map(row => [row.key, row.value])), config });
  } catch (err) { next(err); }
});

app.post('/settings', requireAuth, async (req, res, next) => {
  try {
    const allowed = ['app_name', 'default_account_type', 'default_proxy_type', 'max_accounts_per_proxy', 'export_format_default', 'mask_sensitive_values'];
    for (const key of allowed) {
      await db.query(
        `INSERT INTO settings (key, value, updated_at) VALUES ($1,$2,NOW())
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
        [key, escapeText(req.body[key])]
      );
    }
    await activity.log('settings_updated', 'settings', null, 'Updated application settings');
    res.redirect('/settings');
  } catch (err) { next(err); }
});

app.get('/logs', requireAuth, async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 200');
    res.render('logs', { title: 'Logs', logs: rows.rows });
  } catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).render('error', { title: 'Error', message: err.message });
});

function accountFromBody(body, existing = {}) {
  const keep = value => value === undefined ? '' : escapeText(value);
  return {
    username: keep(body.username),
    password: keep(body.password) || existing.password || '',
    account_type: oneOf(body.account_type, accountTypes, 'legacy'),
    bank_pin: keep(body.bank_pin),
    otp_secret: keep(body.otp_secret),
    display_name: keep(body.display_name),
    category: keep(body.category),
    country_code: keep(body.country_code).toUpperCase(),
    notes: keep(body.notes),
    recovery_email: keep(body.recovery_email),
    recovery_email_password: keep(body.recovery_email_password),
    target_email: keep(body.target_email),
    target_email_password: keep(body.target_email_password),
    jagex_password: keep(body.jagex_password),
    proxy_id: body.proxy_id ? Number(body.proxy_id) : null,
    status: oneOf(body.status, accountStatuses, 'pending')
  };
}

function accountInsertParams(account) {
  return [
    account.username, encrypt(account.password), account.account_type, encrypt(account.bank_pin), encrypt(account.otp_secret),
    account.display_name || null, account.category || null, account.country_code || null, account.notes || null,
    encrypt(account.recovery_email), encrypt(account.recovery_email_password), encrypt(account.target_email),
    encrypt(account.target_email_password), encrypt(account.jagex_password), account.proxy_id || null, account.status
  ];
}

async function loadAccount(id) {
  const result = await db.query('SELECT * FROM accounts WHERE id=$1', [id]);
  if (!result.rows[0]) throw new Error('Account not found.');
  const account = result.rows[0];
  const decrypted = {
    password: decrypt(account.password_encrypted),
    bank_pin: decrypt(account.bank_pin_encrypted),
    otp_secret: decrypt(account.otp_secret_encrypted),
    recovery_email: decrypt(account.recovery_email_encrypted),
    recovery_email_password: decrypt(account.recovery_email_password_encrypted),
    target_email: decrypt(account.target_email_encrypted),
    target_email_password: decrypt(account.target_email_password_encrypted),
    jagex_password: decrypt(account.jagex_password_encrypted)
  };
  return { account, decrypted };
}

async function insertProxy(body) {
  const host = escapeText(body.host);
  const port = Number(body.port);
  if (!host || !port) throw new Error('Proxy host and port are required.');
  return db.query(
    `INSERT INTO proxies (proxy_type, host, port, username_encrypted, password_encrypted, category, country_code, status, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
    [
      oneOf(body.proxy_type, proxyTypes, 'HTTP'), host, port, encrypt(body.username), encrypt(body.password),
      escapeText(body.category) || null, escapeText(body.country_code).toUpperCase() || null,
      oneOf(body.status, proxyStatuses, 'untested'), escapeText(body.notes) || null
    ]
  );
}

function parseImport(text) {
  return text.split(/\r?\n/).map((line, index) => {
    const parts = line.trim().split(':');
    return {
      line: index + 1,
      raw: line,
      username: parts[0] || '',
      password: parts[1] || '',
      bank_pin: parts.length >= 4 ? parts[2] : '',
      otp_secret: parts.length === 3 ? parts[2] : (parts[3] || ''),
      recovery_email: parts[4] || '',
      recovery_email_password: parts[5] || '',
      valid: parts.length >= 2 && parts.length <= 6 && Boolean(parts[0] && parts[1])
    };
  }).filter(row => row.raw.trim());
}

function accountFromImport(row, body) {
  return {
    username: row.username,
    password: row.password,
    account_type: oneOf(body.account_type, accountTypes, 'legacy'),
    bank_pin: row.bank_pin,
    otp_secret: row.otp_secret,
    display_name: '',
    category: escapeText(body.category),
    country_code: escapeText(body.country_code).toUpperCase(),
    notes: '',
    recovery_email: row.recovery_email,
    recovery_email_password: row.recovery_email_password,
    target_email: '',
    target_email_password: '',
    jagex_password: '',
    proxy_id: null,
    status: oneOf(body.status, accountStatuses, 'pending')
  };
}

async function exportRows(options) {
  const type = oneOf(options.account_type, accountTypes, 'legacy');
  const result = await db.query('SELECT * FROM accounts WHERE account_type=$1 ORDER BY username', [type]);
  return result.rows.map(account => {
    const d = {
      password: decrypt(account.password_encrypted),
      bank_pin: decrypt(account.bank_pin_encrypted),
      otp_secret: decrypt(account.otp_secret_encrypted),
      target_email: decrypt(account.target_email_encrypted),
      jagex_password: decrypt(account.jagex_password_encrypted)
    };
    const full = options.full_export === 'yes';
    const value = v => full ? (v || '') : mask(v || '');
    switch (options.format) {
      case 'USERNAME:PASSWORD:OTP_KEY': return `${account.username}:${value(d.password)}:${value(d.otp_secret)}`;
      case 'USERNAME:PASSWORD:BANK_PIN:OTP_KEY': return `${account.username}:${value(d.password)}:${value(d.bank_pin)}:${value(d.otp_secret)}`;
      case 'TARGET_EMAIL:JAGEX_PASSWORD': return `${value(d.target_email)}:${value(d.jagex_password)}`;
      case 'TARGET_EMAIL:JAGEX_PASSWORD:DISPLAY_NAME': return `${value(d.target_email)}:${value(d.jagex_password)}:${account.display_name || ''}`;
      default: return `${account.username}:${value(d.password)}`;
    }
  });
}

async function start() {
  await db.migrate();
  app.listen(config.port, () => console.log(`${config.appName} listening on ${config.port}`));
}

if (require.main === module) {
  start().catch(error => {
    console.error(`Startup error: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { app, parseImport };
