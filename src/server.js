const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const config = require('./config');
const db = require('./db');
const { encrypt, decrypt, mask } = require('./crypto-fields');
const { currentTotp } = require('./otp');
const { csrf, requireAuth, escapeText, oneOf, verifyAdminPassword } = require('./security');
const activity = require('./activity');
const { generatePassword } = require('./generators');
const { parseAccountImport, parseProxyImport } = require('./parsers');
const {
  accountTypes,
  accountStatuses,
  credentialStatuses,
  workflowStatuses,
  proxyTypes,
  proxyStatuses
} = require('./app-constants');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });
const sensitiveFields = [
  'password', 'legacy_password', 'bank_pin', 'otp_secret', 'recovery_email', 'recovery_email_password',
  'target_email', 'target_email_password', 'email_password', 'jagex_email', 'jagex_password'
];
const copyFields = [
  'username', 'legacy_login', 'password', 'legacy_password', 'otp_code', 'otp_secret', 'notes',
  'target_email', 'target_email_password', 'email_password', 'first_name', 'last_name',
  'birth_month', 'birth_day', 'birth_year', 'birth_date', 'jagex_email', 'jagex_password',
  'jagex_name', 'recovery_email', 'recovery_email_password', 'bank_pin'
];

app.set('view engine', 'ejs');
app.set('views', `${__dirname}/../views`);
app.disable('x-powered-by');
if (config.nodeEnv === 'production') app.set('trust proxy', 1);
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.static(`${__dirname}/../public`));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(express.json({ limit: '1mb' }));
app.get('/healthz', (req, res) => res.status(200).send('OK'));
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
  res.locals.appVersion = config.appVersion;
  res.locals.path = req.path;
  res.locals.user = req.session.authenticated ? config.adminUsername : null;
  res.locals.accountStatuses = accountStatuses;
  res.locals.accountTypes = accountTypes;
  res.locals.credentialStatuses = credentialStatuses;
  res.locals.workflowStatuses = workflowStatuses;
  res.locals.proxyTypes = proxyTypes;
  res.locals.proxyStatuses = proxyStatuses;
  next();
});
app.use(csrf);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts. Try again soon.'
});

app.get('/login', (req, res) => res.render('login', { title: 'Login', error: null }));
app.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const ok = req.body.username === config.adminUsername && verifyAdminPassword(req.body.password, config);
    await activity.log(ok ? 'admin_login_success' : 'admin_login_failed', 'admin', null, ok ? 'Admin login succeeded' : 'Admin login failed');
    if (!ok) return res.status(401).render('login', { title: 'Login', error: 'Invalid admin username or password.' });
    req.session.authenticated = true;
    req.session.csrfToken = null;
    res.redirect('/');
  } catch (err) { next(err); }
});
app.post('/logout', requireAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/', requireAuth, async (req, res, next) => {
  try {
    const settings = await getSettings();
    const selectedId = req.query.account_id;
    const [counts, recent, proxyCounts, selectable] = await Promise.all([
      db.query(`SELECT status, COUNT(*)::int count FROM accounts GROUP BY status`),
      db.query(`SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 8`),
      db.query(`SELECT status, COUNT(*)::int count FROM proxies GROUP BY status`),
      db.query(`SELECT id, username, legacy_login, display_name, status, upgrade_status FROM accounts WHERE archived_at IS NULL ORDER BY updated_at DESC LIMIT 100`)
    ]);
    let selected = null;
    let decrypted = {};
    if (selectedId) ({ account: selected, decrypted } = await loadAccount(selectedId));
    else {
      const current = await db.query(
        `SELECT id FROM accounts
         WHERE archived_at IS NULL AND status <> 'archived'
         ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'needs_review' THEN 1 WHEN 'pending' THEN 2 ELSE 3 END, updated_at DESC
         LIMIT 1`
      );
      if (current.rows[0]) ({ account: selected, decrypted } = await loadAccount(current.rows[0].id));
    }
    const nextStep = workflowStep(selected);
    res.render('dashboard', {
      title: 'Dashboard',
      counts: counts.rows,
      recent: recent.rows,
      proxyCounts: proxyCounts.rows,
      selectable: selectable.rows,
      selected,
      decrypted,
      settings,
      nextStep,
      mask
    });
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
      params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
      clauses.push(`(a.username ILIKE $${params.length - 2} OR a.legacy_login ILIKE $${params.length - 1} OR a.display_name ILIKE $${params.length})`);
    }
    if (accountTypes.includes(filters.account_type)) add('a.account_type = ?', filters.account_type);
    if (accountStatuses.includes(filters.status)) add('a.status = ?', filters.status);
    if (filters.category) add('a.category ILIKE ?', filters.category);
    if (filters.country_code) add('a.country_code ILIKE ?', filters.country_code.toUpperCase());
    if (filters.has_proxy === 'yes') clauses.push('(a.assigned_http_proxy_id IS NOT NULL OR a.proxy_id IS NOT NULL)');
    if (filters.has_proxy === 'no') clauses.push('a.assigned_http_proxy_id IS NULL AND a.proxy_id IS NULL');
    if (filters.has_otp === 'yes') clauses.push('a.otp_secret_encrypted IS NOT NULL');
    if (filters.has_otp === 'no') clauses.push('a.otp_secret_encrypted IS NULL');
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await db.query(
      `SELECT a.*, p.host proxy_host, p.port proxy_port, p.status proxy_status, p.proxy_type
       FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id)
       ${where} ORDER BY a.updated_at DESC LIMIT 300`, params
    );
    res.render('accounts/index', { title: 'Accounts', accounts: rows.rows, filters, mask });
  } catch (err) { next(err); }
});

app.get('/accounts/new', requireAuth, async (req, res, next) => {
  try {
    const proxies = await db.query('SELECT id, proxy_type, host, port, status FROM proxies ORDER BY host');
    res.render('accounts/form', { title: 'New Account', account: { account_type: 'legacy', status: 'pending', credential_status: 'partial', upgrade_status: 'pending', email_creation_status: 'pending' }, decrypted: {}, proxies: proxies.rows, errors: [], generatedPassword: generatePassword(await passwordLength()) });
  } catch (err) { next(err); }
});

app.post('/accounts', requireAuth, async (req, res, next) => {
  try {
    const account = accountFromBody(req.body);
    if (!account.username || !account.legacy_password) throw new Error('Login and password are required.');
    const result = await db.query(accountInsertSql(), accountParams(account));
    await activity.log('account_created', 'account', result.rows[0].id, `Created account ${account.username}`, { account_type: account.account_type });
    res.redirect(`/accounts/${result.rows[0].id}`);
  } catch (err) { next(err); }
});

app.get('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const { account, decrypted } = await loadAccount(req.params.id);
    const proxies = await db.query('SELECT id, proxy_type, host, port, status FROM proxies ORDER BY host');
    let otp = null;
    if (decrypted.otp_secret) {
      try { otp = currentTotp(decrypted.otp_secret); } catch (error) { otp = { error: 'Invalid OTP secret' }; }
    }
    res.render('accounts/form', { title: 'Edit Account', account, decrypted, proxies: proxies.rows, otp, errors: [], generatedPassword: generatePassword(await passwordLength()) });
  } catch (err) { next(err); }
});

app.post('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const existing = await loadAccount(req.params.id);
    const account = accountFromBody(req.body, existing.decrypted);
    if (!account.username || !account.legacy_password) throw new Error('Login and password are required.');
    const archive = existing.account.status !== 'upgraded' && account.status === 'upgraded';
    await db.query(accountUpdateSql(), [...accountParams(account), archive, req.params.id]);
    await activity.log('account_updated', 'account', req.params.id, `Updated account ${account.username}`, { status: account.status, upgrade_status: account.upgrade_status });
    res.redirect(`/accounts/${req.params.id}`);
  } catch (err) { next(err); }
});

app.get('/accounts/:id/copy/:field', requireAuth, async (req, res, next) => {
  try {
    const { account, decrypted } = await loadAccount(req.params.id);
    const field = req.params.field;
    if (!copyFields.includes(field)) return res.status(404).json({ error: 'Unsupported field.' });
    let value = '';
    if (field === 'username' || field === 'legacy_login') value = account.legacy_login || account.username;
    else if (field === 'password' || field === 'legacy_password') value = decrypted.legacy_password || decrypted.password;
    else if (field === 'otp_code') {
      if (!decrypted.otp_secret) return res.status(404).json({ error: 'No OTP secret saved.' });
      value = currentTotp(decrypted.otp_secret).code;
    } else if (field === 'birth_date') value = birthDate(account);
    else if (field in decrypted) value = decrypted[field] || '';
    else value = account[field] || '';
    await activity.log('field_copied', 'account', account.id, `Copied ${field}`, { field });
    res.json({ value });
  } catch (err) { next(err); }
});

app.get('/generate/password', requireAuth, async (req, res) => {
  const length = Number(req.query.length || await passwordLength());
  res.json({ value: generatePassword(length) });
});

app.get('/workflow', requireAuth, async (req, res, next) => {
  try {
    const settings = await getSettings();
    const accounts = await db.query(`SELECT id, username, legacy_login, display_name, status, account_type, upgrade_status FROM accounts WHERE archived_at IS NULL ORDER BY updated_at DESC LIMIT 100`);
    let selected = null;
    let decrypted = {};
    if (req.query.account_id) ({ account: selected, decrypted } = await loadAccount(req.query.account_id));
    else if (accounts.rows[0]) ({ account: selected, decrypted } = await loadAccount(accounts.rows[0].id));
    res.render('workflow', { title: 'Upgrade Workflow', accounts: accounts.rows, selected, decrypted, settings, mask, nextStep: workflowStep(selected) });
  } catch (err) { next(err); }
});

app.post('/workflow/:id/status', requireAuth, async (req, res, next) => {
  try {
    const status = oneOf(req.body.status, accountStatuses, 'needs_review');
    const upgradeStatus = status === 'upgraded' ? 'complete' : status === 'in_progress' ? 'in_progress' : status === 'skipped' ? 'skipped' : status === 'blocked' ? 'blocked' : 'needs_review';
    await db.query(
      `UPDATE accounts SET status=$1, upgrade_status=$2, exported_at=CASE WHEN $1='exported' THEN NOW() ELSE exported_at END,
       archived_at=CASE WHEN $1='archived' THEN NOW() ELSE archived_at END, updated_at=NOW() WHERE id=$3`,
      [status, oneOf(upgradeStatus, workflowStatuses, 'needs_review'), req.params.id]
    );
    await activity.log('workflow_status_changed', 'account', req.params.id, `Workflow status changed to ${status}`, { status });
    res.redirect(`/workflow?account_id=${req.params.id}`);
  } catch (err) { next(err); }
});

app.get('/proxies', requireAuth, async (req, res, next) => {
  try {
    const [rows, counts, settings] = await Promise.all([
      db.query(`SELECT p.*, COUNT(a.id)::int assigned_count FROM proxies p LEFT JOIN accounts a ON COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id GROUP BY p.id ORDER BY p.updated_at DESC`),
      db.query(`SELECT
        COUNT(*)::int total,
        COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM accounts a WHERE COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id))::int assigned,
        COUNT(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id))::int unassigned,
        COUNT(*) FILTER (WHERE status IN ('online','works'))::int online,
        COUNT(*) FILTER (WHERE status='blocked')::int blocked,
        COUNT(*) FILTER (WHERE status='review')::int review
       FROM proxies p`),
      getSettings()
    ]);
    res.render('proxies', { title: 'Proxies', proxies: rows.rows, counts: counts.rows[0], settings, mask });
  } catch (err) { next(err); }
});

app.post('/proxies', requireAuth, async (req, res, next) => {
  try {
    if (req.body.bulk) {
      const lines = parseProxyImport(req.body.bulk);
      let imported = 0;
      for (const line of lines.filter(row => row.valid)) {
        const result = await insertProxy({ ...req.body, ...line, proxy_type: req.body.proxy_type || line.proxy_type });
        if (result.rowCount !== 0) imported += 1;
      }
      await activity.log('proxies_imported', 'proxy', null, `Imported ${imported} proxy line(s)`);
    } else {
      const result = await insertProxy(req.body);
      await activity.log('proxy_created', 'proxy', result.rows[0].id, `Created proxy ${req.body.host}:${req.body.port}`);
    }
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.post('/proxies/auto-assign', requireAuth, async (req, res, next) => {
  try {
    const settings = await getSettings();
    const max = Number(settings.max_accounts_per_proxy || 5);
    const proxies = await db.query(
      `SELECT p.id, COUNT(a.id)::int assigned_count
       FROM proxies p LEFT JOIN accounts a ON COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id
       WHERE p.proxy_type='HTTP' AND p.status <> 'blocked'
       GROUP BY p.id ORDER BY assigned_count ASC, p.updated_at DESC`
    );
    const accounts = await db.query(
      `SELECT id FROM accounts
       WHERE assigned_http_proxy_id IS NULL AND proxy_id IS NULL AND archived_at IS NULL
       ORDER BY updated_at ASC LIMIT 500`
    );
    let assigned = 0;
    for (const account of accounts.rows) {
      const proxy = proxies.rows.find(item => item.assigned_count < max);
      if (!proxy) break;
      await db.query('UPDATE accounts SET assigned_http_proxy_id=$1, proxy_id=$1, updated_at=NOW() WHERE id=$2', [proxy.id, account.id]);
      proxy.assigned_count += 1;
      assigned += 1;
    }
    await activity.log('proxies_auto_assigned', 'proxy', null, `Assigned proxies to ${assigned} account(s)`, { assigned, max_accounts_per_proxy: max });
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.get('/imports-exports', requireAuth, (req, res) => {
  res.render('imports-exports', { title: 'Imports / Exports', preview: null, exportRows: null, options: {}, stats: null });
});

app.post('/imports/preview', requireAuth, upload.single('accounts_file'), async (req, res, next) => {
  try {
    const text = inputText(req);
    const preview = parseAccountImport(text, req.body.delimiter || ':');
    await markDuplicates(preview);
    const stats = previewStats(preview);
    res.render('imports-exports', { title: 'Imports / Exports', preview, exportRows: null, options: { ...req.body, accounts_text: text }, stats });
  } catch (err) { next(err); }
});

app.post('/imports/commit', requireAuth, async (req, res, next) => {
  try {
    const rows = parseAccountImport(req.body.accounts_text || '', req.body.delimiter || ':');
    await markDuplicates(rows);
    let imported = 0;
    for (const row of rows.filter(item => item.valid && (req.body.duplicate_mode === 'update' || !item.duplicate))) {
      const account = accountFromImport(row, req.body);
      if (req.body.duplicate_mode === 'update') await db.query(accountUpsertSql(), accountParams(account));
      else await db.query(accountInsertSql('ON CONFLICT (username) DO NOTHING'), accountParams(account));
      imported += 1;
    }
    await activity.log('accounts_imported', 'account', null, `Imported ${imported} account line(s)`, { duplicate_mode: req.body.duplicate_mode || 'skip' });
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.post('/exports/preview', requireAuth, async (req, res, next) => {
  try {
    const rows = await exportRows(req.body);
    if (req.body.confirm_export_action === 'yes') await applyExportAction(req.body);
    await activity.log('accounts_export_previewed', 'account', null, `Prepared ${rows.length} account(s) for export`, { format: req.body.format, export_action: req.body.export_action || 'keep' });
    res.render('imports-exports', { title: 'Imports / Exports', preview: null, exportRows: rows, options: req.body, stats: null });
  } catch (err) { next(err); }
});

app.get('/settings', requireAuth, async (req, res, next) => {
  try {
    const settings = await getSettings();
    settings.app_version = config.appVersion;
    res.render('settings', { title: 'Settings', settings, config });
  } catch (err) { next(err); }
});

app.post('/settings', requireAuth, async (req, res, next) => {
  try {
    const allowed = [
      'app_name', 'default_account_type', 'default_proxy_type', 'default_email_provider',
      'email_signup_url', 'email_signin_url', 'account_settings_url', 'upgrade_url',
      'password_length', 'max_accounts_per_proxy', 'export_format_default',
      'export_behavior_default', 'mask_sensitive_values', 'otp_refresh_interval', 'theme_name'
    ];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        await upsertSetting(key, escapeText(req.body[key]));
      }
    }
    await upsertSetting('app_version', config.appVersion);
    await activity.log('settings_updated', 'settings', null, 'Updated application settings');
    res.redirect('/settings');
  } catch (err) { next(err); }
});

app.get('/logs', requireAuth, async (req, res, next) => {
  try {
    const filters = { q: escapeText(req.query.q), action: escapeText(req.query.action) };
    const clauses = [];
    const params = [];
    if (filters.q) {
      params.push(`%${filters.q}%`);
      clauses.push(`(action ILIKE $${params.length} OR message ILIKE $${params.length})`);
    }
    if (filters.action) {
      params.push(filters.action);
      clauses.push(`action = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const [rows, actions] = await Promise.all([
      db.query(`SELECT * FROM activity_logs ${where} ORDER BY created_at DESC LIMIT 300`, params),
      db.query(`SELECT DISTINCT action FROM activity_logs ORDER BY action`)
    ]);
    res.render('logs', { title: 'Logs', logs: rows.rows, actions: actions.rows.map(row => row.action), filters });
  } catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).render('error', { title: 'Error', message: err.message });
});

function inputText(req) {
  const uploaded = req.file ? req.file.buffer.toString('utf8') : '';
  return uploaded || req.body.accounts_text || '';
}

async function passwordLength() {
  const settings = await getSettings();
  return Number(settings.password_length || 9);
}

async function getSettings() {
  const rows = await db.query('SELECT key, value FROM settings ORDER BY key');
  return Object.fromEntries(rows.rows.map(row => [row.key, row.value]));
}

async function upsertSetting(key, value) {
  await db.query(
    `INSERT INTO settings (key, value, updated_at) VALUES ($1,$2,NOW())
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
    [key, value || '']
  );
}

function accountFromBody(body, existing = {}) {
  const keep = value => value === undefined ? '' : escapeText(value);
  const legacyLogin = keep(body.legacy_login || body.username);
  const jagexEmail = keep(body.jagex_email || body.target_email);
  const username = legacyLogin || jagexEmail;
  const legacyPassword = keep(body.legacy_password || body.password) || existing.legacy_password || existing.password || keep(body.jagex_password) || existing.jagex_password || '';
  const emailPassword = keep(body.email_password || body.target_email_password);
  return {
    username,
    legacy_login: legacyLogin || username,
    legacy_password: legacyPassword,
    password: legacyPassword,
    account_type: oneOf(body.account_type, accountTypes, 'unknown'),
    bank_pin: keep(body.bank_pin),
    otp_secret: keep(body.otp_secret),
    display_name: keep(body.display_name),
    category: keep(body.category),
    country_code: keep(body.country_code).toUpperCase(),
    notes: keep(body.notes),
    recovery_email: keep(body.recovery_email),
    recovery_email_password: keep(body.recovery_email_password),
    target_email: keep(body.target_email),
    target_email_password: emailPassword,
    email_password: emailPassword,
    jagex_email: jagexEmail,
    jagex_password: keep(body.jagex_password),
    jagex_name: keep(body.jagex_name),
    first_name: keep(body.first_name),
    last_name: keep(body.last_name),
    birth_month: numberOrNull(body.birth_month),
    birth_day: numberOrNull(body.birth_day),
    birth_year: numberOrNull(body.birth_year),
    proxy_id: body.assigned_http_proxy_id || body.proxy_id ? Number(body.assigned_http_proxy_id || body.proxy_id) : null,
    assigned_http_proxy_id: body.assigned_http_proxy_id || body.proxy_id ? Number(body.assigned_http_proxy_id || body.proxy_id) : null,
    assigned_socks5_proxy_id: body.assigned_socks5_proxy_id ? Number(body.assigned_socks5_proxy_id) : null,
    status: oneOf(body.status, accountStatuses, 'pending'),
    credential_status: oneOf(body.credential_status, credentialStatuses, 'partial'),
    upgrade_status: oneOf(body.upgrade_status, workflowStatuses, 'pending'),
    email_creation_status: oneOf(body.email_creation_status, workflowStatuses, 'pending')
  };
}

function accountParams(account) {
  return [
    account.username, encrypt(account.password), account.legacy_login, encrypt(account.legacy_password), account.account_type,
    encrypt(account.bank_pin), encrypt(account.otp_secret), account.display_name || null, account.category || null, account.country_code || null, account.notes || null,
    encrypt(account.recovery_email), encrypt(account.recovery_email_password), encrypt(account.target_email), encrypt(account.target_email_password), encrypt(account.email_password),
    encrypt(account.jagex_email), encrypt(account.jagex_password), account.jagex_name || null, account.first_name || null, account.last_name || null,
    account.birth_month, account.birth_day, account.birth_year, account.proxy_id, account.assigned_http_proxy_id, account.assigned_socks5_proxy_id,
    account.status, account.credential_status, account.upgrade_status, account.email_creation_status
  ];
}

function accountColumns() {
  return [
    'username', 'password_encrypted', 'legacy_login', 'legacy_password_encrypted', 'account_type',
    'bank_pin_encrypted', 'otp_secret_encrypted', 'display_name', 'category', 'country_code', 'notes',
    'recovery_email_encrypted', 'recovery_email_password_encrypted', 'target_email_encrypted', 'target_email_password_encrypted', 'email_password_encrypted',
    'jagex_email_encrypted', 'jagex_password_encrypted', 'jagex_name', 'first_name', 'last_name',
    'birth_month', 'birth_day', 'birth_year', 'proxy_id', 'assigned_http_proxy_id', 'assigned_socks5_proxy_id',
    'status', 'credential_status', 'upgrade_status', 'email_creation_status'
  ];
}

function accountInsertSql(conflict = '') {
  const columns = accountColumns();
  const values = columns.map((_, index) => `$${index + 1}`);
  return `INSERT INTO accounts (${columns.join(', ')}) VALUES (${values.join(', ')}) ${conflict} RETURNING id`;
}

function accountUpdateSql() {
  const columns = accountColumns();
  const assignments = columns.map((column, index) => `${column}=$${index + 1}`);
  return `UPDATE accounts SET ${assignments.join(', ')},
    legacy_archived_at=CASE WHEN $${columns.length + 1} THEN NOW() ELSE legacy_archived_at END,
    archived_at=CASE WHEN $28='archived' THEN NOW() ELSE archived_at END,
    exported_at=CASE WHEN $28='exported' THEN NOW() ELSE exported_at END,
    updated_at=NOW()
    WHERE id=$${columns.length + 2}`;
}

function accountUpsertSql() {
  const columns = accountColumns();
  const update = columns.filter(column => column !== 'username').map(column => `${column}=EXCLUDED.${column}`).join(', ');
  return `INSERT INTO accounts (${columns.join(', ')}) VALUES (${columns.map((_, index) => `$${index + 1}`).join(', ')})
    ON CONFLICT (username) DO UPDATE SET ${update}, updated_at=NOW() RETURNING id`;
}

async function loadAccount(id) {
  const result = await db.query(
    `SELECT a.*, p.host proxy_host, p.port proxy_port, p.status proxy_status
     FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id)
     WHERE a.id=$1`, [id]
  );
  if (!result.rows[0]) throw new Error('Account not found.');
  const account = result.rows[0];
  const decrypted = {
    password: decrypt(account.password_encrypted),
    legacy_password: decrypt(account.legacy_password_encrypted) || decrypt(account.password_encrypted),
    bank_pin: decrypt(account.bank_pin_encrypted),
    otp_secret: decrypt(account.otp_secret_encrypted),
    recovery_email: decrypt(account.recovery_email_encrypted),
    recovery_email_password: decrypt(account.recovery_email_password_encrypted),
    target_email: decrypt(account.target_email_encrypted),
    target_email_password: decrypt(account.target_email_password_encrypted),
    email_password: decrypt(account.email_password_encrypted) || decrypt(account.target_email_password_encrypted),
    jagex_email: decrypt(account.jagex_email_encrypted),
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

function accountFromImport(row, body) {
  return {
    username: row.username,
    legacy_login: row.username,
    password: row.password,
    legacy_password: row.password,
    account_type: oneOf(body.account_type, accountTypes, 'unknown'),
    bank_pin: row.bank_pin,
    otp_secret: row.otp_secret,
    display_name: '',
    category: escapeText(body.category),
    country_code: escapeText(body.country_code).toUpperCase(),
    notes: row.notes || '',
    recovery_email: '',
    recovery_email_password: '',
    target_email: '',
    target_email_password: '',
    email_password: '',
    jagex_email: body.account_type === 'jagex' ? row.username : '',
    jagex_password: body.account_type === 'jagex' ? row.password : '',
    jagex_name: '',
    first_name: '',
    last_name: '',
    birth_month: null,
    birth_day: null,
    birth_year: null,
    proxy_id: null,
    assigned_http_proxy_id: null,
    assigned_socks5_proxy_id: null,
    status: oneOf(body.status, accountStatuses, 'pending'),
    credential_status: 'ready',
    upgrade_status: 'pending',
    email_creation_status: 'pending'
  };
}

async function markDuplicates(rows) {
  const names = [...new Set(rows.filter(row => row.username).map(row => row.username))];
  if (!names.length) return;
  const existing = await db.query('SELECT username, legacy_login FROM accounts WHERE username = ANY($1) OR legacy_login = ANY($1)', [names]);
  const found = new Set(existing.rows.flatMap(row => [row.username, row.legacy_login]).filter(Boolean));
  rows.forEach(row => { row.duplicate = found.has(row.username); });
}

function previewStats(rows) {
  return {
    valid: rows.filter(row => row.valid).length,
    duplicate: rows.filter(row => row.duplicate).length,
    invalid: rows.filter(row => !row.valid).length
  };
}

async function exportRows(options) {
  const type = oneOf(options.account_type, accountTypes, 'legacy');
  const result = await db.query(
    `SELECT a.*, p.host proxy_host, p.port proxy_port
     FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id)
     WHERE a.account_type=$1 AND a.archived_at IS NULL
     ORDER BY a.username`, [type]
  );
  return result.rows.map(account => {
    const d = {
      legacy_password: decrypt(account.legacy_password_encrypted) || decrypt(account.password_encrypted),
      otp_secret: decrypt(account.otp_secret_encrypted),
      jagex_email: decrypt(account.jagex_email_encrypted) || decrypt(account.target_email_encrypted),
      jagex_password: decrypt(account.jagex_password_encrypted)
    };
    switch (options.format) {
      case 'legacy_user_pass_otp':
        return `${account.legacy_login || account.username}:${d.legacy_password}:${d.otp_secret}`;
      case 'jagex_email_pass':
        return `${d.jagex_email}:${d.jagex_password}`;
      case 'jagex_email_pass_otp':
        return `${d.jagex_email}:${d.jagex_password}:${d.otp_secret}`;
      case 'safe_csv':
        return csvLine([
          account.id, account.account_type, account.legacy_login || account.username, account.display_name,
          account.status, account.credential_status, account.upgrade_status, account.email_creation_status,
          account.category, account.country_code, account.proxy_host ? `${account.proxy_host}:${account.proxy_port}` : '',
          account.notes, account.updated_at, account.exported_at || ''
        ]);
      default:
        return `${account.legacy_login || account.username}:${d.legacy_password}`;
    }
  });
}

async function applyExportAction(options) {
  const type = oneOf(options.account_type, accountTypes, 'legacy');
  const action = options.export_action || 'keep';
  if (action === 'mark_exported') {
    await db.query(`UPDATE accounts SET status='exported', exported_at=NOW(), updated_at=NOW() WHERE account_type=$1 AND archived_at IS NULL`, [type]);
    await activity.log('accounts_marked_exported', 'account', null, `Marked ${type} accounts exported`);
  }
  if (action === 'archive') {
    await db.query(`UPDATE accounts SET status='archived', archived_at=NOW(), updated_at=NOW() WHERE account_type=$1 AND archived_at IS NULL`, [type]);
    await activity.log('accounts_archived_after_export', 'account', null, `Archived ${type} accounts after export`);
  }
  if (action === 'delete') {
    await activity.log('delete_after_export_requested', 'account', null, 'Delete-after-export was requested but no records were deleted automatically');
  }
}

function csvLine(values) {
  return values.map(value => `"${String(value ?? '').replace(/"/g, '""')}"`).join(',');
}

function workflowStep(account) {
  if (!account) return 'Add or import accounts to begin.';
  if (account.email_creation_status === 'pending') return 'Create target email manually.';
  if (account.email_creation_status === 'in_progress') return 'Finish target email setup manually.';
  if (account.upgrade_status === 'pending') return 'Prepare legacy login, password, and OTP.';
  if (account.upgrade_status === 'in_progress') return 'Complete login/authenticator/upgrade manually.';
  if (account.upgrade_status === 'complete' || account.status === 'upgraded') return 'Save result locally and review export status.';
  if (account.status === 'blocked') return 'Review blocker notes before continuing.';
  return 'Review account status and choose the next manual action.';
}

function birthDate(account) {
  const parts = [account.birth_month, account.birth_day, account.birth_year].filter(Boolean);
  return parts.length ? `${account.birth_month || ''}/${account.birth_day || ''}/${account.birth_year || ''}` : '';
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
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

module.exports = { app, parseAccountImport };
