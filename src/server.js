const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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
const discordAuth = require('./discord-auth');
const { generatePassword } = require('./generators');
const { parseAccountImport, parseProxyImport } = require('./parsers');
const {
  accountTypes,
  accountStatuses,
  credentialStatuses,
  workflowStatuses,
  proxyTypes,
  proxyStatuses,
  userRoles,
  subscriptionStatuses,
  activeSubscriptionStatuses,
  exportFormats,
  workflowModes,
  workflowTypes,
  workflowDefinitionStatuses,
  workflowRunStatuses,
  workflowStepTypes,
  companionJobStatuses,
  paymentMethods
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
      imgSrc: ["'self'", 'data:', 'https://cdn.discordapp.com'],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.static(`${__dirname}/../public`));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(express.json({ limit: '1mb' }));
app.get('/healthz', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.status(200).type('text/plain').send('OK');
  } catch (error) {
    res.status(503).json({ ok: false, service: config.appName, database: 'unavailable' });
  }
});
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
app.use(attachCurrentUser);
app.use(csrf);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts. Try again soon.'
});
const companionLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many companion API requests.' }
});

app.get('/login', (req, res) => {
  if (req.currentUserId) return res.redirect('/');
  return res.render('login', { title: 'Login', error: null });
});

app.get('/auth/discord', (req, res, next) => {
  try {
    res.redirect(discordAuth.authorizationUrl(req));
  } catch (err) {
    res.status(503).render('login', { title: 'Login', error: err.message });
  }
});

app.get('/auth/discord/callback', async (req, res, next) => {
  try {
    if (!req.query.code || !req.query.state || req.query.state !== req.session.discordOAuthState) {
      throw new Error('Discord login state was missing or expired.');
    }
    const redirectUri = req.session.discordRedirectUri;
    req.session.discordOAuthState = null;
    req.session.discordRedirectUri = null;
    const token = await discordAuth.exchangeCode(req.query.code, redirectUri);
    const profile = await discordAuth.fetchDiscordProfile(token.access_token);
    const user = await discordAuth.upsertDiscordUser(profile);
    setUserSession(req, user);
    await activity.log(user.id, 'login', 'user', user.id, `Discord login succeeded for ${user.username || user.discord_username}`, { provider: 'discord' });
    res.redirect('/');
  } catch (err) { next(err); }
});

app.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const ok = config.adminFallbackEnabled && req.body.username === config.adminUsername && verifyAdminPassword(req.body.password, config);
    await activity.log(null, ok ? 'admin_login_success' : 'admin_login_failed', 'admin', null, ok ? 'Emergency admin login succeeded' : 'Emergency admin login failed');
    if (!ok) return res.status(401).render('login', { title: 'Login', error: 'Invalid admin username or password.' });
    const user = await discordAuth.upsertEmergencyAdminUser(config.adminUsername);
    setUserSession(req, user);
    await activity.log(user.id, 'login', 'user', user.id, `Emergency admin login succeeded for ${user.username || user.discord_username}`, { provider: 'admin_fallback' });
    res.redirect('/');
  } catch (err) { next(err); }
});

app.post('/api/companion/pair/complete', companionLimiter, async (req, res, next) => {
  try {
    const code = escapeText(req.body.code).toUpperCase();
    const deviceName = escapeText(req.body.device_name || req.body.deviceName || 'GS Account Manager Companion');
    if (!code) return res.status(400).json({ error: 'Pairing code is required.' });
    const codeHash = hashPairingCode(code);
    const pair = await db.query(
      `SELECT id, user_id
       FROM helper_pairing_codes
       WHERE code_hash=$1 AND used_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [codeHash]
    );
    if (!pair.rows[0]) return res.status(404).json({ error: 'Pairing code is invalid or expired.' });
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashDeviceToken(token);
    const result = await db.query(
      `INSERT INTO companion_devices (user_id, device_name, device_token_hash, companion_version, status, last_seen_at, updated_at)
       VALUES ($1, $2, $3, $4, 'connected', NOW(), NOW())
       RETURNING id, device_name, status, created_at`,
      [pair.rows[0].user_id, deviceName, tokenHash, escapeText(req.body.companion_version || req.body.version)]
    );
    await db.query('UPDATE helper_pairing_codes SET used_at=NOW() WHERE id=$1', [pair.rows[0].id]);
    await activity.log(pair.rows[0].user_id, 'companion_pair', 'companion_device', result.rows[0].id, `Companion device connected: ${deviceName}`);
    await auditLog(null, pair.rows[0].user_id, 'companion_pair', 'companion_device', result.rows[0].id, 'Companion device connected');
    res.json({ device: result.rows[0], token });
  } catch (err) { next(err); }
});

app.post('/api/companion/heartbeat', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    await db.query(
      `UPDATE companion_devices
       SET status='connected', companion_version=COALESCE($1, companion_version), last_seen_at=NOW(), updated_at=NOW()
       WHERE id=$2 AND user_id=$3`,
      [escapeText(req.body.companion_version || req.body.version) || null, device.id, device.user_id]
    );
    res.json({ ok: true, user_id: device.user_id, device_id: device.id });
  } catch (err) { next(err); }
});

app.post('/api/companion/browser/session', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const accountId = req.body.selected_account_id ? Number(req.body.selected_account_id) : null;
    const proxyId = req.body.selected_proxy_id ? Number(req.body.selected_proxy_id) : null;
    if (accountId) await assertAccountOwnership(device.user_id, accountId);
    if (proxyId) await assertProxyOwnership(device.user_id, proxyId);
    const result = await db.query(
      `INSERT INTO companion_sessions (user_id, companion_device_id, selected_account_id, selected_proxy_id, browser_status, current_url, current_domain, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING id, browser_status, current_url, current_domain, created_at, updated_at`,
      [
        device.user_id,
        device.id,
        accountId,
        proxyId,
        oneOf(req.body.browser_status, ['idle', 'opening', 'running', 'paused', 'closed', 'error'], 'idle'),
        escapeText(req.body.current_url),
        escapeText(req.body.current_domain)
      ]
    );
    res.json({ session: result.rows[0] });
  } catch (err) { next(err); }
});

app.post('/api/companion/browser/fill', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    if (accountId) await assertAccountOwnership(device.user_id, accountId);
    await auditLog(device.user_id, device.user_id, 'companion_fill_event', 'account', accountId, 'Companion fill event recorded', {
      field: escapeText(req.body.field),
      mode: 'user_triggered_fill_only'
    });
    res.json({ ok: true, message: 'Fill event recorded. Final submissions must remain user-confirmed.' });
  } catch (err) { next(err); }
});

app.post('/api/companion/status', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const windows = Array.isArray(req.body.windows) ? req.body.windows.slice(0, 20) : [req.body];
    for (const item of windows) {
      await db.query(
        `INSERT INTO companion_client_status (user_id, companion_device_id, process_name, window_title, running, metadata, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [
          device.user_id,
          device.id,
          escapeText(item.process_name || item.processName),
          escapeText(item.window_title || item.windowTitle),
          item.running !== false,
          { source: 'companion', matched_account_hint: escapeText(item.matched_account_hint || item.matchedAccountHint) }
        ]
      );
    }
    res.json({ ok: true, count: windows.length });
  } catch (err) { next(err); }
});

app.post('/api/companion/snapshot', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    if (!device.allow_screenshots) return res.status(403).json({ error: 'Snapshots are disabled for this device.' });
    const settings = await getSettings(device.user_id);
    if (settings.allow_companion_snapshots !== 'true') return res.status(403).json({ error: 'Snapshots are disabled in user settings.' });
    const base64 = String(req.body.image_base64 || '').replace(/^data:image\/[a-z]+;base64,/i, '');
    const image = base64 ? Buffer.from(base64, 'base64') : Buffer.alloc(0);
    if (!image.length || image.length > 750 * 1024) return res.status(400).json({ error: 'Snapshot must be a PNG/JPEG under 750KB.' });
    const result = await db.query(
      `INSERT INTO live_snapshots (user_id, companion_device_id, window_title, content_type, image_data, image_size)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, created_at, image_size`,
      [device.user_id, device.id, escapeText(req.body.window_title), escapeText(req.body.content_type || 'image/png'), image, image.length]
    );
    await activity.log(device.user_id, 'companion_screenshot_received', 'live_snapshot', result.rows[0].id, 'Companion snapshot received', { image_size: image.length });
    await auditLog(device.user_id, device.user_id, 'companion_screenshot_received', 'live_snapshot', result.rows[0].id, 'Companion snapshot received', { image_size: image.length });
    res.json({ snapshot: result.rows[0] });
  } catch (err) { next(err); }
});

app.get('/api/companion/jobs/next', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const result = await db.query(
      `UPDATE companion_jobs
       SET status='accepted',
           companion_device_id=COALESCE(companion_device_id, $1),
           accepted_at=COALESCE(accepted_at, NOW()),
           updated_at=NOW()
       WHERE id = (
         SELECT id
         FROM companion_jobs
         WHERE user_id=$2
           AND status='queued'
           AND (companion_device_id IS NULL OR companion_device_id=$1)
         ORDER BY created_at ASC
         LIMIT 1
       )
       RETURNING *`,
      [device.id, device.user_id]
    );
    const job = result.rows[0];
    if (!job) return res.json({ job: null });
    if (job.workflow_run_id) {
      await db.query(
        `UPDATE workflow_runs
         SET status='running', companion_device_id=$1, started_at=COALESCE(started_at, NOW()), updated_at=NOW()
         WHERE id=$2 AND user_id=$3 AND status IN ('queued','paused','waiting_for_user')`,
        [device.id, job.workflow_run_id, device.user_id]
      );
      await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, 'accepted_by_companion', 'Companion accepted workflow job.', { companion_job_id: job.id });
    }
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, 'accepted', 'Companion accepted job.');
    res.json({ job: safeCompanionJob(job) });
  } catch (err) { next(err); }
});

app.post('/api/companion/jobs/:id/status', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const status = oneOf(req.body.status, companionJobStatuses, 'running');
    const message = escapeText(req.body.message);
    const job = await loadCompanionJobForDevice(device, req.params.id);
    const completed = ['completed', 'failed', 'cancelled'].includes(status);
    const runStatus = workflowRunStatusFromJob(status);
    await db.query(
      `UPDATE companion_jobs
       SET status=$1, result=COALESCE($2, result), updated_at=NOW(), completed_at=CASE WHEN $3 THEN NOW() ELSE completed_at END
       WHERE id=$4 AND user_id=$5`,
      [status, safeJobResult(req.body.result || {}), completed, job.id, device.user_id]
    );
    if (job.workflow_run_id) {
      await db.query(
        `UPDATE workflow_runs
         SET status=$1, completed_at=CASE WHEN $2 THEN NOW() ELSE completed_at END, updated_at=NOW()
         WHERE id=$3 AND user_id=$4`,
        [runStatus, completed, job.workflow_run_id, device.user_id]
      );
      await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, status, message || `Companion job ${status}.`, { companion_job_id: job.id });
    }
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, status, message || `Job ${status}.`, req.body.metadata || {});
    if (status === 'completed') await activity.log(device.user_id, 'workflow_completed', 'workflow_run', job.workflow_run_id, 'Workflow completed by companion');
    if (status === 'failed') await activity.log(device.user_id, 'workflow_failed', 'workflow_run', job.workflow_run_id, 'Workflow failed in companion');
    res.json({ ok: true, status });
  } catch (err) { next(err); }
});

app.post('/api/companion/jobs/:id/events', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const job = await loadCompanionJobForDevice(device, req.params.id);
    const eventType = escapeText(req.body.event_type || req.body.type || 'status');
    const message = escapeText(req.body.message);
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, eventType, message, req.body.metadata || {});
    if (job.workflow_run_id) await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, eventType, message, { companion_job_id: job.id });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get('/api/companion/accounts/:id/field/:field', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid companion token.' });
    const { account, decrypted } = await loadAccount(device.user_id, req.params.id);
    const field = escapeText(req.params.field);
    const value = accountFieldForCompanion(account, decrypted, field);
    await activity.log(device.user_id, 'companion_field_requested', 'account', account.id, `Companion requested ${field}`, { field });
    await auditLog(device.user_id, device.user_id, 'companion_field_requested', 'account', account.id, `Companion requested ${field}`, { field });
    res.json({ field, value });
  } catch (err) { next(err); }
});

app.use(requireAuth, requireUserRecord);

app.post('/logout', requireAuth, async (req, res, next) => {
  try {
    await activity.log(req.currentUserId, 'logout', 'user', req.currentUserId, `Logout for ${req.currentUser && req.currentUser.username ? req.currentUser.username : 'user'}`);
    req.session.destroy(() => res.redirect('/login'));
  } catch (err) {
    next(err);
  }
});

app.get('/locked', requireAuth, (req, res) => {
  if (hasAppAccess(req.currentUserRecord)) return res.redirect('/');
  res.status(403).render('locked', { title: 'Access Locked', lockedShell: true });
});

app.use(requireActiveSubscription);

app.post('/api/companion/pair/start', companionLimiter, requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await db.query(
      `UPDATE helper_pairing_codes
       SET expires_at=NOW()
       WHERE user_id=$1 AND used_at IS NULL AND expires_at > NOW()`,
      [userId]
    );
    await db.query(
      `INSERT INTO helper_pairing_codes (user_id, code_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, hashPairingCode(code), expiresAt]
    );
    await activity.log(userId, 'companion_pairing_started', 'companion', null, 'Generated companion pairing code');
    res.json({ code, expires_at: expiresAt.toISOString() });
  } catch (err) { next(err); }
});

app.get('/api/companion/devices', requireAuth, async (req, res, next) => {
  try {
    const rows = await db.query(
      `SELECT id, device_name, companion_version, status, allow_screenshots, last_seen_at, revoked_at, created_at, updated_at
       FROM companion_devices
       WHERE user_id=$1
       ORDER BY updated_at DESC`,
      [req.currentUserId]
    );
    res.json({ devices: rows.rows });
  } catch (err) { next(err); }
});

app.post('/api/companion/devices/:id/revoke', requireAuth, async (req, res, next) => {
  try {
    const result = await db.query(
      `UPDATE companion_devices
       SET status='revoked', revoked_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND user_id=$2
       RETURNING id, device_name`,
      [req.params.id, req.currentUserId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Companion device not found.' });
    await activity.log(req.currentUserId, 'companion_revoke', 'companion_device', result.rows[0].id, `Revoked companion device ${result.rows[0].device_name || result.rows[0].id}`);
    await auditLog(req.currentUserId, req.currentUserId, 'companion_revoke', 'companion_device', result.rows[0].id, 'Revoked companion device');
    res.json({ ok: true, device: result.rows[0] });
  } catch (err) { next(err); }
});

app.get('/admin', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const [userCounts, userTotals, accountCounts, proxyCounts, companionCounts, auditRows] = await Promise.all([
      db.query(`SELECT subscription_status, COUNT(*)::int count FROM users GROUP BY subscription_status`),
      db.query(`SELECT
        COUNT(*)::int total,
        COUNT(*) FILTER (WHERE subscription_status='active')::int active,
        COUNT(*) FILTER (WHERE subscription_status='inactive')::int inactive,
        COUNT(*) FILTER (WHERE subscription_status='banned')::int banned
       FROM users`),
      db.query(`SELECT COUNT(*)::int total FROM accounts`),
      db.query(`SELECT COUNT(*)::int total FROM proxies`),
      db.query(`SELECT status, COUNT(*)::int count FROM companion_devices GROUP BY status`),
      db.query(`SELECT a.*, COALESCE(actor.global_name, actor.username, actor.discord_username) actor_name,
                        COALESCE(target.global_name, target.username, target.discord_username) target_name
                 FROM audit_logs a
                 LEFT JOIN users actor ON actor.id = a.actor_user_id
                 LEFT JOIN users target ON target.id = a.user_id
                 ORDER BY a.created_at DESC
                 LIMIT 25`)
    ]);
    res.render('admin/dashboard', {
      title: 'Admin',
      userCounts: userCounts.rows,
      userTotals: userTotals.rows[0],
      accountCount: accountCounts.rows[0].total,
      proxyCount: proxyCounts.rows[0].total,
      companionCounts: companionCounts.rows,
      auditLogs: auditRows.rows
    });
  } catch (err) { next(err); }
});

app.get('/admin/users', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const users = await db.query(
      `SELECT u.id, u.discord_id, u.username, u.global_name, u.avatar, u.email,
              u.discord_username, u.discord_email, u.role, u.subscription_status,
              u.created_at, u.updated_at, u.last_login_at, u.disabled_at,
              COUNT(DISTINCT a.id)::int account_count,
              COUNT(DISTINCT p.id)::int proxy_count
       FROM users u
       LEFT JOIN accounts a ON a.user_id = u.id
       LEFT JOIN proxies p ON p.user_id = u.id
       GROUP BY u.id
       ORDER BY u.created_at DESC, u.id DESC`
    );
    res.render('admin/users', {
      title: 'Admin Users',
      users: users.rows,
      userRoles,
      subscriptionStatuses
    });
  } catch (err) { next(err); }
});

app.post('/admin/users/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const targetId = Number(req.params.id);
    const role = oneOf(req.body.role, userRoles, 'user');
    const subscriptionStatus = oneOf(req.body.subscription_status, subscriptionStatuses, 'inactive');
    if (targetId === req.currentUserId && role !== 'admin') {
      throw new Error('Admins cannot remove their own admin role.');
    }
    const before = await db.query('SELECT * FROM users WHERE id=$1', [targetId]);
    if (!before.rows[0]) throw new Error('User not found.');
    const disabledAtSql = subscriptionStatus === 'banned' ? 'NOW()' : 'NULL';
    const disabledBySql = subscriptionStatus === 'banned' ? '$4' : 'NULL';
    const result = await db.query(
      `UPDATE users
       SET role=$1,
           subscription_status=$2,
           disabled_at=${disabledAtSql},
           disabled_by_user_id=${disabledBySql},
           updated_at=NOW()
       WHERE id=$3
       RETURNING *`,
      subscriptionStatus === 'banned'
        ? [role, subscriptionStatus, targetId, req.currentUserId]
        : [role, subscriptionStatus, targetId]
    );
    const user = result.rows[0];
    await discordAuth.claimUnownedDataForAdmin(user);
    if (before.rows[0].subscription_status !== user.subscription_status) {
      await activity.log(user.id, 'subscription_status_changed_by_admin', 'user', user.id, `Subscription status changed to ${user.subscription_status}`, {
        actor_user_id: req.currentUserId,
        previous_subscription_status: before.rows[0].subscription_status,
        subscription_status: user.subscription_status
      });
      await auditLog(req.currentUserId, user.id, 'admin_changed_subscription', 'user', user.id, `Subscription status changed to ${user.subscription_status}`, {
        previous_subscription_status: before.rows[0].subscription_status,
        subscription_status: user.subscription_status
      });
    }
    if (before.rows[0].role !== user.role) {
      await activity.log(user.id, 'role_changed_by_admin', 'user', user.id, `Role changed to ${user.role}`, {
        actor_user_id: req.currentUserId,
        previous_role: before.rows[0].role,
        role: user.role
      });
      await auditLog(req.currentUserId, user.id, 'admin_changed_role', 'user', user.id, `Role changed to ${user.role}`, {
        previous_role: before.rows[0].role,
        role: user.role
      });
    }
    res.redirect('/admin/users');
  } catch (err) { next(err); }
});

app.get('/', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const settings = await getSettings(userId);
    const selectedId = req.query.account_id;
    const [counts, recent, proxyCounts, selectable, helper, dashboardStats, latestExport] = await Promise.all([
      db.query(`SELECT status, COUNT(*)::int count FROM accounts WHERE user_id=$1 GROUP BY status`, [userId]),
      db.query(`SELECT * FROM activity_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 8`, [userId]),
      db.query(`SELECT status, COUNT(*)::int count FROM proxies WHERE user_id=$1 GROUP BY status`, [userId]),
      db.query(`SELECT id, username, legacy_login, display_name, status, upgrade_status FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 100`, [userId]),
      helperStatus(userId),
      db.query(
        `SELECT
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1) total_accounts,
          (SELECT COUNT(*)::int FROM proxies WHERE user_id=$1) total_proxies,
          (SELECT COUNT(*)::int FROM workflow_runs WHERE user_id=$1 AND status IN ('queued','running','paused','waiting_for_user')) active_workflows,
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_companions`,
        [userId]
      ),
      db.query(`SELECT * FROM export_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, [userId])
    ]);
    let selected = null;
    let decrypted = {};
    if (selectedId) ({ account: selected, decrypted } = await loadAccount(userId, selectedId));
    else {
      const current = await db.query(
        `SELECT id FROM accounts
         WHERE user_id=$1 AND archived_at IS NULL AND status <> 'archived'
         ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'needs_review' THEN 1 WHEN 'pending' THEN 2 ELSE 3 END, updated_at DESC
         LIMIT 1`, [userId]
      );
      if (current.rows[0]) ({ account: selected, decrypted } = await loadAccount(userId, current.rows[0].id));
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
      helper,
      dashboardStats: dashboardStats.rows[0],
      latestExport: latestExport.rows[0] || null,
      proxyMode: proxyMode(selected, helper, settings),
      nextStep,
      mask
    });
  } catch (err) { next(err); }
});

app.get('/accounts', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const filters = {
      q: escapeText(req.query.q),
      account_type: escapeText(req.query.account_type),
      status: escapeText(req.query.status),
      category: escapeText(req.query.category),
      country_code: escapeText(req.query.country_code),
      has_proxy: escapeText(req.query.has_proxy),
      has_otp: escapeText(req.query.has_otp),
      created_date: escapeText(req.query.created_date),
      archived: escapeText(req.query.archived)
    };
    const clauses = ['a.user_id = $1'];
    const params = [userId];
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
    if (filters.archived === 'yes') clauses.push('a.archived_at IS NOT NULL OR a.status = \'archived\'');
    if (filters.archived === 'no') clauses.push('a.archived_at IS NULL AND a.status <> \'archived\'');
    if (filters.created_date === 'today') clauses.push(`a.created_at >= CURRENT_DATE`);
    if (filters.created_date === '7d') clauses.push(`a.created_at >= NOW() - INTERVAL '7 days'`);
    if (filters.created_date === '30d') clauses.push(`a.created_at >= NOW() - INTERVAL '30 days'`);
    if (filters.created_date === 'older_30d') clauses.push(`a.created_at < NOW() - INTERVAL '30 days'`);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const [rows, stats, categories, proxyCategories, countries, proxies, settings] = await Promise.all([
      db.query(
        `SELECT a.*, p.host proxy_host, p.port proxy_port, p.status proxy_status, p.proxy_type
         FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id) AND p.user_id = a.user_id
         ${where} ORDER BY a.updated_at DESC LIMIT 300`, params
      ),
      db.query(
        `SELECT
          COUNT(*)::int total,
          COUNT(*) FILTER (WHERE account_type='legacy')::int legacy,
          COUNT(*) FILTER (WHERE account_type='jagex')::int jagex,
          COUNT(*) FILTER (WHERE COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) IS NOT NULL)::int with_proxy,
          COUNT(*) FILTER (WHERE COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) IS NULL)::int without_proxy,
          COUNT(*) FILTER (WHERE status='available')::int active,
          COUNT(*) FILTER (WHERE status='in_progress')::int in_progress,
          COUNT(*) FILTER (WHERE status='completed')::int completed,
          COUNT(*) FILTER (WHERE status='archived' OR archived_at IS NOT NULL)::int archived
         FROM accounts WHERE user_id=$1`,
        [userId]
      ),
      db.query(`SELECT DISTINCT category FROM accounts WHERE user_id=$1 AND category IS NOT NULL AND category <> '' ORDER BY category`, [userId]),
      db.query(`SELECT DISTINCT category FROM proxies WHERE user_id=$1 AND category IS NOT NULL AND category <> '' ORDER BY category`, [userId]),
      db.query(`SELECT DISTINCT country_code FROM accounts WHERE user_id=$1 AND country_code IS NOT NULL AND country_code <> '' ORDER BY country_code`, [userId]),
      db.query(`SELECT id, name, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      getSettings(userId)
    ]);
    res.render('accounts/index', {
      title: 'Accounts',
      accounts: rows.rows,
      stats: stats.rows[0],
      categories: categories.rows.map(row => row.category),
      proxyCategories: proxyCategories.rows.map(row => row.category),
      countries: countries.rows.map(row => row.country_code),
      proxies: proxies.rows,
      filters,
      settings,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.get('/accounts/new', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const proxies = await db.query('SELECT id, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY host', [userId]);
    res.render('accounts/form', { title: 'New Account', account: { account_type: 'legacy', status: 'pending', credential_status: 'partial', upgrade_status: 'pending', email_creation_status: 'pending' }, decrypted: {}, proxies: proxies.rows, errors: [], generatedPassword: generatePassword(await passwordLength(userId)) });
  } catch (err) { next(err); }
});

app.post('/accounts', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const account = accountFromBody(req.body);
    await enforceProxyOwnership(userId, account);
    if (!account.username || !account.legacy_password) throw new Error('Login and password are required.');
    const result = await db.query(accountInsertSql(), accountParams(account, userId));
    await activity.log(userId, 'account_created', 'account', result.rows[0].id, `Created account ${mask(account.username)}`, { account_type: account.account_type });
    res.redirect(`/accounts/${result.rows[0].id}`);
  } catch (err) { next(err); }
});

app.post('/accounts/import', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    if (req.body.confirm_import !== 'yes') throw new Error('Preview the account import before confirming.');
    const rows = parseAccountImport(req.body.accounts_text || '', req.body.delimiter || ':', { account_type: req.body.account_type, import_format: req.body.import_format });
    await markDuplicates(userId, rows);
    let imported = 0;
    let skipped = 0;
    for (const row of rows) {
      if (!row.valid || row.duplicate) {
        skipped += 1;
        continue;
      }
      const account = accountFromImport(row, req.body);
      const result = await db.query(accountInsertSql('ON CONFLICT (user_id, username) DO NOTHING'), accountParams(account, userId));
      if (result.rowCount) imported += 1;
      else skipped += 1;
    }
    await recordImportExportRun(userId, 'import_accounts', imported, req.body.account_type || null, {
      skipped,
      delimiter: req.body.delimiter || ':',
      account_category: escapeText(req.body.category),
      proxy_category: escapeText(req.body.proxy_category),
      country_code: escapeText(req.body.country_code).toUpperCase()
    });
    await activity.log(userId, 'import', 'account', null, `Imported ${imported} account line(s)`, { skipped, account_type: req.body.account_type || 'legacy' });
    await auditLog(userId, userId, 'import', 'account', null, `Imported ${imported} account line(s)`, { skipped, account_type: req.body.account_type || 'legacy' });
    res.redirect(`/accounts?imported=${imported}&skipped=${skipped}`);
  } catch (err) { next(err); }
});

app.post('/accounts/export', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    let selectedIds = selectedAccountIds(req.body);
    if (req.body.export_scope === 'filtered') selectedIds = await filteredAccountIds(userId, req.body);
    if (!selectedIds.length) throw new Error('Select at least one account to export.');
    const format = oneOf(req.body.export_format || req.body.format, exportFormats, 'username_password');
    const delimiter = normalizeDelimiter(req.body.delimiter || ':');
    const exportResult = await buildSelectedAccountExport(userId, {
      account_ids: selectedIds,
      format,
      delimiter,
      custom_fields: req.body.custom_fields,
      include_sensitive: req.body.include_sensitive !== 'no',
      include_account_type: req.body.include_account_type === 'yes',
      include_proxy: req.body.include_proxy === 'yes',
      include_notes: req.body.include_notes === 'yes',
      include_otp_secret: req.body.include_otp_secret === 'yes'
    });
    if (!exportResult.rows.length) throw new Error('No selected accounts were available to export.');
    const filename = `gs-accounts-${new Date().toISOString().slice(0, 10)}.txt`;
    const postExportAction = escapeText(req.body.post_export_action || 'keep');
    const deleteAfterExport = req.body.delete_after_export === 'yes' || postExportAction === 'delete';
    const confirmDelete = req.body.confirm_delete_after_export === 'yes';
    await recordImportExportRun(userId, 'export_accounts', exportResult.rows.length, format, {
      selected_count: selectedIds.length,
      export_action: postExportAction,
      delete_after_export: deleteAfterExport && confirmDelete
    });
    await activity.log(userId, 'export', 'account', null, `Exported ${exportResult.rows.length} selected account(s)`, { format, selected_count: selectedIds.length });
    await auditLog(userId, userId, 'export', 'account', null, `Exported ${exportResult.rows.length} selected account(s)`, { format, selected_count: selectedIds.length });
    if (postExportAction === 'archive') {
      await db.query(
        `UPDATE accounts
         SET status='archived', archived_at=COALESCE(archived_at, NOW()), exported_at=NOW(), updated_at=NOW()
         WHERE user_id=$1 AND id = ANY($2)`,
        [userId, exportResult.accountIds]
      );
      await activity.log(userId, 'archive_after_export', 'account', null, `Archived ${exportResult.accountIds.length} exported account(s)`, { count: exportResult.accountIds.length });
      await auditLog(userId, userId, 'archive_after_export', 'account', null, `Archived ${exportResult.accountIds.length} exported account(s)`, { count: exportResult.accountIds.length });
    } else if (deleteAfterExport) {
      if (!confirmDelete) throw new Error('Delete after export requires the second confirmation.');
      const deleted = await db.query(
        `DELETE FROM accounts
         WHERE user_id=$1 AND id = ANY($2)
         RETURNING id`,
        [userId, exportResult.accountIds]
      );
      await activity.log(userId, 'delete_after_export', 'account', null, `Deleted ${deleted.rowCount} exported account(s) after TXT generation`, { deleted_count: deleted.rowCount });
      await auditLog(userId, userId, 'delete_after_export', 'account', null, `Deleted ${deleted.rowCount} exported account(s) after TXT generation`, { deleted_count: deleted.rowCount });
    } else {
      await db.query('UPDATE accounts SET exported_at=NOW(), updated_at=NOW() WHERE user_id=$1 AND id = ANY($2)', [userId, exportResult.accountIds]);
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(`${exportResult.rows.join('\n')}\n`);
  } catch (err) { next(err); }
});

app.post('/accounts/bulk', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const selectedIds = selectedAccountIds(req.body);
    if (!selectedIds.length) throw new Error('Select at least one account.');
    const action = escapeText(req.body.bulk_action);
    let affected = 0;
    if (action === 'archive') {
      const result = await db.query(
        `UPDATE accounts SET status='archived', archived_at=COALESCE(archived_at, NOW()), updated_at=NOW()
         WHERE user_id=$1 AND id = ANY($2) RETURNING id`,
        [userId, selectedIds]
      );
      affected = result.rowCount;
      await activity.log(userId, 'archive', 'account', null, `Archived ${affected} selected account(s)`, { count: affected });
    } else if (action === 'delete') {
      if (req.body.confirm_bulk_delete !== 'yes') throw new Error('Bulk delete requires confirmation.');
      const result = await db.query('DELETE FROM accounts WHERE user_id=$1 AND id = ANY($2) RETURNING id', [userId, selectedIds]);
      affected = result.rowCount;
      await activity.log(userId, 'delete', 'account', null, `Deleted ${affected} selected account(s)`, { count: affected });
    } else if (action === 'assign_proxy') {
      const proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : null;
      if (proxyId) await assertProxyOwnership(userId, proxyId);
      const result = await db.query(
        `UPDATE accounts SET proxy_id=$1, assigned_http_proxy_id=$1, updated_at=NOW()
         WHERE user_id=$2 AND id = ANY($3) RETURNING id`,
        [proxyId, userId, selectedIds]
      );
      affected = result.rowCount;
      await activity.log(userId, 'bulk_assign_proxy', 'account', null, `Assigned proxy to ${affected} account(s)`, { count: affected, proxy_id: proxyId });
    } else if (action === 'assign_category_status') {
      const category = escapeText(req.body.bulk_category);
      const status = oneOf(req.body.bulk_status, accountStatuses, 'pending');
      const result = await db.query(
        `UPDATE accounts
         SET category=COALESCE(NULLIF($1, ''), category), status=$2, updated_at=NOW()
         WHERE user_id=$3 AND id = ANY($4) RETURNING id`,
        [category, status, userId, selectedIds]
      );
      affected = result.rowCount;
      await activity.log(userId, 'bulk_assign_category_status', 'account', null, `Updated ${affected} selected account(s)`, { count: affected, status });
    } else {
      throw new Error('Unsupported bulk action.');
    }
    await auditLog(userId, userId, action, 'account', null, `Bulk account action ${action} affected ${affected} account(s)`, { count: affected });
    res.redirect(`/accounts?bulk=${encodeURIComponent(action)}&affected=${affected}`);
  } catch (err) { next(err); }
});

app.get('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const { account, decrypted } = await loadAccount(userId, req.params.id);
    const proxies = await db.query('SELECT id, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY host', [userId]);
    let otp = null;
    if (decrypted.otp_secret) {
      try { otp = currentTotp(decrypted.otp_secret); } catch (error) { otp = { error: 'Invalid OTP secret' }; }
    }
    res.render('accounts/form', { title: 'Edit Account', account, decrypted, proxies: proxies.rows, otp, errors: [], generatedPassword: generatePassword(await passwordLength(userId)) });
  } catch (err) { next(err); }
});

app.post('/accounts/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const existing = await loadAccount(userId, req.params.id);
    const account = accountFromBody(req.body, existing.decrypted);
    await enforceProxyOwnership(userId, account);
    if (!account.username || !account.legacy_password) throw new Error('Login and password are required.');
    const archive = existing.account.status !== 'upgraded' && account.status === 'upgraded';
    await db.query(accountUpdateSql(), [...accountParams(account, userId), archive, req.params.id]);
    await activity.log(userId, 'account_updated', 'account', req.params.id, `Updated account ${mask(account.username)}`, { status: account.status, upgrade_status: account.upgrade_status });
    res.redirect(`/accounts/${req.params.id}`);
  } catch (err) { next(err); }
});

app.post('/accounts/:id/delete', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `DELETE FROM accounts
       WHERE id=$1 AND user_id=$2
       RETURNING id, username, legacy_login`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Account not found.');
    await activity.log(userId, 'account_deleted', 'account', result.rows[0].id, `Deleted account ${mask(result.rows[0].legacy_login || result.rows[0].username)}`);
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.post('/accounts/:id/archive', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `UPDATE accounts
       SET status='archived', archived_at=COALESCE(archived_at, NOW()), updated_at=NOW()
       WHERE id=$1 AND user_id=$2
       RETURNING id, username, legacy_login`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Account not found.');
    await activity.log(userId, 'archive', 'account', result.rows[0].id, `Archived account ${mask(result.rows[0].legacy_login || result.rows[0].username)}`);
    await auditLog(userId, userId, 'archive', 'account', result.rows[0].id, 'Archived account');
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.get('/accounts/:id/copy/:field', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const { account, decrypted } = await loadAccount(userId, req.params.id);
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
    const action = sensitiveCopyField(field) ? 'copy_secret' : 'field_copied';
    await activity.log(userId, action, 'account', account.id, `Copied ${field}`, { field });
    if (action === 'copy_secret') await auditLog(userId, userId, action, 'account', account.id, `Copied ${field}`, { field });
    res.json({ value });
  } catch (err) { next(err); }
});

app.get('/accounts/:id/reveal/:field', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const { account, decrypted } = await loadAccount(userId, req.params.id);
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
    await activity.log(userId, 'reveal_secret', 'account', account.id, `Revealed ${field}`, { field });
    await auditLog(userId, userId, 'reveal_secret', 'account', account.id, `Revealed ${field}`, { field });
    res.json({ value });
  } catch (err) { next(err); }
});

app.get('/generate/password', requireAuth, async (req, res) => {
  const length = Number(req.query.length || await passwordLength(req.currentUserId));
  res.json({ value: generatePassword(length) });
});

app.get('/workflows', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    await ensureStarterWorkflows(userId);
    const [workflows, runs, accounts, proxies, devices, counts] = await Promise.all([
      db.query(
        `SELECT w.*, COUNT(s.id)::int step_count
         FROM workflows w
         LEFT JOIN workflow_steps s ON s.workflow_id=w.id AND s.user_id=w.user_id
         WHERE w.user_id=$1
         GROUP BY w.id
         ORDER BY CASE w.status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 ELSE 2 END, w.updated_at DESC`,
        [userId]
      ),
      db.query(
        `SELECT r.*, w.name workflow_name, a.username account_username, a.legacy_login account_legacy_login, a.display_name account_display_name
         FROM workflow_runs r
         LEFT JOIN workflows w ON w.id=r.workflow_id AND w.user_id=r.user_id
         LEFT JOIN accounts a ON a.id=r.account_id AND a.user_id=r.user_id
         WHERE r.user_id=$1
         ORDER BY r.created_at DESC
         LIMIT 25`,
        [userId]
      ),
      db.query(`SELECT id, username, legacy_login, display_name, account_type, status FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, device_name, status, last_seen_at FROM companion_devices WHERE user_id=$1 AND status <> 'revoked' ORDER BY last_seen_at DESC NULLS LAST`, [userId]),
      db.query(`SELECT status, COUNT(*)::int count FROM workflow_runs WHERE user_id=$1 GROUP BY status`, [userId])
    ]);
    res.render('workflows/index', {
      title: 'Workflows',
      workflows: workflows.rows,
      runs: runs.rows,
      accounts: accounts.rows,
      proxies: proxies.rows,
      devices: devices.rows,
      counts: counts.rows,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.post('/workflows', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const template = oneOf(req.body.template, workflowTypes, 'generic_form_fill');
    const name = escapeText(req.body.name) || workflowTemplateName(template);
    const description = escapeText(req.body.description) || workflowTemplateDescription(template);
    const result = await db.query(
      `INSERT INTO workflows (user_id, name, description, type, status, updated_at)
       VALUES ($1, $2, $3, $4, 'active', NOW())
       RETURNING id`,
      [userId, name, description, template]
    );
    await replaceWorkflowSteps(userId, result.rows[0].id, workflowTemplateSteps(template));
    await activity.log(userId, 'workflow_created', 'workflow', result.rows[0].id, `Created workflow ${name}`, { type: template });
    res.redirect(`/workflows/${result.rows[0].id}/edit`);
  } catch (err) { next(err); }
});

app.get('/workflows/runs/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const run = await loadWorkflowRun(userId, req.params.id);
    const [events, jobEvents, snapshot] = await Promise.all([
      db.query(`SELECT * FROM workflow_run_events WHERE user_id=$1 AND workflow_run_id=$2 ORDER BY created_at DESC LIMIT 100`, [userId, run.id]),
      db.query(`SELECT e.* FROM companion_job_events e JOIN companion_jobs j ON j.id=e.companion_job_id AND j.user_id=e.user_id WHERE e.user_id=$1 AND j.workflow_run_id=$2 ORDER BY e.created_at DESC LIMIT 100`, [userId, run.id]),
      db.query(`SELECT id, window_title, image_size, created_at FROM live_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, [userId])
    ]);
    res.render('workflows/run', { title: 'Workflow Run', run, events: events.rows, jobEvents: jobEvents.rows, snapshot: snapshot.rows[0] || null });
  } catch (err) { next(err); }
});

app.post('/workflows/runs/:id/continue', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const run = await loadWorkflowRun(userId, req.params.id);
    await db.query(`UPDATE workflow_runs SET status='running', updated_at=NOW() WHERE id=$1 AND user_id=$2`, [run.id, userId]);
    await insertWorkflowRunEvent(userId, run.id, 'user_continue', 'User confirmed manual step and continued.');
    await activity.log(userId, 'workflow_user_continue', 'workflow_run', run.id, 'User continued workflow after manual step');
    res.redirect(`/workflows/runs/${run.id}`);
  } catch (err) { next(err); }
});

app.post('/workflows/runs/:id/cancel', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const run = await loadWorkflowRun(userId, req.params.id);
    await db.query(`UPDATE workflow_runs SET status='cancelled', completed_at=NOW(), updated_at=NOW() WHERE id=$1 AND user_id=$2`, [run.id, userId]);
    await db.query(`UPDATE companion_jobs SET status='cancelled', updated_at=NOW(), completed_at=NOW() WHERE user_id=$1 AND workflow_run_id=$2 AND status NOT IN ('completed','failed','cancelled')`, [userId, run.id]);
    await insertWorkflowRunEvent(userId, run.id, 'cancelled', 'Workflow cancelled by user.');
    await activity.log(userId, 'workflow_cancelled', 'workflow_run', run.id, 'Workflow cancelled by user');
    res.redirect(`/workflows/runs/${run.id}`);
  } catch (err) { next(err); }
});

app.get('/workflows/:id/edit', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const workflow = await loadWorkflow(userId, req.params.id);
    const steps = await db.query(`SELECT * FROM workflow_steps WHERE user_id=$1 AND workflow_id=$2 ORDER BY step_order`, [userId, workflow.id]);
    res.render('workflows/form', {
      title: 'Edit Workflow',
      workflow,
      steps: steps.rows,
      stepsJson: JSON.stringify(steps.rows.map(step => ({
        step_order: step.step_order,
        step_type: step.step_type,
        label: step.label,
        manual_pause: step.manual_pause,
        config: step.config
      })), null, 2)
    });
  } catch (err) { next(err); }
});

app.post('/workflows/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const workflow = await loadWorkflow(userId, req.params.id);
    const name = escapeText(req.body.name);
    if (!name) throw new Error('Workflow name is required.');
    const status = oneOf(req.body.status, workflowDefinitionStatuses, 'active');
    const type = oneOf(req.body.type, workflowTypes, workflow.type || 'custom');
    await db.query(
      `UPDATE workflows SET name=$1, description=$2, type=$3, status=$4, updated_at=NOW() WHERE id=$5 AND user_id=$6`,
      [name, escapeText(req.body.description), type, status, workflow.id, userId]
    );
    const steps = parseWorkflowStepsJson(req.body.steps_json || '[]');
    await replaceWorkflowSteps(userId, workflow.id, steps);
    await activity.log(userId, 'workflow_updated', 'workflow', workflow.id, `Updated workflow ${name}`, { type, status });
    res.redirect(`/workflows/${workflow.id}/edit`);
  } catch (err) { next(err); }
});

app.post('/workflows/:id/run', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const workflow = await loadWorkflow(userId, req.params.id);
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    const proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : null;
    const deviceId = req.body.companion_device_id ? Number(req.body.companion_device_id) : null;
    if (accountId) await assertAccountOwnership(userId, accountId);
    if (proxyId) await assertProxyOwnership(userId, proxyId);
    if (deviceId) await assertDeviceOwnership(userId, deviceId);
    const steps = await db.query(`SELECT * FROM workflow_steps WHERE user_id=$1 AND workflow_id=$2 ORDER BY step_order`, [userId, workflow.id]);
    if (!steps.rows.length) throw new Error('Workflow has no steps.');
    const run = await db.query(
      `INSERT INTO workflow_runs (user_id, workflow_id, account_id, proxy_id, companion_device_id, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'queued', NOW(), NOW())
       RETURNING id`,
      [userId, workflow.id, accountId, proxyId, deviceId]
    );
    const payload = await workflowJobPayload(userId, workflow, steps.rows, { accountId, proxyId, deviceId });
    const job = await db.query(
      `INSERT INTO companion_jobs (user_id, companion_device_id, workflow_id, workflow_run_id, account_id, proxy_id, job_type, status, payload, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'workflow_run', 'queued', $7, NOW())
       RETURNING id`,
      [userId, deviceId, workflow.id, run.rows[0].id, accountId, proxyId, payload]
    );
    await insertWorkflowRunEvent(userId, run.rows[0].id, 'queued', 'Workflow queued for companion.', { companion_job_id: job.rows[0].id });
    await activity.log(userId, 'workflow_started', 'workflow_run', run.rows[0].id, `Queued workflow ${workflow.name}`, { workflow_id: workflow.id });
    await auditLog(userId, userId, 'workflow_started', 'workflow_run', run.rows[0].id, `Queued workflow ${workflow.name}`, { workflow_id: workflow.id });
    res.redirect(`/workflows/runs/${run.rows[0].id}`);
  } catch (err) { next(err); }
});

app.get('/workflow', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const settings = await getSettings(userId);
    const [accounts, helper] = await Promise.all([
      db.query(`SELECT id, username, legacy_login, display_name, status, account_type, upgrade_status FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 100`, [userId]),
      helperStatus(userId)
    ]);
    let selected = null;
    let decrypted = {};
    if (req.query.account_id) ({ account: selected, decrypted } = await loadAccount(userId, req.query.account_id));
    else if (accounts.rows[0]) ({ account: selected, decrypted } = await loadAccount(userId, accounts.rows[0].id));
    res.render('workflow', { title: 'Workflow', accounts: accounts.rows, selected, decrypted, settings, helper, proxyMode: proxyMode(selected, helper, settings), mask, nextStep: workflowStep(selected) });
  } catch (err) { next(err); }
});

app.post('/workflow/:id/status', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const status = oneOf(req.body.status, accountStatuses, 'needs_review');
    const upgradeStatus = status === 'upgraded' ? 'complete' : status === 'in_progress' ? 'in_progress' : status === 'skipped' ? 'skipped' : status === 'blocked' ? 'blocked' : 'needs_review';
    await db.query(
      `UPDATE accounts SET status=$1, upgrade_status=$2, exported_at=CASE WHEN $1='exported' THEN NOW() ELSE exported_at END,
       archived_at=CASE WHEN $1='archived' THEN NOW() ELSE archived_at END, updated_at=NOW() WHERE id=$3 AND user_id=$4`,
      [status, oneOf(upgradeStatus, workflowStatuses, 'needs_review'), req.params.id, userId]
    );
    await activity.log(userId, 'workflow_status_changed', 'account', req.params.id, `Workflow status changed to ${status}`, { status });
    res.redirect(`/workflow?account_id=${req.params.id}`);
  } catch (err) { next(err); }
});

app.get('/proxies', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [rows, counts, settings, categories] = await Promise.all([
      db.query(`SELECT p.*, COUNT(a.id)::int assigned_count FROM proxies p LEFT JOIN accounts a ON COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id AND a.user_id=p.user_id WHERE p.user_id=$1 GROUP BY p.id ORDER BY p.updated_at DESC`, [userId]),
      db.query(`SELECT
        COUNT(*)::int total,
        COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM accounts a WHERE a.user_id=p.user_id AND COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id))::int assigned,
        COUNT(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.user_id=p.user_id AND COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id))::int unassigned,
        COUNT(*) FILTER (WHERE status IN ('online','works'))::int online,
        COUNT(*) FILTER (WHERE status='blocked')::int blocked,
        COUNT(*) FILTER (WHERE status='review')::int review
       FROM proxies p WHERE p.user_id=$1`, [userId]),
      getSettings(userId),
      db.query(`SELECT DISTINCT category FROM proxies WHERE user_id=$1 AND category IS NOT NULL AND category <> '' ORDER BY category`, [userId])
    ]);
    res.render('proxies', { title: 'Proxies', proxies: rows.rows, counts: counts.rows[0], settings, categories: categories.rows.map(row => row.category), query: req.query, mask });
  } catch (err) { next(err); }
});

app.post('/proxies', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    if (req.body.bulk) {
      const lines = parseProxyImport(req.body.bulk, req.body.delimiter || ':', { proxy_type: req.body.proxy_type || 'HTTP', category: req.body.category });
      let imported = 0;
      for (const line of lines.filter(row => row.valid)) {
        const result = await insertProxy(userId, { ...req.body, ...line, proxy_type: req.body.proxy_type || line.proxy_type });
        if (result.rowCount !== 0) imported += 1;
      }
      await activity.log(userId, 'import', 'proxy', null, `Imported ${imported} proxy line(s)`);
      await auditLog(userId, userId, 'import', 'proxy', null, `Imported ${imported} proxy line(s)`);
    } else {
      const result = await insertProxy(userId, req.body);
      await activity.log(userId, 'proxy_created', 'proxy', result.rows[0].id, `Created proxy ${req.body.host}:${req.body.port}`);
    }
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.post('/proxies/import', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    if (req.body.confirm_import !== 'yes') throw new Error('Preview the proxy import before confirming.');
    const lines = parseProxyImport(req.body.proxies_text || req.body.bulk || '', req.body.delimiter || ':', {
      proxy_type: req.body.proxy_type || 'HTTP',
      category: escapeText(req.body.category)
    });
    let imported = 0;
    let invalid = 0;
    for (const line of lines) {
      if (!line.valid) {
        invalid += 1;
        continue;
      }
      const result = await insertProxy(userId, { ...req.body, ...line, proxy_type: req.body.proxy_type || line.proxy_type });
      if (result.rowCount !== 0) imported += 1;
    }
    await recordImportExportRun(userId, 'import_proxies', imported, req.body.proxy_type || 'HTTP', {
      invalid,
      delimiter: req.body.delimiter || ':',
      category: escapeText(req.body.category)
    });
    await activity.log(userId, 'import', 'proxy', null, `Imported ${imported} proxy line(s)`, { invalid, proxy_type: req.body.proxy_type || 'HTTP' });
    await auditLog(userId, userId, 'import', 'proxy', null, `Imported ${imported} proxy line(s)`, { invalid, proxy_type: req.body.proxy_type || 'HTTP' });
    res.redirect(`/proxies?imported=${imported}&invalid=${invalid}`);
  } catch (err) { next(err); }
});

app.post('/proxies/export', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const selected = selectedProxyIds(req.body);
    const delimiter = normalizeDelimiter(req.body.delimiter || ':');
    const includeCredentials = req.body.include_credentials === 'yes';
    const params = [userId];
    let selectedClause = '';
    if (selected.length) {
      params.push(selected);
      selectedClause = `AND id = ANY($${params.length})`;
    }
    const result = await db.query(
      `SELECT *
       FROM proxies
       WHERE user_id=$1 ${selectedClause}
       ORDER BY host, port`,
      params
    );
    const rows = result.rows.map(proxy => {
      const values = [proxy.host, proxy.port];
      if (includeCredentials) {
        values.push(decrypt(proxy.username_encrypted), decrypt(proxy.password_encrypted));
      }
      return values.map(value => String(value || '')).join(delimiter);
    });
    await activity.log(userId, 'export', 'proxy', null, `Exported ${rows.length} proxy line(s)`, { include_credentials: includeCredentials });
    await auditLog(userId, userId, 'export', 'proxy', null, `Exported ${rows.length} proxy line(s)`, { include_credentials: includeCredentials });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="gs-proxies-${new Date().toISOString().slice(0, 10)}.txt"`);
    res.send(`${rows.join('\n')}\n`);
  } catch (err) { next(err); }
});

app.post('/proxies/auto-assign', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const settings = await getSettings(userId);
    const max = Number(settings.max_accounts_per_proxy || 5);
    const proxies = await db.query(
      `SELECT p.id, COUNT(a.id)::int assigned_count
       FROM proxies p LEFT JOIN accounts a ON COALESCE(a.assigned_http_proxy_id, a.proxy_id)=p.id AND a.user_id=p.user_id
       WHERE p.user_id=$1 AND p.proxy_type='HTTP' AND p.status <> 'blocked'
       GROUP BY p.id ORDER BY assigned_count ASC, p.updated_at DESC`, [userId]
    );
    const accounts = await db.query(
      `SELECT id FROM accounts
       WHERE user_id=$1 AND assigned_http_proxy_id IS NULL AND proxy_id IS NULL AND archived_at IS NULL
       ORDER BY updated_at ASC LIMIT 500`, [userId]
    );
    let assigned = 0;
    for (const account of accounts.rows) {
      const proxy = proxies.rows.find(item => item.assigned_count < max);
      if (!proxy) break;
      await db.query('UPDATE accounts SET assigned_http_proxy_id=$1, proxy_id=$1, updated_at=NOW() WHERE id=$2 AND user_id=$3', [proxy.id, account.id, userId]);
      proxy.assigned_count += 1;
      assigned += 1;
    }
    await activity.log(userId, 'proxies_auto_assigned', 'proxy', null, `Assigned proxies to ${assigned} account(s)`, { assigned, max_accounts_per_proxy: max });
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.post('/proxies/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const existing = await db.query('SELECT * FROM proxies WHERE id=$1 AND user_id=$2', [req.params.id, userId]);
    if (!existing.rows[0]) throw new Error('Proxy not found.');
    const host = escapeText(req.body.host);
    const port = Number(req.body.port);
    if (!host || !port) throw new Error('Proxy host and port are required.');
    const fields = [
      'name=$1',
      'proxy_type=$2',
      'host=$3',
      'port=$4',
      'category=$5',
      'country_code=$6',
      'status=$7',
      'max_accounts_per_proxy=$8',
      'notes=$9'
    ];
    const params = [
      escapeText(req.body.name) || null,
      oneOf(req.body.proxy_type, proxyTypes, 'HTTP'),
      host,
      port,
      escapeText(req.body.category) || null,
      escapeText(req.body.country_code).toUpperCase() || null,
      oneOf(req.body.status, proxyStatuses, 'untested'),
      numberOrNull(req.body.max_accounts_per_proxy),
      escapeText(req.body.notes) || null
    ];
    if (escapeText(req.body.username)) {
      params.push(encrypt(req.body.username));
      fields.push(`username_encrypted=$${params.length}`);
    }
    if (escapeText(req.body.password)) {
      params.push(encrypt(req.body.password));
      fields.push(`password_encrypted=$${params.length}`);
    }
    params.push(req.params.id, userId);
    const idParam = params.length - 1;
    const userParam = params.length;
    await db.query(
      `UPDATE proxies SET ${fields.join(', ')}, updated_at=NOW()
       WHERE id=$${idParam} AND user_id=$${userParam}`,
      params
    );
    await activity.log(userId, 'proxy_updated', 'proxy', req.params.id, `Updated proxy ${host}:${port}`);
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.post('/proxies/:id/delete', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `DELETE FROM proxies
       WHERE id=$1 AND user_id=$2
       RETURNING id, host, port`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Proxy not found.');
    await activity.log(userId, 'proxy_deleted', 'proxy', result.rows[0].id, `Deleted proxy ${result.rows[0].host}:${result.rows[0].port}`);
    res.redirect('/proxies');
  } catch (err) { next(err); }
});

app.get('/imports-exports', requireAuth, async (req, res, next) => {
  try {
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.post('/imports/preview', requireAuth, upload.single('accounts_file'), async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const text = inputText(req);
    const preview = parseAccountImport(text, req.body.delimiter || ':', { account_type: req.body.account_type, import_format: req.body.import_format });
    await markDuplicates(userId, preview);
    const stats = previewStats(preview);
    await recordImportExportRun(userId, 'import_preview', stats.valid, null, { duplicate: stats.duplicate, invalid: stats.invalid });
    res.render('imports-exports', { title: 'Imports / Exports', preview, exportRows: null, options: { ...req.body, accounts_text: text }, stats, settings: await getSettings(userId) });
  } catch (err) { next(err); }
});

app.post('/imports/commit', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const rows = parseAccountImport(req.body.accounts_text || '', req.body.delimiter || ':', { account_type: req.body.account_type, import_format: req.body.import_format });
    await markDuplicates(userId, rows);
    let imported = 0;
    for (const row of rows.filter(item => item.valid && (req.body.duplicate_mode === 'update' || !item.duplicate))) {
      const account = accountFromImport(row, req.body);
      if (req.body.duplicate_mode === 'update') await db.query(accountUpsertSql(), accountParams(account, userId));
      else await db.query(accountInsertSql('ON CONFLICT (user_id, username) DO NOTHING'), accountParams(account, userId));
      imported += 1;
    }
    await recordImportExportRun(userId, 'import_commit', imported, null, { duplicate_mode: req.body.duplicate_mode || 'skip' });
    await activity.log(userId, 'accounts_imported', 'account', null, `Imported ${imported} account line(s)`, { duplicate_mode: req.body.duplicate_mode || 'skip' });
    res.redirect('/accounts');
  } catch (err) { next(err); }
});

app.post('/exports/preview', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const format = oneOf(req.body.format, exportFormats, 'legacy_user_pass');
    const rows = await exportRows(userId, req.body);
    if (req.body.confirm_export_action === 'yes') await applyExportAction(userId, req.body);
    await recordImportExportRun(userId, 'export_preview', rows.length, format, { account_type: req.body.account_type, export_action: req.body.export_action || 'keep' });
    await activity.log(userId, 'account_exported', 'account', null, `Prepared ${rows.length} account(s) for export`, { format, export_action: req.body.export_action || 'keep' });
    res.render('imports-exports', { title: 'Imports / Exports', preview: null, exportRows: rows, options: req.body, stats: null, settings: await getSettings(userId) });
  } catch (err) { next(err); }
});

app.get('/local-helper', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [helper, settings] = await Promise.all([
      helperStatus(userId),
      getSettings(userId)
    ]);
    const pairingCode = req.session.helperPairingCode || null;
    req.session.helperPairingCode = null;
    res.render('local-helper', {
      title: 'Companion',
      helper,
      settings,
      pairingCode,
      download: helperDownloadMetadata()
    });
  } catch (err) { next(err); }
});

app.get('/companion', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [helper, settings, devices, statuses, snapshot, jobs] = await Promise.all([
      helperStatus(userId),
      getSettings(userId),
      db.query(
        `SELECT id, device_name, companion_version, status, allow_screenshots, last_seen_at, revoked_at, created_at, updated_at
         FROM companion_devices
         WHERE user_id=$1
         ORDER BY
           CASE WHEN status='connected' THEN 0 WHEN status='disconnected' THEN 1 ELSE 2 END,
           last_seen_at DESC NULLS LAST,
           updated_at DESC
         LIMIT 50`,
        [userId]
      ),
      db.query(
        `SELECT s.*, d.device_name
         FROM companion_client_status s
         LEFT JOIN companion_devices d ON d.id=s.companion_device_id AND d.user_id=s.user_id
         WHERE s.user_id=$1
         ORDER BY s.last_seen_at DESC
         LIMIT 20`,
        [userId]
      ),
      db.query(
        `SELECT id, window_title, image_size, created_at
         FROM live_snapshots
         WHERE user_id=$1
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      ),
      db.query(
        `SELECT j.*, w.name workflow_name
         FROM companion_jobs j
         LEFT JOIN workflows w ON w.id=j.workflow_id AND w.user_id=j.user_id
         WHERE j.user_id=$1
         ORDER BY j.created_at DESC
         LIMIT 20`,
        [userId]
      )
    ]);
    const pairingCode = req.session.helperPairingCode || null;
    req.session.helperPairingCode = null;
    res.render('companion', {
      title: 'Companion',
      helper,
      settings,
      devices: devices.rows,
      clientStatuses: statuses.rows,
      snapshot: snapshot.rows[0] || null,
      jobs: jobs.rows,
      pairingCode,
      download: helperDownloadMetadata()
    });
  } catch (err) { next(err); }
});

app.post('/companion/pairing-code', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await db.query(
      `UPDATE helper_pairing_codes
       SET expires_at=NOW()
       WHERE user_id=$1 AND used_at IS NULL AND expires_at > NOW()`,
      [userId]
    );
    await db.query(
      `INSERT INTO helper_pairing_codes (user_id, code_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, hashPairingCode(code), expiresAt]
    );
    req.session.helperPairingCode = { code, expiresAt: expiresAt.toISOString() };
    await activity.log(userId, 'companion_pair', 'companion', null, 'Generated a short-lived Companion pairing code');
    await auditLog(userId, userId, 'companion_pair', 'companion', null, 'Generated a short-lived Companion pairing code');
    res.redirect('/companion');
  } catch (err) { next(err); }
});

app.post('/companion/devices/:id/revoke', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `UPDATE companion_devices
       SET status='revoked', revoked_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND user_id=$2
       RETURNING id, device_name`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Companion device not found.');
    await activity.log(userId, 'companion_revoke', 'companion_device', result.rows[0].id, `Revoked companion device ${result.rows[0].device_name || result.rows[0].id}`);
    await auditLog(userId, userId, 'companion_revoke', 'companion_device', result.rows[0].id, 'Revoked companion device');
    res.redirect('/companion');
  } catch (err) { next(err); }
});

app.post('/companion/devices/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `UPDATE companion_devices
       SET device_name=$1, allow_screenshots=$2, updated_at=NOW()
       WHERE id=$3 AND user_id=$4 AND status <> 'revoked'
       RETURNING id, device_name, allow_screenshots`,
      [escapeText(req.body.device_name) || 'GS Companion', req.body.allow_screenshots === 'yes', req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Companion device not found.');
    await activity.log(userId, 'companion_device_updated', 'companion_device', result.rows[0].id, 'Updated companion device settings');
    res.redirect('/companion');
  } catch (err) { next(err); }
});

app.post('/local-helper/pairing-code', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await db.query(
      `UPDATE helper_pairing_codes
       SET expires_at=NOW()
       WHERE user_id=$1 AND used_at IS NULL AND expires_at > NOW()`,
      [userId]
    );
    await db.query(
      `INSERT INTO helper_pairing_codes (user_id, code_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, hashPairingCode(code), expiresAt]
    );
    req.session.helperPairingCode = { code, expiresAt: expiresAt.toISOString() };
    await activity.log(userId, 'companion_pair', 'companion', null, 'Generated a short-lived Companion pairing code');
    await auditLog(userId, userId, 'companion_pair', 'companion', null, 'Generated a short-lived Companion pairing code');
    res.redirect('/companion');
  } catch (err) { next(err); }
});

app.get('/downloads/helper/windows', requireAuth, (req, res) => {
  const download = helperDownloadMetadata();
  if (download.available) {
    const windowsPath = path.join(__dirname, '..', 'companion', 'dist', 'GS Account Manager Companion Setup.exe');
    return res.download(windowsPath, 'GS Account Manager Companion Setup.exe');
  }
  return res.status(404).render('helper-download', {
    title: 'GS Account Manager Companion Download',
    download
  });
});

app.get('/downloads', requireAuth, async (req, res, next) => {
  try {
    res.render('downloads', {
      title: 'Downloads',
      download: helperDownloadMetadata(),
      companionName: 'GS Account Manager Companion'
    });
  } catch (err) { next(err); }
});

app.get('/settings', requireAuth, async (req, res, next) => {
  try {
    const settings = await getSettings(req.currentUserId);
    settings.app_version = config.appVersion;
    res.render('settings', { title: 'Settings', settings, config });
  } catch (err) { next(err); }
});

app.post('/settings', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const allowed = [
      'app_name', 'default_account_type', 'default_proxy_type', 'default_email_provider',
      'email_signup_url', 'email_signin_url', 'account_settings_url', 'upgrade_url',
      'password_length', 'max_accounts_per_proxy', 'preferred_export_format', 'export_format_default',
      'default_export_delimiter', 'export_behavior_default', 'mask_sensitive_values', 'otp_refresh_interval',
      'companion_heartbeat_interval_seconds', 'default_browser_type', 'require_confirmation_before_export_delete', 'allow_companion_snapshots',
      'require_helper_for_proxy_actions', 'allow_website_only_browser_open',
      'warn_before_opening_without_helper', 'require_confirmation_before_direct_open',
      'show_proxy_mode_before_open', 'enable_assisted_fill_buttons', 'theme_name', 'workflow_mode'
      , 'dense_table_mode', 'screenshot_interval_seconds',
      'payment_method_ltc_enabled', 'payment_method_btc_enabled', 'payment_method_eth_enabled',
      'manual_admin_activation_enabled'
    ];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        await upsertSetting(userId, key, escapeText(req.body[key]));
      }
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'preferred_export_format')) {
      await upsertSetting(userId, 'export_format_default', escapeText(req.body.preferred_export_format));
    }
    await upsertSetting(userId, 'app_version', config.appVersion);
    await activity.log(userId, 'settings_changed', 'settings', null, 'Updated application settings');
    res.redirect('/settings');
  } catch (err) { next(err); }
});

app.get('/logs', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const admin = isAdminUser(req.currentUserRecord);
    const filters = {
      q: escapeText(req.query.q),
      action: escapeText(req.query.action),
      entity_type: escapeText(req.query.entity_type),
      date: escapeText(req.query.date)
    };
    const clauses = [];
    const params = [];
    if (!admin) {
      params.push(userId);
      clauses.push(`l.user_id = $${params.length}`);
    }
    if (filters.q) {
      params.push(`%${filters.q}%`);
      clauses.push(`(l.action ILIKE $${params.length} OR l.message ILIKE $${params.length})`);
    }
    if (filters.action) {
      params.push(filters.action);
      clauses.push(`l.action = $${params.length}`);
    }
    if (filters.entity_type) {
      params.push(filters.entity_type);
      clauses.push(`l.entity_type = $${params.length}`);
    }
    if (filters.date === 'today') clauses.push(`l.created_at >= CURRENT_DATE`);
    if (filters.date === '7d') clauses.push(`l.created_at >= NOW() - INTERVAL '7 days'`);
    if (filters.date === '30d') clauses.push(`l.created_at >= NOW() - INTERVAL '30 days'`);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const [rows, actions] = await Promise.all([
      db.query(
        `SELECT l.*, COALESCE(u.global_name, u.username, u.discord_username, 'System') log_username
         FROM activity_logs l
         LEFT JOIN users u ON u.id = l.user_id
         ${where}
         ORDER BY l.created_at DESC
         LIMIT 300`,
        params
      ),
      admin
        ? db.query(`SELECT DISTINCT action FROM activity_logs ORDER BY action`)
        : db.query(`SELECT DISTINCT action FROM activity_logs WHERE user_id=$1 ORDER BY action`, [userId])
    ]);
    const entityTypes = [...new Set(rows.rows.map(row => row.entity_type).filter(Boolean))].sort();
    res.render('logs', { title: 'Logs', logs: rows.rows, actions: actions.rows.map(row => row.action), entityTypes, filters, admin });
  } catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).render('error', { title: 'Error', message: err.message });
});

const defaultSettings = {
  app_name: 'GS Account Manager',
  default_account_type: 'legacy',
  default_proxy_type: 'HTTP',
  default_email_provider: 'Outlook',
  email_signup_url: 'https://signup.live.com/',
  email_signin_url: 'https://outlook.live.com/',
  account_settings_url: 'https://account.jagex.com/',
  upgrade_url: 'https://account.jagex.com/',
  password_length: '9',
  max_accounts_per_proxy: '5',
  preferred_export_format: 'legacy_user_pass',
  export_format_default: 'legacy_user_pass',
  default_export_delimiter: ':',
  workflow_mode: 'manual',
  dense_table_mode: 'false',
  screenshot_interval_seconds: '30',
  companion_heartbeat_interval_seconds: '30',
  default_browser_type: 'chromium',
  require_confirmation_before_export_delete: 'true',
  allow_companion_snapshots: 'false',
  payment_method_ltc_enabled: 'false',
  payment_method_btc_enabled: 'false',
  payment_method_eth_enabled: 'false',
  manual_admin_activation_enabled: 'true',
  export_behavior_default: 'keep',
  mask_sensitive_values: 'true',
  otp_refresh_interval: '30',
  require_helper_for_proxy_actions: 'true',
  allow_website_only_browser_open: 'true',
  warn_before_opening_without_helper: 'true',
  require_confirmation_before_direct_open: 'true',
  show_proxy_mode_before_open: 'true',
  enable_assisted_fill_buttons: 'false',
  theme_name: 'Premium Dark',
  app_version: config.appVersion
};

function attachCurrentUser(req, res, next) {
  req.currentUserId = req.session.userId ? Number(req.session.userId) : null;
  req.currentUser = req.session.user || null;
  res.locals.appName = config.appName;
  res.locals.appVersion = config.appVersion;
  res.locals.path = req.path;
  res.locals.user = req.currentUser;
  res.locals.authMode = config.authMode;
  res.locals.discordConfigured = config.discord.configured;
  res.locals.adminFallbackEnabled = config.adminFallbackEnabled;
  res.locals.accountStatuses = accountStatuses;
  res.locals.accountTypes = accountTypes;
  res.locals.credentialStatuses = credentialStatuses;
  res.locals.workflowStatuses = workflowStatuses;
  res.locals.proxyTypes = proxyTypes;
  res.locals.proxyStatuses = proxyStatuses;
  res.locals.userRoles = userRoles;
  res.locals.subscriptionStatuses = subscriptionStatuses;
  res.locals.exportFormats = exportFormats;
  res.locals.workflowModes = workflowModes;
  res.locals.workflowTypes = workflowTypes;
  res.locals.workflowDefinitionStatuses = workflowDefinitionStatuses;
  res.locals.workflowRunStatuses = workflowRunStatuses;
  res.locals.workflowStepTypes = workflowStepTypes;
  res.locals.companionJobStatuses = companionJobStatuses;
  res.locals.paymentMethods = paymentMethods;
  res.locals.isAdmin = req.currentUser && req.currentUser.role === 'admin';
  next();
}

async function requireUserRecord(req, res, next) {
  try {
    let result = await db.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    let user = result.rows[0];
    if (!user) {
      return req.session.destroy(() => res.redirect('/login'));
    }
    if (config.adminDiscordIdSet.has(String(user.discord_id)) && (user.role !== 'admin' || user.subscription_status !== 'active')) {
      result = await db.query(
        `UPDATE users
         SET role='admin', subscription_status='active', disabled_at=NULL, disabled_by_user_id=NULL, updated_at=NOW()
         WHERE id=$1
         RETURNING *`,
        [user.id]
      );
      user = result.rows[0];
      await activity.log(user.id, 'admin_discord_id_verified', 'user', user.id, 'ADMIN_DISCORD_IDS granted admin access');
      await auditLog(user.id, user.id, 'admin_discord_id_verified', 'user', user.id, 'ADMIN_DISCORD_IDS granted admin access');
    }
    req.currentUserId = Number(user.id);
    req.currentUserRecord = user;
    req.currentUser = discordAuth.sessionUser(user);
    req.session.user = req.currentUser;
    req.session.discordId = user.discord_id;
    res.locals.user = req.currentUser;
    res.locals.isAdmin = isAdminUser(user);
    next();
  } catch (error) {
    next(error);
  }
}

function isAdminUser(user) {
  return Boolean(user && user.role === 'admin');
}

function hasAppAccess(user) {
  return isAdminUser(user) || activeSubscriptionStatuses.includes(user && user.subscription_status);
}

function requireActiveSubscription(req, res, next) {
  if (hasAppAccess(req.currentUserRecord)) return next();
  return res.redirect('/locked');
}

function requireAdmin(req, res, next) {
  if (isAdminUser(req.currentUserRecord)) return next();
  return res.status(403).render('error', { title: 'Admin only', message: 'This page is only available to admins.' });
}

function helperDownloadMetadata() {
  const windowsPath = path.join(__dirname, '..', 'companion', 'dist', 'GS Account Manager Companion Setup.exe');
  const available = fs.existsSync(windowsPath);
  return {
    available,
    version: available ? config.appVersion : 'Coming soon',
    releaseDate: available ? 'Packaged locally' : 'Coming soon',
    fileSize: available ? `${Math.ceil(fs.statSync(windowsPath).size / 1024 / 1024)} MB` : '',
    windowsPath: '/downloads/helper/windows'
  };
}

function proxyMode(account, helper, settings) {
  const hasProxy = Boolean(account && account.proxy_host);
  return {
    browserMode: helper && helper.connected ? 'Companion mode' : 'Website-only mode',
    modeDescription: helper && helper.connected
      ? 'Companion mode: opens controlled Chrome through selected proxy when available.'
      : 'Website-only mode: opens in your current browser. No proxy control.',
    helperConnected: helper && helper.connected ? 'yes' : 'no',
    proxyType: hasProxy ? account.proxy_type || 'HTTP' : 'Direct',
    proxyEndpoint: hasProxy ? `${maskEndpoint(account.proxy_host)}:${account.proxy_port}` : 'No proxy assigned',
    directFallback: settings && settings.allow_website_only_browser_open !== 'false' ? 'enabled' : 'disabled'
  };
}

function maskEndpoint(host) {
  const value = String(host || '');
  if (!value) return '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split('.');
    return `***.***.***.${parts[3]}`;
  }
  const visible = value.replace(/[^a-z0-9.-]/gi, '');
  if (visible.length <= 4) return '*'.repeat(visible.length);
  return `${visible.slice(0, 2)}${'*'.repeat(Math.max(3, visible.length - 4))}${visible.slice(-2)}`;
}

function sensitiveCopyField(field) {
  return [
    'password', 'legacy_password', 'otp_code', 'otp_secret', 'bank_pin',
    'recovery_email', 'recovery_email_password', 'target_email',
    'target_email_password', 'email_password', 'jagex_email', 'jagex_password'
  ].includes(field);
}

async function helperStatus(userId) {
  const [devices, activePairing, commands] = await Promise.all([
    db.query(
      `SELECT id, device_name, companion_version AS helper_version, status, last_seen_at, created_at, updated_at
       FROM companion_devices
       WHERE user_id=$1 AND status <> 'revoked'
       ORDER BY
         CASE WHEN status='connected' THEN 0 ELSE 1 END,
         last_seen_at DESC NULLS LAST,
         updated_at DESC
       LIMIT 1`,
      [userId]
    ),
    db.query(
      `SELECT expires_at
       FROM helper_pairing_codes
       WHERE user_id=$1 AND used_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId]
    ),
    db.query(
      `SELECT status, COUNT(*)::int count
       FROM helper_commands
       WHERE user_id=$1
       GROUP BY status`,
      [userId]
    )
  ]);
  const device = devices.rows[0] || null;
  const connected = Boolean(device && device.status === 'connected');
  return {
    connected,
    statusLabel: connected ? 'Connected' : 'Not Connected',
    device,
    helperVersion: device && device.helper_version ? device.helper_version : 'Not available',
    lastHeartbeat: device && device.last_seen_at ? device.last_seen_at : null,
    tokenStatus: activePairing.rows[0] ? 'Pairing code active' : device ? 'Device token stored as hash' : 'No active pairing code',
    activePairingExpiresAt: activePairing.rows[0] ? activePairing.rows[0].expires_at : null,
    commandCounts: Object.fromEntries(commands.rows.map(row => [row.status, row.count]))
  };
}

function generatePairingCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let value = 'GS-';
  for (let index = 0; index < 8; index += 1) {
    value += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return value;
}

function hashPairingCode(code) {
  return crypto
    .createHash('sha256')
    .update(`${config.sessionSecret}:${String(code || '').trim().toUpperCase()}`)
    .digest('hex');
}

function hashDeviceToken(token) {
  return crypto
    .createHash('sha256')
    .update(`${config.sessionSecret}:companion:${String(token || '').trim()}`)
    .digest('hex');
}

async function companionDeviceFromRequest(req) {
  const auth = String(req.get('authorization') || '');
  const token = auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : escapeText(req.body.device_token || req.query.device_token);
  if (!token) return null;
  const result = await db.query(
    `SELECT id, user_id, device_name, companion_version, status, allow_screenshots
     FROM companion_devices
     WHERE device_token_hash=$1 AND status <> 'revoked' AND revoked_at IS NULL`,
    [hashDeviceToken(token)]
  );
  return result.rows[0] || null;
}

async function assertAccountOwnership(userId, accountId) {
  const result = await db.query('SELECT id FROM accounts WHERE id=$1 AND user_id=$2', [accountId, userId]);
  if (!result.rows[0]) throw new Error('Account not found for this user.');
}

async function assertProxyOwnership(userId, proxyId) {
  const result = await db.query('SELECT id FROM proxies WHERE id=$1 AND user_id=$2', [proxyId, userId]);
  if (!result.rows[0]) throw new Error('Proxy not found for this user.');
}

async function assertDeviceOwnership(userId, deviceId) {
  const result = await db.query('SELECT id FROM companion_devices WHERE id=$1 AND user_id=$2 AND status <> $3', [deviceId, userId, 'revoked']);
  if (!result.rows[0]) throw new Error('Companion device not found for this user.');
}

async function loadWorkflow(userId, workflowId) {
  const result = await db.query('SELECT * FROM workflows WHERE id=$1 AND user_id=$2', [workflowId, userId]);
  if (!result.rows[0]) throw new Error('Workflow not found.');
  return result.rows[0];
}

async function loadWorkflowRun(userId, runId) {
  const result = await db.query(
    `SELECT r.*, w.name workflow_name, w.type workflow_type,
            a.username account_username, a.legacy_login account_legacy_login, a.display_name account_display_name,
            p.name proxy_name, p.proxy_type, p.host proxy_host, p.port proxy_port,
            d.device_name companion_device_name, j.id companion_job_id, j.status companion_job_status
     FROM workflow_runs r
     LEFT JOIN workflows w ON w.id=r.workflow_id AND w.user_id=r.user_id
     LEFT JOIN accounts a ON a.id=r.account_id AND a.user_id=r.user_id
     LEFT JOIN proxies p ON p.id=r.proxy_id AND p.user_id=r.user_id
     LEFT JOIN companion_devices d ON d.id=r.companion_device_id AND d.user_id=r.user_id
     LEFT JOIN companion_jobs j ON j.workflow_run_id=r.id AND j.user_id=r.user_id
     WHERE r.id=$1 AND r.user_id=$2`,
    [runId, userId]
  );
  if (!result.rows[0]) throw new Error('Workflow run not found.');
  return result.rows[0];
}

async function ensureStarterWorkflows(userId) {
  const existing = await db.query('SELECT COUNT(*)::int count FROM workflows WHERE user_id=$1', [userId]);
  if (existing.rows[0].count > 0) return;
  for (const type of ['login_fill', 'account_creation_fill', 'generic_form_fill']) {
    const workflow = await db.query(
      `INSERT INTO workflows (user_id, name, description, type, status, updated_at)
       VALUES ($1, $2, $3, $4, 'active', NOW())
       RETURNING id`,
      [userId, workflowTemplateName(type), workflowTemplateDescription(type), type]
    );
    await replaceWorkflowSteps(userId, workflow.rows[0].id, workflowTemplateSteps(type));
  }
}

function workflowTemplateName(type) {
  return {
    login_fill: 'Login form fill',
    account_creation_fill: 'Account creation form fill',
    generic_form_fill: 'Generic multi-field form fill',
    custom: 'Custom workflow'
  }[type] || 'Custom workflow';
}

function workflowTemplateDescription(type) {
  return {
    login_fill: 'Open a login page and fill visible login fields after a user-started run.',
    account_creation_fill: 'Open a signup page and fill selected visible fields, then pause for manual checks.',
    generic_form_fill: 'Fill a generic form from selected account field references.',
    custom: 'User-controlled visible browser workflow.'
  }[type] || 'User-controlled visible browser workflow.';
}

function workflowTemplateSteps(type) {
  const templates = {
    login_fill: [
      { step_type: 'open_url', label: 'Open login page', config: { url: '', visible_browser: true } },
      { step_type: 'fill_field', label: 'Fill login/email', config: { selector: '', matcher: 'email, username, login', value_ref: 'account.login_email' } },
      { step_type: 'fill_field', label: 'Fill password', config: { selector: '', matcher: 'password', value_ref: 'account.login_password', sensitive: true } },
      { step_type: 'pause_for_user', label: 'Manual verification', manual_pause: true, config: { message: 'Complete CAPTCHA, 2FA, email, phone, or security checks manually. Click Continue when ready.' } }
    ],
    account_creation_fill: [
      { step_type: 'open_url', label: 'Open signup page', config: { url: '', visible_browser: true } },
      { step_type: 'fill_field', label: 'Fill email/Jagex email', config: { matcher: 'email', value_ref: 'account.login_email' } },
      { step_type: 'fill_field', label: 'Fill password', config: { matcher: 'password', value_ref: 'account.login_password', sensitive: true } },
      { step_type: 'fill_field', label: 'Fill display name', config: { matcher: 'display name, username', value_ref: 'account.display_name' } },
      { step_type: 'pause_for_user', label: 'Manual verification', manual_pause: true, config: { message: 'Complete any CAPTCHA, email verification, phone verification, or 2FA manually.' } }
    ],
    generic_form_fill: [
      { step_type: 'open_url', label: 'Open target page', config: { url: '', visible_browser: true } },
      { step_type: 'fill_field', label: 'Fill configured field', config: { selector: '', matcher: '', value_ref: 'account.login_email' } },
      { step_type: 'pause_for_user', label: 'Review before submit', manual_pause: true, config: { message: 'Review the visible page. Submit manually if everything looks correct.' } }
    ],
    custom: [
      { step_type: 'note', label: 'Manual-safe workflow note', config: { message: 'Add steps. Keep CAPTCHA, 2FA, email, and phone verification manual.' } }
    ]
  };
  return templates[type] || templates.custom;
}

function parseWorkflowStepsJson(raw) {
  let parsed;
  try { parsed = JSON.parse(raw || '[]'); } catch (error) { throw new Error('Workflow steps JSON is invalid.'); }
  if (!Array.isArray(parsed)) throw new Error('Workflow steps JSON must be an array.');
  return parsed.map((step, index) => ({
    step_order: Number(step.step_order || index + 1),
    step_type: oneOf(step.step_type, workflowStepTypes, 'note'),
    label: escapeText(step.label || step.step_type || `Step ${index + 1}`),
    manual_pause: Boolean(step.manual_pause || step.step_type === 'pause_for_user' || step.step_type === 'wait_for_user_continue'),
    config: safeWorkflowStepConfig(step.config || {})
  }));
}

function safeWorkflowStepConfig(configObject) {
  const clean = safeMetadata(configObject);
  if (clean.value && !clean.value_ref) {
    clean.static_text = String(clean.value).slice(0, 500);
    delete clean.value;
  }
  if (clean.password || clean.otp_secret || clean.token) {
    delete clean.password;
    delete clean.otp_secret;
    delete clean.token;
  }
  return clean;
}

async function replaceWorkflowSteps(userId, workflowId, steps) {
  await db.query('DELETE FROM workflow_steps WHERE user_id=$1 AND workflow_id=$2', [userId, workflowId]);
  const normalized = Array.isArray(steps) ? steps : workflowTemplateSteps('custom');
  for (let index = 0; index < normalized.length; index += 1) {
    const step = parseWorkflowStepsJson(JSON.stringify([normalized[index]]))[0];
    await db.query(
      `INSERT INTO workflow_steps (user_id, workflow_id, step_order, step_type, label, config, manual_pause, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [userId, workflowId, step.step_order || index + 1, step.step_type, step.label, step.config, step.manual_pause]
    );
  }
}

async function workflowJobPayload(userId, workflow, steps, options) {
  let account = null;
  let proxy = null;
  if (options.accountId) {
    const result = await db.query(
      `SELECT id, account_type, username, legacy_login, display_name, status, category,
              COALESCE(assigned_http_proxy_id, proxy_id) account_proxy_id
       FROM accounts WHERE id=$1 AND user_id=$2`,
      [options.accountId, userId]
    );
    account = result.rows[0] || null;
  }
  if (options.proxyId || (account && account.account_proxy_id)) {
    const result = await db.query(
      `SELECT id, name, proxy_type, host, port, status
       FROM proxies WHERE id=$1 AND user_id=$2`,
      [options.proxyId || account.account_proxy_id, userId]
    );
    proxy = result.rows[0] || null;
  }
  return {
    mode: 'visible_user_controlled_browser',
    workflow: { id: workflow.id, name: workflow.name, type: workflow.type },
    account: account ? {
      id: account.id,
      label: account.display_name || account.legacy_login || account.username,
      account_type: account.account_type,
      status: account.status,
      field_values_url: `/api/companion/accounts/${account.id}/field/:field`
    } : null,
    proxy: proxy ? {
      id: proxy.id,
      name: proxy.name,
      proxy_type: proxy.proxy_type,
      endpoint: `${maskEndpoint(proxy.host)}:${proxy.port}`,
      status: proxy.status
    } : null,
    safety: {
      visible_browser_required: true,
      user_click_required: true,
      no_captcha_bypass: true,
      no_2fa_bypass: true,
      no_email_or_phone_bypass: true,
      stop_for_security_checks: true
    },
    steps: steps.map(step => ({
      order: step.step_order,
      type: step.step_type,
      label: step.label,
      manual_pause: step.manual_pause,
      config: safeWorkflowStepConfig(step.config || {})
    }))
  };
}

async function insertWorkflowRunEvent(userId, workflowRunId, eventType, message, metadata = {}) {
  await db.query(
    `INSERT INTO workflow_run_events (user_id, workflow_run_id, event_type, message, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, workflowRunId, escapeText(eventType), escapeText(message), safeMetadata(metadata)]
  );
}

async function insertCompanionJobEvent(userId, companionJobId, workflowRunId, eventType, message, metadata = {}) {
  await db.query(
    `INSERT INTO companion_job_events (user_id, companion_job_id, workflow_run_id, event_type, message, metadata)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId, companionJobId, workflowRunId || null, escapeText(eventType), escapeText(message), safeMetadata(metadata)]
  );
}

async function loadCompanionJobForDevice(device, jobId) {
  const result = await db.query(
    `SELECT *
     FROM companion_jobs
     WHERE id=$1 AND user_id=$2 AND (companion_device_id IS NULL OR companion_device_id=$3)`,
    [jobId, device.user_id, device.id]
  );
  if (!result.rows[0]) throw new Error('Companion job not found.');
  return result.rows[0];
}

function safeCompanionJob(job) {
  return {
    id: job.id,
    job_type: job.job_type,
    status: job.status,
    workflow_id: job.workflow_id,
    workflow_run_id: job.workflow_run_id,
    account_id: job.account_id,
    proxy_id: job.proxy_id,
    payload: job.payload,
    created_at: job.created_at
  };
}

function workflowRunStatusFromJob(status) {
  if (status === 'completed') return 'completed';
  if (status === 'failed') return 'failed';
  if (status === 'cancelled') return 'cancelled';
  if (status === 'paused') return 'paused';
  if (status === 'waiting_for_user') return 'waiting_for_user';
  return 'running';
}

function safeJobResult(result) {
  return safeMetadata(result || {});
}

function safeMetadata(value) {
  if (Array.isArray(value)) return value.map(item => safeMetadata(item));
  if (!value || typeof value !== 'object') return value;
  const clean = {};
  for (const [key, item] of Object.entries(value)) {
    if (/password|secret|token|cookie|session|encrypted|otp/i.test(key)) {
      clean[key] = '[redacted]';
    } else {
      clean[key] = safeMetadata(item);
    }
  }
  return clean;
}

function accountFieldForCompanion(account, decrypted, field) {
  const normalized = String(field || '').replace(/^account\./, '');
  const values = {
    login_email: decrypted.jagex_email || decrypted.target_email || account.legacy_login || account.username,
    username: account.legacy_login || account.username,
    legacy_login: account.legacy_login || account.username,
    login_password: account.account_type === 'jagex'
      ? decrypted.jagex_password || decrypted.password || decrypted.legacy_password
      : decrypted.legacy_password || decrypted.password,
    legacy_password: decrypted.legacy_password || decrypted.password,
    target_email: decrypted.target_email || decrypted.jagex_email,
    jagex_email: decrypted.jagex_email || decrypted.target_email,
    jagex_password: decrypted.jagex_password,
    recovery_email: decrypted.recovery_email,
    recovery_email_password: decrypted.recovery_email_password,
    display_name: account.display_name || '',
    bank_pin: decrypted.bank_pin,
    otp_secret: decrypted.otp_secret,
    notes: account.notes || ''
  };
  if (normalized === 'otp_code') {
    if (!decrypted.otp_secret) return '';
    return currentTotp(decrypted.otp_secret).code;
  }
  if (!Object.prototype.hasOwnProperty.call(values, normalized)) throw new Error('Unsupported account field.');
  return values[normalized] || '';
}

function setUserSession(req, user) {
  req.session.authenticated = true;
  req.session.userId = user.id;
  req.session.discordId = user.discord_id;
  req.session.user = discordAuth.sessionUser(user);
  req.session.csrfToken = null;
}

function inputText(req) {
  const uploaded = req.file ? req.file.buffer.toString('utf8') : '';
  return uploaded || req.body.accounts_text || '';
}

async function passwordLength(userId) {
  const settings = await getSettings(userId);
  return Number(settings.password_length || 9);
}

async function getSettings(userId) {
  const rows = await db.query('SELECT key, value FROM settings WHERE user_id=$1 ORDER BY key', [userId]);
  const settings = { ...defaultSettings, ...Object.fromEntries(rows.rows.map(row => [row.key, row.value])) };
  settings.preferred_export_format = settings.preferred_export_format || settings.export_format_default || defaultSettings.preferred_export_format;
  settings.export_format_default = settings.export_format_default || settings.preferred_export_format;
  settings.workflow_mode = settings.workflow_mode || defaultSettings.workflow_mode;
  return settings;
}

async function upsertSetting(userId, key, value) {
  await db.query(
    `INSERT INTO settings (user_id, key, value, updated_at) VALUES ($1,$2,$3,NOW())
     ON CONFLICT (user_id, key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
    [userId, key, value || '']
  );
}

async function recordImportExportRun(userId, runType, itemCount, format, metadata = {}) {
  await db.query(
    `INSERT INTO import_export_runs (user_id, run_type, item_count, format, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, runType, Number(itemCount || 0), format || null, safeMetadata(metadata)]
  );
  if (runType.startsWith('import')) {
    await db.query(
      `INSERT INTO import_logs (user_id, item_count, format, metadata)
       VALUES ($1, $2, $3, $4)`,
      [userId, Number(itemCount || 0), format || null, safeMetadata(metadata)]
    );
  }
  if (runType.startsWith('export')) {
    await db.query(
      `INSERT INTO export_logs (user_id, item_count, format, archived_after_export, deleted_after_export, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        userId,
        Number(itemCount || 0),
        format || null,
        metadata.export_action === 'archive',
        metadata.export_action === 'delete',
        safeMetadata(metadata)
      ]
    );
  }
}

async function auditLog(actorUserId, userId, action, entityType, entityId, message, metadata = {}) {
  await db.query(
    `INSERT INTO audit_logs (actor_user_id, user_id, action, entity_type, entity_id, message, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [actorUserId || null, userId || null, action, entityType || null, entityId || null, message || null, safeMetadata(metadata)]
  );
}

function accountFromBody(body, existing = {}) {
  const keep = value => value === undefined ? '' : escapeText(value);
  const secret = (key, ...aliases) => {
    const keys = [key, ...aliases];
    for (const item of keys) {
      if (Object.prototype.hasOwnProperty.call(body, item) && escapeText(body[item])) return escapeText(body[item]);
    }
    return existing[key] || '';
  };
  const legacyLogin = keep(body.legacy_login || body.username);
  const jagexEmail = keep(body.jagex_email || body.target_email);
  const targetEmail = keep(body.target_email) || jagexEmail;
  const username = legacyLogin || jagexEmail;
  const legacyPassword = secret('legacy_password', 'password') || existing.password || secret('jagex_password') || '';
  const emailPassword = secret('email_password', 'target_email_password');
  return {
    username,
    legacy_login: legacyLogin || username,
    legacy_password: legacyPassword,
    password: legacyPassword,
    account_type: oneOf(body.account_type, accountTypes, 'unknown'),
    bank_pin: secret('bank_pin'),
    otp_secret: secret('otp_secret'),
    display_name: keep(body.display_name),
    category: keep(body.category),
    country_code: keep(body.country_code).toUpperCase(),
    notes: keep(body.notes),
    recovery_email: secret('recovery_email'),
    recovery_email_password: secret('recovery_email_password'),
    target_email: targetEmail || existing.target_email || '',
    target_email_password: emailPassword,
    email_password: emailPassword,
    jagex_email: jagexEmail || existing.jagex_email || '',
    jagex_password: secret('jagex_password'),
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

function accountParams(account, userId) {
  return [
    userId, account.username, encrypt(account.password), account.legacy_login, encrypt(account.legacy_password), account.account_type,
    encrypt(account.bank_pin), encrypt(account.otp_secret), account.display_name || null, account.category || null, account.country_code || null, account.notes || null,
    encrypt(account.recovery_email), encrypt(account.recovery_email_password), encrypt(account.target_email), encrypt(account.target_email_password), encrypt(account.email_password),
    encrypt(account.jagex_email), encrypt(account.jagex_password), account.jagex_name || null, account.first_name || null, account.last_name || null,
    account.birth_month, account.birth_day, account.birth_year, account.proxy_id, account.assigned_http_proxy_id, account.assigned_socks5_proxy_id,
    account.status, account.credential_status, account.upgrade_status, account.email_creation_status
  ];
}

function accountColumns() {
  return [
    'user_id', 'username', 'password_encrypted', 'legacy_login', 'legacy_password_encrypted', 'account_type',
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
  const statusParam = columns.indexOf('status') + 1;
  const archiveParam = columns.length + 1;
  const idParam = columns.length + 2;
  return `UPDATE accounts SET ${assignments.join(', ')},
    legacy_archived_at=CASE WHEN $${archiveParam} THEN NOW() ELSE legacy_archived_at END,
    archived_at=CASE WHEN $${statusParam}='archived' THEN NOW() ELSE archived_at END,
    exported_at=CASE WHEN $${statusParam}='exported' THEN NOW() ELSE exported_at END,
    updated_at=NOW()
    WHERE id=$${idParam} AND user_id=$1`;
}

function accountUpsertSql() {
  const columns = accountColumns();
  const update = columns.filter(column => !['user_id', 'username'].includes(column)).map(column => `${column}=EXCLUDED.${column}`).join(', ');
  return `INSERT INTO accounts (${columns.join(', ')}) VALUES (${columns.map((_, index) => `$${index + 1}`).join(', ')})
    ON CONFLICT (user_id, username) DO UPDATE SET ${update}, updated_at=NOW() RETURNING id`;
}

async function loadAccount(userId, id) {
  const result = await db.query(
    `SELECT a.*, p.host proxy_host, p.port proxy_port, p.status proxy_status, p.proxy_type proxy_type
     FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id) AND p.user_id = a.user_id
     WHERE a.id=$1 AND a.user_id=$2`, [id, userId]
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

async function insertProxy(userId, body) {
  const host = escapeText(body.host);
  const port = Number(body.port);
  if (!host || !port) throw new Error('Proxy host and port are required.');
  return db.query(
    `INSERT INTO proxies (user_id, name, proxy_type, host, port, username_encrypted, password_encrypted, category, country_code, status, max_accounts_per_proxy, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
    [
      userId, escapeText(body.name) || null, oneOf(body.proxy_type, proxyTypes, 'HTTP'), host, port, encrypt(body.username), encrypt(body.password),
      escapeText(body.category) || null, escapeText(body.country_code).toUpperCase() || null,
      oneOf(body.status, proxyStatuses, 'untested'), numberOrNull(body.max_accounts_per_proxy), escapeText(body.notes) || null
    ]
  );
}

function accountFromImport(row, body) {
  const accountType = oneOf(body.account_type, accountTypes, 'legacy');
  const notes = [escapeText(body.notes), row.notes].filter(Boolean).join(' ');
  return {
    username: row.jagex_email || row.username,
    legacy_login: row.legacy_login || (accountType === 'jagex' ? '' : row.username),
    password: row.jagex_password || row.password,
    legacy_password: row.legacy_password || (accountType === 'jagex' ? '' : row.password),
    account_type: accountType,
    bank_pin: row.bank_pin,
    otp_secret: row.otp_secret,
    display_name: '',
    category: escapeText(body.category),
    country_code: escapeText(body.country_code).toUpperCase(),
    notes,
    recovery_email: row.recovery_email || '',
    recovery_email_password: row.recovery_email_password || '',
    target_email: row.target_email || (accountType === 'jagex' ? row.username : ''),
    target_email_password: row.email_password || (accountType === 'jagex' ? row.password : ''),
    email_password: row.email_password || '',
    jagex_email: accountType === 'jagex' ? (row.jagex_email || row.username) : '',
    jagex_password: accountType === 'jagex' ? (row.jagex_password || row.password) : '',
    jagex_name: '',
    first_name: row.first_name || '',
    last_name: row.last_name || '',
    birth_month: birthParts(row.birth_date).month,
    birth_day: birthParts(row.birth_date).day,
    birth_year: birthParts(row.birth_date).year,
    proxy_id: null,
    assigned_http_proxy_id: null,
    assigned_socks5_proxy_id: null,
    status: oneOf(body.status, accountStatuses, 'pending'),
    credential_status: 'ready',
    upgrade_status: 'pending',
    email_creation_status: 'pending'
  };
}

async function markDuplicates(userId, rows) {
  const names = [...new Set(rows.filter(row => row.username).map(row => row.username))];
  if (!names.length) return;
  const existing = await db.query('SELECT username, legacy_login FROM accounts WHERE user_id=$1 AND (username = ANY($2) OR legacy_login = ANY($2))', [userId, names]);
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

async function exportRows(userId, options) {
  const type = oneOf(options.account_type, accountTypes, 'legacy');
  const format = oneOf(options.format, exportFormats, 'legacy_user_pass');
  const selectedIds = selectedAccountIds(options);
  const params = [userId, type];
  const selectedClause = selectedIds.length ? `AND a.id = ANY($3)` : '';
  if (selectedIds.length) params.push(selectedIds);
  const result = await db.query(
    `SELECT a.*, p.host proxy_host, p.port proxy_port
     FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id) AND p.user_id = a.user_id
     WHERE a.user_id=$1 AND a.account_type=$2 AND a.archived_at IS NULL
       ${selectedClause}
     ORDER BY a.username`,
    params
  );
  return result.rows.map(account => {
    const d = {
      legacy_password: decrypt(account.legacy_password_encrypted) || decrypt(account.password_encrypted),
      otp_secret: decrypt(account.otp_secret_encrypted),
      jagex_email: decrypt(account.jagex_email_encrypted) || decrypt(account.target_email_encrypted),
      jagex_password: decrypt(account.jagex_password_encrypted)
    };
    switch (format) {
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

async function applyExportAction(userId, options) {
  const type = oneOf(options.account_type, accountTypes, 'legacy');
  const action = options.export_action || 'keep';
  const selectedIds = selectedAccountIds(options);
  const params = [userId, type];
  const selectedClause = selectedIds.length ? `AND id = ANY($3)` : '';
  if (selectedIds.length) params.push(selectedIds);
  if (action === 'mark_exported') {
    await db.query(`UPDATE accounts SET status='exported', exported_at=NOW(), updated_at=NOW() WHERE user_id=$1 AND account_type=$2 AND archived_at IS NULL ${selectedClause}`, params);
    await activity.log(userId, 'accounts_marked_exported', 'account', null, `Marked ${type} accounts exported`);
  }
  if (action === 'archive') {
    await db.query(`UPDATE accounts SET status='archived', archived_at=NOW(), updated_at=NOW() WHERE user_id=$1 AND account_type=$2 AND archived_at IS NULL ${selectedClause}`, params);
    await activity.log(userId, 'accounts_archived_after_export', 'account', null, `Archived ${type} accounts after export`);
  }
  if (action === 'delete') {
    await activity.log(userId, 'delete_after_export_requested', 'account', null, 'Delete-after-export was requested but no records were deleted automatically');
  }
}

async function buildSelectedAccountExport(userId, options) {
  const selectedIds = selectedAccountIds(options);
  const result = await db.query(
    `SELECT a.*, p.host proxy_host, p.port proxy_port, p.proxy_type, p.username_encrypted proxy_username_encrypted, p.password_encrypted proxy_password_encrypted
     FROM accounts a
     LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id) AND p.user_id = a.user_id
     WHERE a.user_id=$1 AND a.id = ANY($2)
     ORDER BY array_position($2::bigint[], a.id)`,
    [userId, selectedIds]
  );
  const format = oneOf(options.format, exportFormats, 'username_password');
  const delimiter = normalizeDelimiter(options.delimiter || ':');
  const rows = result.rows.map(account => {
    const decrypted = decryptedExportFields(account);
    let fields = exportFieldList(format, options.custom_fields);
    if (options.include_account_type && !fields.includes('type')) fields = ['type', ...fields];
    if (options.include_proxy && !fields.includes('proxy')) fields.push('proxy');
    if (options.include_notes && !fields.includes('notes')) fields.push('notes');
    if (options.include_otp_secret && !fields.includes('otp')) fields.push('otp');
    return fields.map(field => {
      if (options.include_sensitive === false && sensitiveExportField(field)) return '';
      return exportFieldValue(field, account, decrypted);
    }).join(delimiter);
  });
  return { rows, accountIds: result.rows.map(row => Number(row.id)) };
}

function decryptedExportFields(account) {
  return {
    password: decrypt(account.password_encrypted),
    legacy_password: decrypt(account.legacy_password_encrypted) || decrypt(account.password_encrypted),
    bank_pin: decrypt(account.bank_pin_encrypted),
    otp: decrypt(account.otp_secret_encrypted),
    otp_secret: decrypt(account.otp_secret_encrypted),
    recovery_email: decrypt(account.recovery_email_encrypted),
    recovery_password: decrypt(account.recovery_email_password_encrypted),
    recovery_email_password: decrypt(account.recovery_email_password_encrypted),
    target_email: decrypt(account.target_email_encrypted),
    target_email_password: decrypt(account.target_email_password_encrypted),
    email_password: decrypt(account.email_password_encrypted) || decrypt(account.target_email_password_encrypted),
    email: decrypt(account.jagex_email_encrypted) || decrypt(account.target_email_encrypted) || account.legacy_login || account.username,
    jagex_email: decrypt(account.jagex_email_encrypted),
    jagex_password: decrypt(account.jagex_password_encrypted),
    proxy_username: decrypt(account.proxy_username_encrypted),
    proxy_password: decrypt(account.proxy_password_encrypted)
  };
}

function exportFieldList(format, customFields) {
  const presets = {
    username_password: ['username', 'password'],
    legacy_user_pass: ['username', 'password'],
    username_password_bank_pin: ['username', 'password', 'bank_pin'],
    username_password_otp: ['username', 'password', 'otp'],
    legacy_user_pass_otp: ['username', 'password', 'otp'],
    username_password_bank_pin_otp: ['username', 'password', 'bank_pin', 'otp'],
    legacy_user_pass_pin_otp: ['username', 'password', 'bank_pin', 'otp'],
    legacy_user_pass_pin: ['username', 'password', 'bank_pin'],
    username_password_recovery: ['username', 'password', 'recovery_email', 'recovery_password'],
    email_password: ['email', 'password'],
    jagex_email_pass: ['email', 'password'],
    jagex_email_password: ['email', 'password'],
    email_password_recovery: ['email', 'password', 'recovery_email', 'recovery_password'],
    legacy_to_jagex: ['legacy_login', 'legacy_password', 'jagex_email', 'jagex_password'],
    jagex_email_pass_otp: ['email', 'password', 'otp'],
    login_email_pass_proxy: ['username', 'email', 'password', 'proxy'],
    full: ['id', 'type', 'username', 'password', 'email', 'jagex_password', 'bank_pin', 'otp', 'recovery_email', 'recovery_password', 'proxy', 'category', 'country', 'status', 'notes'],
    full_account_export: ['id', 'type', 'username', 'password', 'email', 'jagex_password', 'bank_pin', 'otp', 'recovery_email', 'recovery_password', 'proxy', 'category', 'country', 'status', 'notes'],
    safe_csv: ['id', 'type', 'username', 'display_name', 'status', 'category', 'country', 'proxy', 'updated_at']
  };
  if (format === 'custom') {
    const fields = String(customFields || '')
      .split(/[\s,]+/)
      .map(field => field.trim().toLowerCase())
      .filter(Boolean);
    return fields.length ? fields : presets.username_password;
  }
  return presets[format] || presets.username_password;
}

function sensitiveExportField(field) {
  return ['password', 'legacy_password', 'jagex_password', 'bank_pin', 'otp', 'otp_secret', 'recovery_password', 'recovery_email_password', 'proxy_password'].includes(String(field || '').toLowerCase());
}

function exportFieldValue(field, account, decrypted) {
  const normalized = String(field || '').toLowerCase();
  const proxy = account.proxy_host ? `${account.proxy_host}:${account.proxy_port}` : '';
  const values = {
    id: account.id,
    type: account.account_type,
    account_type: account.account_type,
    username: account.legacy_login || account.username || '',
    login: account.legacy_login || account.username || '',
    password: account.account_type === 'jagex'
      ? decrypted.jagex_password || decrypted.password || decrypted.legacy_password
      : decrypted.legacy_password || decrypted.password,
    legacy_password: decrypted.legacy_password || decrypted.password,
    email: decrypted.jagex_email || decrypted.target_email || decrypted.email || account.username || '',
    jagex_email: decrypted.jagex_email || decrypted.target_email || '',
    jagex_password: decrypted.jagex_password || '',
    bank_pin: decrypted.bank_pin || '',
    otp: decrypted.otp_secret || '',
    otp_secret: decrypted.otp_secret || '',
    recovery_email: decrypted.recovery_email || '',
    recovery_password: decrypted.recovery_email_password || '',
    recovery_email_password: decrypted.recovery_email_password || '',
    proxy,
    proxy_username: decrypted.proxy_username || '',
    proxy_password: decrypted.proxy_password || '',
    display_name: account.display_name || '',
    category: account.category || '',
    country: account.country_code || '',
    country_code: account.country_code || '',
    status: account.status || '',
    notes: account.notes || '',
    updated_at: account.updated_at ? new Date(account.updated_at).toISOString() : ''
  };
  return values[normalized] == null ? '' : String(values[normalized]);
}

function normalizeDelimiter(value) {
  const raw = String(value || ':');
  if (raw === '\\t' || raw.toLowerCase() === 'tab') return '\t';
  if (raw === 'space') return ' ';
  return raw.slice(0, 4) || ':';
}

async function enforceProxyOwnership(userId, account) {
  const ids = [account.proxy_id, account.assigned_http_proxy_id, account.assigned_socks5_proxy_id].filter(Boolean);
  if (!ids.length) return;
  const result = await db.query('SELECT id FROM proxies WHERE user_id=$1 AND id = ANY($2)', [userId, ids]);
  const owned = new Set(result.rows.map(row => Number(row.id)));
  if (account.proxy_id && !owned.has(Number(account.proxy_id))) throw new Error('Selected proxy does not belong to this user.');
  if (account.assigned_http_proxy_id && !owned.has(Number(account.assigned_http_proxy_id))) throw new Error('Selected HTTP proxy does not belong to this user.');
  if (account.assigned_socks5_proxy_id && !owned.has(Number(account.assigned_socks5_proxy_id))) throw new Error('Selected SOCKS5 proxy does not belong to this user.');
}

function csvLine(values) {
  return values.map(value => `"${String(value ?? '').replace(/"/g, '""')}"`).join(',');
}

function selectedAccountIds(options) {
  const raw = options.account_ids || options.selected_account_ids || [];
  const values = Array.isArray(raw) ? raw : String(raw).split(',');
  return [...new Set(values.map(value => Number(value)).filter(value => Number.isInteger(value) && value > 0))];
}

function selectedProxyIds(options) {
  const raw = options.proxy_ids || options.selected_proxy_ids || [];
  const values = Array.isArray(raw) ? raw : String(raw).split(',');
  return [...new Set(values.map(value => Number(value)).filter(value => Number.isInteger(value) && value > 0))];
}

async function filteredAccountIds(userId, source) {
  const filters = {
    q: escapeText(source.q),
    account_type: escapeText(source.account_type),
    status: escapeText(source.status),
    category: escapeText(source.category),
    country_code: escapeText(source.country_code),
    has_proxy: escapeText(source.has_proxy),
    has_otp: escapeText(source.has_otp),
    archived: escapeText(source.archived),
    created_date: escapeText(source.created_date)
  };
  const clauses = ['user_id = $1'];
  const params = [userId];
  function add(sql, value) { params.push(value); clauses.push(sql.replace('?', `$${params.length}`)); }
  if (filters.q) {
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
    clauses.push(`(username ILIKE $${params.length - 2} OR legacy_login ILIKE $${params.length - 1} OR display_name ILIKE $${params.length})`);
  }
  if (accountTypes.includes(filters.account_type)) add('account_type = ?', filters.account_type);
  if (accountStatuses.includes(filters.status)) add('status = ?', filters.status);
  if (filters.category) add('category ILIKE ?', filters.category);
  if (filters.country_code) add('country_code ILIKE ?', filters.country_code.toUpperCase());
  if (filters.has_proxy === 'yes') clauses.push('(assigned_http_proxy_id IS NOT NULL OR proxy_id IS NOT NULL OR assigned_socks5_proxy_id IS NOT NULL)');
  if (filters.has_proxy === 'no') clauses.push('assigned_http_proxy_id IS NULL AND proxy_id IS NULL AND assigned_socks5_proxy_id IS NULL');
  if (filters.has_otp === 'yes') clauses.push('otp_secret_encrypted IS NOT NULL');
  if (filters.has_otp === 'no') clauses.push('otp_secret_encrypted IS NULL');
  if (filters.archived === 'yes') clauses.push('(archived_at IS NOT NULL OR status = \'archived\')');
  if (filters.archived === 'no') clauses.push('(archived_at IS NULL AND status <> \'archived\')');
  if (filters.created_date === 'today') clauses.push(`created_at >= CURRENT_DATE`);
  if (filters.created_date === '7d') clauses.push(`created_at >= NOW() - INTERVAL '7 days'`);
  if (filters.created_date === '30d') clauses.push(`created_at >= NOW() - INTERVAL '30 days'`);
  if (filters.created_date === 'older_30d') clauses.push(`created_at < NOW() - INTERVAL '30 days'`);
  const result = await db.query(`SELECT id FROM accounts WHERE ${clauses.join(' AND ')} ORDER BY updated_at DESC LIMIT 1000`, params);
  return result.rows.map(row => Number(row.id));
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

function birthParts(value) {
  const raw = escapeText(value);
  if (!raw) return { month: null, day: null, year: null };
  const parts = raw.split(/[\/\-.]/).map(item => Number(item)).filter(Number.isFinite);
  if (parts.length !== 3) return { month: null, day: null, year: null };
  if (parts[0] > 31) return { month: parts[1] || null, day: parts[2] || null, year: parts[0] || null };
  return { month: parts[0] || null, day: parts[1] || null, year: parts[2] || null };
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

async function start() {
  await db.migrate();
  app.listen(config.port, () => console.log(`${config.appName} v${config.appVersion} listening on ${config.port}`));
}

if (require.main === module) {
  start().catch(error => {
    console.error(`Startup error: ${error.message}`);
    process.exit(1);
  });
}

module.exports = {
  app,
  parseAccountImport,
  testInternals: {
    hasAppAccess,
    isAdminUser,
    requireActiveSubscription,
    requireAdmin,
    loadAccount,
    getSettings
  }
};
