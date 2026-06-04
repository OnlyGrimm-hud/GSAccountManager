const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const db = require('./db');
const { encrypt, decrypt, mask } = require('./crypto-fields');
const { currentTotp } = require('./otp');
const { csrf, requireAuth, escapeText, oneOf, verifyAdminPassword } = require('./security');
const activity = require('./activity');
const discordAuth = require('./discord-auth');
const { generatePassword } = require('./generators');
const osrsStats = require('./osrs-stats');
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
  companionJobTypes,
  clientTypes,
  clientInstanceStatuses,
  clientStates,
  wealthSources,
  paymentMethods,
  downloadStatuses,
  downloadCategories
} = require('./app-constants');

const app = express();
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
  message: { error: 'Too many Local App API requests.' }
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
  } catch (err) {
    console.error(`Discord OAuth callback failed: ${err.message}`);
    res.status(400).render('login', {
      title: 'Login',
      error: 'Discord login could not be completed. Please try again.'
    });
  }
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
    const deviceName = escapeText(req.body.device_name || req.body.deviceName || 'GS Local App');
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
    if (!await userIdHasFullAccess(pair.rows[0].user_id)) {
      return res.status(403).json({ error: 'Local App pairing requires active access.' });
    }
    const owner = await db.query('SELECT * FROM users WHERE id=$1', [pair.rows[0].user_id]);
    const ownerAccess = await accessSummaryForUser(owner.rows[0]);
    if (!ownerAccess.gates.addDevice) {
      return res.status(403).json({ error: 'Connected device limit reached for this subscription tier.' });
    }
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashDeviceToken(token);
    const result = await db.query(
      `INSERT INTO companion_devices (user_id, device_name, device_token_hash, companion_version, status, last_seen_at, updated_at)
       VALUES ($1, $2, $3, $4, 'connected', NOW(), NOW())
       RETURNING id, device_name, status, created_at`,
      [pair.rows[0].user_id, deviceName, tokenHash, escapeText(req.body.companion_version || req.body.version)]
    );
    await db.query('UPDATE helper_pairing_codes SET used_at=NOW() WHERE id=$1', [pair.rows[0].id]);
    await activity.log(pair.rows[0].user_id, 'companion_pair', 'companion_device', result.rows[0].id, `Local App device connected: ${deviceName}`);
    await auditLog(null, pair.rows[0].user_id, 'companion_pair', 'companion_device', result.rows[0].id, 'Local App device connected');
    res.json({ device: result.rows[0], token });
  } catch (err) { next(err); }
});

app.post('/api/companion/heartbeat', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    await db.query(
      `UPDATE companion_devices
       SET status='connected', companion_version=COALESCE($1, companion_version), last_seen_at=NOW(), updated_at=NOW()
       WHERE id=$2 AND user_id=$3`,
      [escapeText(req.body.companion_version || req.body.version) || null, device.id, device.user_id]
    );
    res.json({ ok: true, user_id: device.user_id, device_id: device.id });
  } catch (err) { next(err); }
});

app.post('/api/companion/clients/status', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App client status requires active access.' });
    const settings = await getSettings(device.user_id);
    if (settings.enable_local_client_detection !== 'true') {
      return res.status(403).json({ error: 'Local client detection is disabled in Settings.' });
    }
    const instances = normalizeClientStatusPayload(req.body);
    const saved = [];
    for (const item of instances) {
      const prepared = await prepareDetectedClientInstance(device.user_id, item);
      const instance = await upsertClientInstance(device, prepared);
      saved.push(instance);
      await maybeAutoRefreshStats(device.user_id, instance.account_id, settings);
    }
    await activity.log(device.user_id, 'companion_client_status_received', 'client_instance', null, `Local App reported ${saved.length} live session(s)`, { count: saved.length });
    await auditLog(device.user_id, device.user_id, 'companion_client_status_received', 'client_instance', null, `Local App reported ${saved.length} live session(s)`, { count: saved.length });
    res.json({ ok: true, count: saved.length, instances: saved });
  } catch (err) { next(err); }
});

app.post('/api/companion/clients/instance', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App client status requires active access.' });
    const settings = await getSettings(device.user_id);
    if (settings.enable_local_client_detection !== 'true') {
      return res.status(403).json({ error: 'Local client detection is disabled in Settings.' });
    }
    const prepared = await prepareDetectedClientInstance(device.user_id, normalizeClientInstance(req.body));
    const instance = await upsertClientInstance(device, prepared);
    await maybeAutoRefreshStats(device.user_id, instance.account_id, settings);
    await activity.log(device.user_id, 'companion_client_instance_updated', 'client_instance', instance.id, `Live session ${instance.status}`);
    res.json({ ok: true, instance });
  } catch (err) { next(err); }
});

app.post('/api/companion/browser/session', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App browser actions require active access.' });
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
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App fill actions require active access.' });
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    if (accountId) await assertAccountOwnership(device.user_id, accountId);
    await auditLog(device.user_id, device.user_id, 'companion_fill_event', 'account', accountId, 'Local App fill event recorded', {
      field: escapeText(req.body.field),
      mode: 'user_triggered_fill_only'
    });
    res.json({ ok: true, message: 'Fill event recorded. Final submissions must remain user-confirmed.' });
  } catch (err) { next(err); }
});

app.post('/api/companion/status', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App status uploads require active access.' });
    const settings = await getSettings(device.user_id);
    if (settings.enable_local_client_detection !== 'true') {
      return res.status(403).json({ error: 'Local client detection is disabled in Settings.' });
    }
    const windows = normalizeClientStatusPayload(req.body);
    for (const item of windows) {
      await db.query(
        `INSERT INTO companion_client_status (user_id, companion_device_id, process_name, window_title, running, metadata, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [
          device.user_id,
          device.id,
          escapeText(item.process_name || item.processName),
          escapeText(item.window_title || item.windowTitle),
          item.status !== 'stopped',
          { source: 'companion', client_state: item.client_state, matched_account_hint: item.match_hint }
        ]
      );
      const prepared = await prepareDetectedClientInstance(device.user_id, item);
      const instance = await upsertClientInstance(device, prepared);
      await maybeAutoRefreshStats(device.user_id, instance.account_id, settings);
    }
    res.json({ ok: true, count: windows.length });
  } catch (err) { next(err); }
});

app.post('/api/companion/snapshot', companionLimiter, handleCompanionSnapshot);
app.post('/api/companion/snapshots', companionLimiter, handleCompanionSnapshot);

async function handleCompanionSnapshot(req, res, next) {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App snapshots require active access.' });
    if (!device.allow_screenshots) return res.status(403).json({ error: 'Snapshots are disabled for this device.' });
    const settings = await getSettings(device.user_id);
    if (settings.allow_companion_snapshots !== 'true') return res.status(403).json({ error: 'Snapshots are disabled in user settings.' });
    const base64 = String(req.body.image_base64 || '').replace(/^data:image\/[a-z]+;base64,/i, '');
    const image = base64 ? Buffer.from(base64, 'base64') : Buffer.alloc(0);
    if (!image.length || image.length > 750 * 1024) return res.status(400).json({ error: 'Snapshot must be a PNG/JPEG under 750KB.' });
    const clientInstanceId = req.body.client_instance_id ? Number(req.body.client_instance_id) : null;
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    if (clientInstanceId) await assertClientInstanceOwnership(device.user_id, clientInstanceId);
    if (accountId) await assertAccountOwnership(device.user_id, accountId);
    const mimeType = escapeText(req.body.mime_type || req.body.content_type || 'image/png');
    const retention = Number(settings.client_snapshot_retention_hours || 24);
    const retentionHours = Number.isFinite(retention) && retention > 0 ? Math.floor(Math.min(retention, 168)) : 24;
    const result = await db.query(
      `INSERT INTO live_snapshots (
         user_id, companion_device_id, client_instance_id, account_id, window_title,
         content_type, mime_type, image_data, image_size, file_size, width, height, expires_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, $8, $9, $10, CASE WHEN $11::int > 0 THEN NOW() + ($11::int * INTERVAL '1 hour') ELSE NULL END)
       RETURNING id, created_at, image_size, file_size`,
      [
        device.user_id,
        device.id,
        clientInstanceId,
        accountId,
        escapeText(req.body.window_title),
        mimeType,
        image,
        image.length,
        numberOrNull(req.body.width),
        numberOrNull(req.body.height),
        retentionHours
      ]
    );
    await activity.log(device.user_id, 'companion_screenshot_received', 'live_snapshot', result.rows[0].id, 'Local App snapshot received', { image_size: image.length });
    await auditLog(device.user_id, device.user_id, 'companion_screenshot_received', 'live_snapshot', result.rows[0].id, 'Local App snapshot received', { image_size: image.length });
    res.json({ snapshot: result.rows[0] });
  } catch (err) { next(err); }
}

app.get('/api/companion/jobs/next', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App jobs require active access.' });
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
      await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, 'accepted_by_companion', 'Local App accepted automation job.', { companion_job_id: job.id });
    }
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, 'accepted', 'Local App accepted job.');
    res.json({ job: safeCompanionJob(job) });
  } catch (err) { next(err); }
});

app.get('/api/companion/jobs/poll', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App jobs require active access.' });
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
      await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, 'accepted_by_companion', 'Local App accepted automation job.', { companion_job_id: job.id });
    }
    if (job.client_instance_id) {
      await db.query(
        `UPDATE client_instances
         SET companion_device_id=$1, status=CASE WHEN status='unknown' THEN 'running' ELSE status END, updated_at=NOW(), last_seen_at=NOW()
         WHERE id=$2 AND user_id=$3`,
        [device.id, job.client_instance_id, device.user_id]
      );
      await insertClientInstanceEvent(device.user_id, job.client_instance_id, 'accepted_by_companion', 'Local App accepted client job.', { companion_job_id: job.id });
    }
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, 'accepted', 'Local App accepted job.');
    res.json({ job: safeCompanionJob(job) });
  } catch (err) { next(err); }
});

app.post('/api/companion/jobs/:id/status', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App jobs require active access.' });
    const status = oneOf(req.body.status, companionJobStatuses, 'running');
    const message = escapeText(req.body.message);
    const job = await loadCompanionJobForDevice(device, req.params.id);
    const completed = ['completed', 'failed', 'cancelled'].includes(status);
    const runStatus = workflowRunStatusFromJob(status);
    await db.query(
      `UPDATE companion_jobs
       SET status=$1, result=COALESCE($2, result), safe_result_json=COALESCE($2, safe_result_json), updated_at=NOW(), completed_at=CASE WHEN $3 THEN NOW() ELSE completed_at END
       WHERE id=$4 AND user_id=$5`,
      [status, safeJobResult(req.body.result || {}), completed, job.id, device.user_id]
    );
    let clientInstanceId = job.client_instance_id || null;
    if (['launch_client', 'stop_client', 'detect_clients', 'request_snapshot'].includes(job.job_type)) {
      const instancePayload = req.body.client_instance || (req.body.result && (req.body.result.client_instance || req.body.result.instance));
      if (instancePayload && typeof instancePayload === 'object') {
        const instance = await upsertClientInstance(device, {
          ...normalizeClientInstance(instancePayload),
          client_profile_id: job.client_profile_id || instancePayload.client_profile_id,
          account_id: job.account_id || instancePayload.account_id,
          proxy_id: job.proxy_id || instancePayload.proxy_id,
          status: oneOf(instancePayload.status || statusToClientInstanceStatus(status), clientInstanceStatuses, statusToClientInstanceStatus(status))
        });
        clientInstanceId = instance.id;
        await db.query('UPDATE companion_jobs SET client_instance_id=$1 WHERE id=$2 AND user_id=$3', [clientInstanceId, job.id, device.user_id]);
      } else if (clientInstanceId) {
        const nextClientState = clientStateFromJobStatus(status);
        await db.query(
          `UPDATE client_instances
           SET status=$1,
               client_state=$2,
               current_activity=$3,
               stopped_at=CASE WHEN $1='stopped' THEN NOW() ELSE stopped_at END,
               error_message=CASE WHEN $1='crashed' THEN $6 ELSE error_message END,
               last_seen_at=NOW(),
               updated_at=NOW()
           WHERE id=$4 AND user_id=$5`,
          [statusToClientInstanceStatus(status), nextClientState, activityForClientState(nextClientState), clientInstanceId, device.user_id, message || null]
        );
      }
      if (clientInstanceId) await insertClientInstanceEvent(device.user_id, clientInstanceId, status, message || `Local App client job ${status}.`, { companion_job_id: job.id, job_type: job.job_type });
      if (status === 'completed') await activity.log(device.user_id, 'client_job_completed', 'client_instance', clientInstanceId, `Client job completed: ${job.job_type}`);
      if (status === 'failed') await activity.log(device.user_id, 'client_job_failed', 'client_instance', clientInstanceId, `Client job failed: ${job.job_type}`);
    }
    if (job.workflow_run_id) {
      await db.query(
        `UPDATE workflow_runs
         SET status=$1, completed_at=CASE WHEN $2 THEN NOW() ELSE completed_at END, updated_at=NOW()
         WHERE id=$3 AND user_id=$4`,
        [runStatus, completed, job.workflow_run_id, device.user_id]
      );
      await insertWorkflowRunEvent(device.user_id, job.workflow_run_id, status, message || `Local App job ${status}.`, { companion_job_id: job.id });
    }
    await insertCompanionJobEvent(device.user_id, job.id, job.workflow_run_id, status, message || `Job ${status}.`, req.body.metadata || {});
    if (job.status !== status && isBrowserTaskJob(job.job_type)) {
      if (status === 'completed') await recordBrowserTaskUsage(device.user_id, 'successful');
      if (status === 'failed') await recordBrowserTaskUsage(device.user_id, 'failed');
    }
    if (status === 'completed') await activity.log(device.user_id, 'workflow_completed', 'workflow_run', job.workflow_run_id, 'Automation completed by Local App');
    if (status === 'failed') await activity.log(device.user_id, 'workflow_failed', 'workflow_run', job.workflow_run_id, 'Automation failed in Local App');
    res.json({ ok: true, status });
  } catch (err) { next(err); }
});

app.post('/api/companion/jobs/:id/events', companionLimiter, async (req, res, next) => {
  try {
    const device = await companionDeviceFromRequest(req);
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App jobs require active access.' });
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
    if (!device) return res.status(401).json({ error: 'Invalid Local App token.' });
    if (!await userIdHasFullAccess(device.user_id)) return res.status(403).json({ error: 'Local App account fields require active access.' });
    const { account, decrypted } = await loadAccount(device.user_id, req.params.id);
    const field = escapeText(req.params.field);
    const value = accountFieldForCompanion(account, decrypted, field);
    await activity.log(device.user_id, 'companion_field_requested', 'account', account.id, `Local App requested ${field}`, { field });
    await auditLog(device.user_id, device.user_id, 'companion_field_requested', 'account', account.id, `Local App requested ${field}`, { field });
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
  if (hasFullAppAccess(req.currentUserRecord) && !isBlockedUser(req.currentUserRecord)) return res.redirect('/');
  res.status(403).render('locked', { title: 'Access Locked', lockedShell: true });
});

app.use(requireNotBlocked);
app.use(restrictLimitedUsers);

app.post('/api/companion/pair/start', companionLimiter, requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.addDevice) {
      return res.status(403).json({ error: 'Connected device limit reached for this subscription tier.' });
    }
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
    await activity.log(userId, 'companion_pairing_started', 'companion', null, 'Generated Local App pairing code');
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
    if (!result.rows[0]) return res.status(404).json({ error: 'Local App device not found.' });
    await activity.log(req.currentUserId, 'companion_revoke', 'companion_device', result.rows[0].id, `Revoked Local App device ${result.rows[0].device_name || result.rows[0].id}`);
    await auditLog(req.currentUserId, req.currentUserId, 'companion_revoke', 'companion_device', result.rows[0].id, 'Revoked Local App device');
    res.json({ ok: true, device: result.rows[0] });
  } catch (err) { next(err); }
});

app.get('/admin', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const [userCounts, userTotals, accountCounts, proxyCounts, companionCounts, clientCounts, jobCounts, auditRows] = await Promise.all([
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
      db.query(`SELECT status, COUNT(*)::int count FROM client_instances GROUP BY status`),
      db.query(`SELECT status, COUNT(*)::int count FROM companion_jobs GROUP BY status`),
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
      clientCounts: clientCounts.rows,
      jobCounts: jobCounts.rows,
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
              COUNT(DISTINCT p.id)::int proxy_count,
              COUNT(DISTINCT d.id)::int companion_count,
              COUNT(DISTINCT ci.id)::int client_count
       FROM users u
       LEFT JOIN accounts a ON a.user_id = u.id
       LEFT JOIN proxies p ON p.user_id = u.id
       LEFT JOIN companion_devices d ON d.user_id = u.id AND d.status <> 'revoked'
       LEFT JOIN client_instances ci ON ci.user_id = u.id
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

app.get('/admin/logs', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const filters = {
      q: escapeText(req.query.q),
      action: escapeText(req.query.action),
      entity_type: escapeText(req.query.entity_type),
      date: escapeText(req.query.date)
    };
    const clauses = [];
    const params = [];
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
    const [rows, actions, auditRows] = await Promise.all([
      db.query(
        `SELECT l.*, COALESCE(u.global_name, u.username, u.discord_username, 'System') log_username
         FROM activity_logs l
         LEFT JOIN users u ON u.id = l.user_id
         ${where}
         ORDER BY l.created_at DESC
         LIMIT 300`,
        params
      ),
      db.query(`SELECT DISTINCT action FROM activity_logs ORDER BY action`),
      db.query(
        `SELECT a.*, COALESCE(actor.global_name, actor.username, actor.discord_username) actor_name,
                  COALESCE(target.global_name, target.username, target.discord_username) target_name
         FROM audit_logs a
         LEFT JOIN users actor ON actor.id = a.actor_user_id
         LEFT JOIN users target ON target.id = a.user_id
         ORDER BY a.created_at DESC
         LIMIT 100`
      )
    ]);
    const entityTypes = [...new Set(rows.rows.map(row => row.entity_type).filter(Boolean))].sort();
    res.render('admin/logs', {
      title: 'Platform Logs',
      logs: rows.rows,
      auditLogs: auditRows.rows,
      actions: actions.rows.map(row => row.action),
      entityTypes,
      filters
    });
  } catch (err) { next(err); }
});

app.get('/admin/system', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const [users, accounts, proxies, devices, clients, jobs, snapshots] = await Promise.all([
      db.query(`SELECT COUNT(*)::int total FROM users`),
      db.query(`SELECT COUNT(*)::int total FROM accounts`),
      db.query(`SELECT COUNT(*)::int total FROM proxies`),
      db.query(`SELECT status, COUNT(*)::int count FROM companion_devices GROUP BY status`),
      db.query(`SELECT status, COUNT(*)::int count FROM client_instances GROUP BY status`),
      db.query(`SELECT status, COUNT(*)::int count FROM companion_jobs GROUP BY status`),
      db.query(`SELECT COUNT(*)::int total, MAX(created_at) latest FROM live_snapshots`)
    ]);
    res.render('admin/system', {
      title: 'System Health',
      users: users.rows[0],
      accounts: accounts.rows[0],
      proxies: proxies.rows[0],
      devices: devices.rows,
      clients: clients.rows,
      jobs: jobs.rows,
      snapshots: snapshots.rows[0],
      config
    });
  } catch (err) { next(err); }
});

app.get('/admin/subscriptions', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const [counts, tiers, users, usage, paymentSettings] = await Promise.all([
      db.query(`SELECT subscription_status, COUNT(*)::int count FROM users GROUP BY subscription_status ORDER BY subscription_status`),
      db.query(`SELECT * FROM subscription_tiers ORDER BY sort_order, id`),
      db.query(
        `SELECT u.id, u.discord_id, u.username, u.global_name, u.discord_username, u.discord_email,
                u.role, u.subscription_status, u.subscription_tier_id, u.subscription_started_at,
                u.subscription_expires_at, u.manually_paid_at, u.payment_method, u.payment_note,
                u.created_at, u.last_login_at, t.name tier_name, t.slug tier_slug
         FROM users u
         LEFT JOIN subscription_tiers t ON t.id=u.subscription_tier_id
         ORDER BY u.created_at DESC, u.id DESC`
      ),
      db.query(
        `SELECT user_id, successful_count, failed_count
         FROM browser_task_usage
         WHERE date=CURRENT_DATE`
      ),
      db.query(`SELECT * FROM payment_settings ORDER BY method`)
    ]);
    const usageByUser = Object.fromEntries(usage.rows.map(row => [row.user_id, row]));
    res.render('admin/subscriptions', {
      title: 'Subscription Controls',
      counts: counts.rows,
      tiers: tiers.rows,
      users: users.rows,
      usageByUser,
      paymentSettings: paymentSettings.rows,
      paymentMethods
    });
  } catch (err) { next(err); }
});

app.post('/admin/subscriptions/users/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const targetId = Number(req.params.id);
    const tierId = req.body.subscription_tier_id ? Number(req.body.subscription_tier_id) : null;
    const subscriptionStatus = oneOf(req.body.subscription_status, subscriptionStatuses, 'inactive');
    const expiresAt = escapeText(req.body.subscription_expires_at) || null;
    const startedAt = escapeText(req.body.subscription_started_at) || null;
    const paymentMethod = oneOf(req.body.payment_method, paymentMethods, 'manual_admin_activation');
    const manuallyPaidAt = req.body.manually_paid === 'yes' ? new Date() : null;
    const paymentNote = escapeText(req.body.payment_note);
    const disabledAtSql = subscriptionStatus === 'banned' ? 'NOW()' : 'NULL';
    const disabledBySql = subscriptionStatus === 'banned' ? '$9' : 'NULL';
    const params = [
      tierId,
      subscriptionStatus,
      startedAt,
      expiresAt,
      manuallyPaidAt,
      paymentMethod,
      paymentNote,
      targetId
    ];
    if (subscriptionStatus === 'banned') params.push(req.currentUserId);
    const result = await db.query(
      `UPDATE users
       SET subscription_tier_id=$1,
           subscription_status=$2,
           subscription_started_at=COALESCE($3::timestamptz, subscription_started_at),
           subscription_expires_at=$4::timestamptz,
           manually_paid_at=COALESCE($5::timestamptz, manually_paid_at),
           payment_method=$6,
           payment_note=$7,
           disabled_at=${disabledAtSql},
           disabled_by_user_id=${disabledBySql},
           updated_at=NOW()
       WHERE id=$8
       RETURNING id, subscription_status`,
      params
    );
    if (!result.rows[0]) throw new Error('User not found.');
    await auditLog(req.currentUserId, targetId, 'admin_subscription_updated', 'user', targetId, 'Admin updated subscription tier/status', {
      subscription_status: subscriptionStatus,
      subscription_tier_id: tierId,
      payment_method: paymentMethod
    });
    res.redirect('/admin/subscriptions');
  } catch (err) { next(err); }
});

app.post('/admin/subscriptions/tiers/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const tierId = Number(req.params.id);
    await db.query(
      `UPDATE subscription_tiers
       SET name=$1,
           description=$2,
           max_devices=$3,
           daily_successful_browser_task_limit=$4,
           max_accounts=$5,
           max_proxies=$6,
           snapshots_enabled=$7,
           client_launcher_enabled=$8,
           browser_automator_enabled=$9,
           price_label=$10,
           payment_notes=$11,
           active=$12,
           sort_order=$13,
           updated_at=NOW()
       WHERE id=$14`,
      [
        escapeText(req.body.name),
        escapeText(req.body.description),
        optionalInteger(req.body.max_devices),
        optionalInteger(req.body.daily_successful_browser_task_limit),
        optionalInteger(req.body.max_accounts),
        optionalInteger(req.body.max_proxies),
        req.body.snapshots_enabled === 'yes',
        req.body.client_launcher_enabled === 'yes',
        req.body.browser_automator_enabled === 'yes',
        escapeText(req.body.price_label),
        escapeText(req.body.payment_notes),
        req.body.active === 'yes',
        numberOrNull(req.body.sort_order) || 0,
        tierId
      ]
    );
    await auditLog(req.currentUserId, null, 'admin_subscription_tier_updated', 'subscription_tier', tierId, 'Admin updated subscription tier');
    res.redirect('/admin/subscriptions');
  } catch (err) { next(err); }
});

app.post('/admin/subscriptions/payment-settings/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const paymentId = Number(req.params.id);
    const address = escapeText(req.body.address || '');
    await db.query(
      `UPDATE payment_settings
       SET enabled=$1,
           public_label=$2,
           instructions=$3,
           address_encrypted=CASE WHEN $4='' THEN address_encrypted ELSE $5 END,
           updated_at=NOW()
       WHERE id=$6`,
      [
        req.body.enabled === 'yes',
        escapeText(req.body.public_label),
        escapeText(req.body.instructions),
        address,
        encrypt(address),
        paymentId
      ]
    );
    await auditLog(req.currentUserId, null, 'admin_payment_settings_updated', 'payment_settings', paymentId, 'Admin updated payment settings placeholder');
    res.redirect('/admin/subscriptions');
  } catch (err) { next(err); }
});

app.get('/admin/downloads', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const items = await db.query(`SELECT * FROM download_items ORDER BY sort_order, category, title`);
    res.render('admin/downloads', {
      title: 'Downloads Manager',
      items: items.rows,
      downloadStatuses,
      downloadCategories
    });
  } catch (err) { next(err); }
});

app.post('/admin/downloads', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const title = escapeText(req.body.title);
    if (!title) throw new Error('Download title is required.');
    const slug = escapeText(req.body.slug) || slugify(title);
    const category = oneOf(req.body.category, downloadCategories, 'client_tool');
    const status = oneOf(req.body.status, downloadStatuses, 'coming_soon');
    const result = await db.query(
      `INSERT INTO download_items (title, slug, category, description, version, download_url, status, public_notes, admin_notes, sort_order, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT (slug) DO UPDATE SET
         title=EXCLUDED.title,
         category=EXCLUDED.category,
         description=EXCLUDED.description,
         version=EXCLUDED.version,
         download_url=EXCLUDED.download_url,
         status=EXCLUDED.status,
         public_notes=EXCLUDED.public_notes,
         admin_notes=EXCLUDED.admin_notes,
         sort_order=EXCLUDED.sort_order,
         updated_at=NOW()
       RETURNING id`,
      [
        title,
        slug,
        category,
        escapeText(req.body.description),
        escapeText(req.body.version),
        escapeText(req.body.download_url),
        status,
        escapeText(req.body.public_notes),
        escapeText(req.body.admin_notes),
        numberOrNull(req.body.sort_order) || 0
      ]
    );
    await auditLog(req.currentUserId, null, 'admin_download_item_saved', 'download_item', result.rows[0].id, 'Admin saved download item');
    res.redirect('/admin/downloads');
  } catch (err) { next(err); }
});

app.post('/admin/downloads/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const itemId = Number(req.params.id);
    const status = oneOf(req.body.status, downloadStatuses, 'coming_soon');
    const category = oneOf(req.body.category, downloadCategories, 'client_tool');
    const result = await db.query(
      `UPDATE download_items
       SET title=$1,
           slug=$2,
           category=$3,
           description=$4,
           version=$5,
           download_url=$6,
           status=$7,
           public_notes=$8,
           admin_notes=$9,
           sort_order=$10,
           updated_at=NOW()
       WHERE id=$11
       RETURNING id`,
      [
        escapeText(req.body.title),
        escapeText(req.body.slug) || slugify(req.body.title),
        category,
        escapeText(req.body.description),
        escapeText(req.body.version),
        escapeText(req.body.download_url),
        status,
        escapeText(req.body.public_notes),
        escapeText(req.body.admin_notes),
        numberOrNull(req.body.sort_order) || 0,
        itemId
      ]
    );
    if (!result.rows[0]) throw new Error('Download item not found.');
    await auditLog(req.currentUserId, null, 'admin_download_item_updated', 'download_item', itemId, 'Admin updated download item');
    res.redirect('/admin/downloads');
  } catch (err) { next(err); }
});

app.get('/setup', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [counts, helper, settings, access] = await Promise.all([
      db.query(
        `SELECT
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND archived_at IS NULL) accounts,
          (SELECT COUNT(*)::int FROM proxies WHERE user_id=$1) proxies,
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status <> 'revoked') devices,
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_devices,
          (SELECT COUNT(*)::int FROM client_profiles WHERE user_id=$1) launch_profiles,
          (SELECT COUNT(*)::int FROM workflows WHERE user_id=$1) automations,
          (SELECT COUNT(*)::int FROM workflow_runs WHERE user_id=$1) automation_runs,
          (SELECT COUNT(*)::int FROM companion_jobs WHERE user_id=$1) local_jobs,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1) live_sessions,
          (SELECT COUNT(*)::int FROM live_snapshots WHERE user_id=$1) snapshots`,
        [userId]
      ),
      helperStatus(userId),
      getSettings(userId),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    const setupCounts = counts.rows[0] || {};
    res.render('setup', {
      title: 'Setup Wizard',
      counts: setupCounts,
      helper,
      settings,
      access,
      download: helperDownloadMetadata(),
      steps: setupStepsForWorkspace(setupCounts, helper, access),
      matrix: automationCompatibilityMatrix()
    });
  } catch (err) { next(err); }
});

app.get('/setup-guide', requireAuth, (req, res) => {
  res.render('setup-guide', {
    title: 'Setup Guide',
    download: helperDownloadMetadata(),
    docs: setupGuideSections(),
    matrix: automationCompatibilityMatrix()
  });
});

app.get('/compatibility', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [helper, settings, access] = await Promise.all([
      helperStatus(userId),
      getSettings(userId),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    res.render('compatibility', {
      title: 'Compatibility',
      helper,
      settings,
      access,
      matrix: automationCompatibilityMatrix()
    });
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
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND archived_at IS NULL AND status NOT IN ('archived','locked','invalid','banned_temp','banned_perm')) active_accounts,
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND status='locked') locked_accounts,
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND status='invalid') invalid_accounts,
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND status='banned_temp') banned_temp_accounts,
          (SELECT COUNT(*)::int FROM accounts WHERE user_id=$1 AND status='banned_perm') banned_perm_accounts,
          (SELECT COUNT(*)::int FROM proxies WHERE user_id=$1) total_proxies,
          (SELECT COUNT(*)::int FROM workflow_runs WHERE user_id=$1 AND status IN ('queued','running','paused','waiting_for_user')) active_workflows,
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_companions,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status IN ('pending','launching','running','scanning','detected')) running_instances,
          (SELECT COUNT(*)::int FROM companion_jobs WHERE user_id=$1 AND status IN ('queued','accepted','running','paused','waiting_for_user')) pending_jobs`,
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
    await markStaleClientInstancesOffline(userId);
    const filters = {
      q: escapeText(req.query.q),
      account_type: escapeText(req.query.account_type),
      status: escapeText(req.query.status),
      category: escapeText(req.query.category),
      character_type: escapeText(req.query.character_type),
      country_code: escapeText(req.query.country_code),
      has_proxy: escapeText(req.query.has_proxy),
      has_otp: escapeText(req.query.has_otp),
      has_notes: escapeText(req.query.has_notes),
      completed_tutorial: escapeText(req.query.completed_tutorial),
      has_active_instance: escapeText(req.query.has_active_instance),
      verified: escapeText(req.query.verified),
      authenticator: escapeText(req.query.authenticator),
      bans: escapeText(req.query.bans),
      min_total_level: escapeText(req.query.min_total_level),
      max_total_level: escapeText(req.query.max_total_level),
      sort_by: escapeText(req.query.sort_by),
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
    if (filters.character_type) {
      params.push(`%${filters.character_type}%`);
      clauses.push(`(a.character_type ILIKE $${params.length} OR a.category ILIKE $${params.length})`);
    }
    if (filters.country_code) add('a.country_code ILIKE ?', filters.country_code.toUpperCase());
    if (filters.has_proxy === 'yes') clauses.push('(a.assigned_http_proxy_id IS NOT NULL OR a.proxy_id IS NOT NULL)');
    if (filters.has_proxy === 'no') clauses.push('a.assigned_http_proxy_id IS NULL AND a.proxy_id IS NULL');
    if (filters.has_otp === 'yes') clauses.push('a.otp_secret_encrypted IS NOT NULL');
    if (filters.has_otp === 'no') clauses.push('a.otp_secret_encrypted IS NULL');
    if (filters.has_notes === 'yes') clauses.push("(COALESCE(a.notes, '') <> '' OR a.private_notes_encrypted IS NOT NULL)");
    if (filters.has_notes === 'no') clauses.push("COALESCE(a.notes, '') = '' AND a.private_notes_encrypted IS NULL");
    if (filters.completed_tutorial === 'yes') clauses.push('a.completed_tutorial IS TRUE');
    if (filters.completed_tutorial === 'no') clauses.push('a.completed_tutorial IS FALSE');
    if (filters.has_active_instance === 'yes') clauses.push("EXISTS (SELECT 1 FROM client_instances ci2 WHERE ci2.user_id=a.user_id AND ci2.account_id=a.id AND ci2.status IN ('pending','launching','running','scanning','detected'))");
    if (filters.has_active_instance === 'no') clauses.push("NOT EXISTS (SELECT 1 FROM client_instances ci2 WHERE ci2.user_id=a.user_id AND ci2.account_id=a.id AND ci2.status IN ('pending','launching','running','scanning','detected'))");
    if (['yes', 'no', 'unknown'].includes(filters.verified)) add('a.verified = ?', filters.verified);
    if (filters.authenticator === 'yes') clauses.push('a.otp_secret_encrypted IS NOT NULL');
    if (filters.authenticator === 'no') clauses.push('a.otp_secret_encrypted IS NULL');
    if (filters.bans === 'any') clauses.push("(a.status IN ('banned_temp','banned_perm') OR a.ban_status <> 'none')");
    if (filters.bans === 'temp') clauses.push("(a.status='banned_temp' OR a.ban_status='temp')");
    if (filters.bans === 'perm') clauses.push("(a.status='banned_perm' OR a.ban_status='perm')");
    if (filters.bans === 'none') clauses.push("(a.status NOT IN ('banned_temp','banned_perm') AND a.ban_status='none')");
    const minTotalLevel = Number(filters.min_total_level);
    const maxTotalLevel = Number(filters.max_total_level);
    if (Number.isFinite(minTotalLevel) && minTotalLevel >= 0) add('COALESCE(a.total_level, 0) >= ?', minTotalLevel);
    if (Number.isFinite(maxTotalLevel) && maxTotalLevel >= 0) add('COALESCE(a.total_level, 0) <= ?', maxTotalLevel);
    if (filters.archived === 'yes') clauses.push('a.archived_at IS NOT NULL OR a.status = \'archived\'');
    if (filters.archived === 'no') clauses.push('a.archived_at IS NULL AND a.status <> \'archived\'');
    if (filters.created_date === 'today') clauses.push(`a.created_at >= CURRENT_DATE`);
    if (filters.created_date === '7d') clauses.push(`a.created_at >= NOW() - INTERVAL '7 days'`);
    if (filters.created_date === '30d') clauses.push(`a.created_at >= NOW() - INTERVAL '30 days'`);
    if (filters.created_date === 'older_30d') clauses.push(`a.created_at < NOW() - INTERVAL '30 days'`);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const accountSorts = {
      updated_desc: 'a.updated_at DESC',
      created_desc: 'a.created_at DESC',
      username_asc: 'LOWER(COALESCE(a.legacy_login, a.username)) ASC',
      wealth_desc: 'COALESCE(a.wealth_amount, 0) DESC',
      gp_desc: 'COALESCE(a.gp_amount, 0) DESC',
      total_level_desc: 'COALESCE(a.total_level, 0) DESC',
      status_asc: 'a.status ASC, a.updated_at DESC'
    };
    const orderBy = accountSorts[filters.sort_by] || accountSorts.updated_desc;
    const [rows, stats, categories, proxyCategories, countries, proxies, clientProfiles, settings, access] = await Promise.all([
      db.query(
        `SELECT a.*, p.host proxy_host, p.port proxy_port, p.status proxy_status, p.proxy_type,
                ci.id active_instance_id, ci.status active_instance_status, ci.window_title active_instance_window,
                ci.client_state active_instance_client_state, ci.current_activity active_instance_activity, ci.last_seen_at active_instance_last_seen_at,
                ast.total_level stats_total_level, ast.combat_level stats_combat_level, ast.fetched_at stats_fetched_at,
                ast.status stats_status, ast.error_message stats_error_message
         FROM accounts a LEFT JOIN proxies p ON p.id = COALESCE(a.assigned_http_proxy_id, a.proxy_id) AND p.user_id = a.user_id
         LEFT JOIN account_stats ast ON ast.account_id=a.id AND ast.user_id=a.user_id
         LEFT JOIN LATERAL (
           SELECT id, status, window_title, client_state, current_activity, last_seen_at
           FROM client_instances
           WHERE user_id=a.user_id AND account_id=a.id AND status IN ('pending','launching','running','scanning','detected','stopped','crashed','unknown')
           ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC
           LIMIT 1
         ) ci ON TRUE
         ${where} ORDER BY ${orderBy} LIMIT 300`, params
      ),
      db.query(
        `SELECT
          COUNT(*)::int total,
          COUNT(*) FILTER (WHERE account_type='legacy')::int legacy,
          COUNT(*) FILTER (WHERE account_type='jagex')::int jagex,
          COUNT(*) FILTER (WHERE COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) IS NOT NULL)::int with_proxy,
          COUNT(*) FILTER (WHERE COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) IS NULL)::int without_proxy,
          COUNT(*) FILTER (WHERE archived_at IS NULL AND status NOT IN ('archived','locked','invalid','banned_temp','banned_perm'))::int active,
          COUNT(*) FILTER (WHERE status IN ('banned_temp','banned_perm'))::int banned,
          COUNT(*) FILTER (WHERE status='locked')::int locked,
          COUNT(*) FILTER (WHERE status='invalid')::int invalid,
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
      db.query(`SELECT id, name FROM client_profiles WHERE user_id=$1 AND enabled IS TRUE ORDER BY updated_at DESC LIMIT 50`, [userId]),
      getSettings(userId),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    res.render('accounts/index', {
      title: 'Accounts',
      accounts: rows.rows,
      stats: stats.rows[0],
      categories: categories.rows.map(row => row.category),
      proxyCategories: proxyCategories.rows.map(row => row.category),
      countries: countries.rows.map(row => row.country_code),
      proxies: proxies.rows,
      clientProfiles: clientProfiles.rows,
      filters,
      settings,
      access,
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
    if (hasLimitedAccess(req.currentUserRecord) && postExportAction !== 'keep') {
      throw new Error('Private-build access is not active for this account.');
    }
    const deleteAfterExport = req.body.delete_after_export === 'yes' || postExportAction === 'delete';
    const confirmDelete = req.body.confirm_delete_after_export === 'yes';
    const confirmDeleteText = escapeText(req.body.confirm_delete_after_export_text || req.body.delete_confirm_text);
    if (deleteAfterExport && (!confirmDelete || confirmDeleteText !== 'DELETE')) {
      throw new Error('Permanent delete after export requires the checkbox and typing DELETE.');
    }
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
    } else if (action === 'launch_selected') {
      const access = await accessSummaryForUser(req.currentUserRecord);
      if (!isAdminUser(req.currentUserRecord) && !(access.tier && access.tier.client_launcher_enabled)) {
        throw new Error('Client launcher is not available for your subscription tier.');
      }
      const profileId = req.body.bulk_client_profile_id ? Number(req.body.bulk_client_profile_id) : null;
      if (!profileId) throw new Error('Select a launch profile before launching accounts.');
      const profile = await loadClientProfile(userId, profileId);
      const accounts = await db.query(
        `SELECT id, COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) proxy_id
         FROM accounts
         WHERE user_id=$1 AND id = ANY($2) AND archived_at IS NULL`,
        [userId, selectedIds]
      );
      for (const account of accounts.rows) {
        const payload = await clientLaunchPayload(userId, profile, { accountId: Number(account.id), proxyId: account.proxy_id ? Number(account.proxy_id) : null });
        await db.query(
          `INSERT INTO companion_jobs (user_id, client_profile_id, account_id, proxy_id, job_type, status, payload, safe_payload_json, updated_at)
           VALUES ($1, $2, $3, $4, 'launch_client', 'queued', $5, $5, NOW())`,
          [userId, profile.id, account.id, account.proxy_id || null, payload]
        );
        affected += 1;
      }
      await activity.log(userId, 'bulk_client_launch_requested', 'account', null, `Queued ${affected} client launch job(s)`, { count: affected, client_profile_id: profile.id });
    } else {
      throw new Error('Unsupported bulk action.');
    }
    await auditLog(userId, userId, action, 'account', null, `Bulk account action ${action} affected ${affected} account(s)`, { count: affected });
    if (action === 'launch_selected') return res.redirect(`/local-jobs?queued=${affected}`);
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

app.post('/accounts/:id/refresh-stats', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await refreshAccountStats(userId, req.params.id, {
      displayName: req.body.display_name
    });
    res.redirect(`/accounts?stats_sync=${encodeURIComponent(result.status)}&account_id=${encodeURIComponent(req.params.id)}`);
  } catch (err) {
    if (/Account not found|display name/i.test(err.message)) {
      res.redirect(`/accounts?stats_sync=failed&stats_error=${encodeURIComponent(err.message)}`);
      return;
    }
    next(err);
  }
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
    const [workflows, runs, accounts, proxies, devices, counts, access, helper] = await Promise.all([
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
      db.query(`SELECT status, COUNT(*)::int count FROM workflow_runs WHERE user_id=$1 GROUP BY status`, [userId]),
      accessSummaryForUser(req.currentUserRecord),
      helperStatus(userId)
    ]);
    res.render('workflows/index', {
      title: 'Browser Automator',
      workflows: workflows.rows,
      runs: runs.rows,
      accounts: accounts.rows,
      proxies: proxies.rows,
      devices: devices.rows,
      counts: counts.rows,
      access,
      helper,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.post('/workflows', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.browserAutomator) throw new Error('Browser Automator is not available for your subscription tier.');
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
    await activity.log(userId, 'workflow_created', 'workflow', result.rows[0].id, `Created automation ${name}`, { type: template });
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
    res.render('workflows/run', { title: 'Job Status', run, events: events.rows, jobEvents: jobEvents.rows, snapshot: snapshot.rows[0] || null });
  } catch (err) { next(err); }
});

app.post('/workflows/runs/:id/continue', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const run = await loadWorkflowRun(userId, req.params.id);
    await db.query(`UPDATE workflow_runs SET status='running', updated_at=NOW() WHERE id=$1 AND user_id=$2`, [run.id, userId]);
    await insertWorkflowRunEvent(userId, run.id, 'user_continue', 'User confirmed manual step and continued.');
    await activity.log(userId, 'workflow_user_continue', 'workflow_run', run.id, 'User continued automation after manual step');
    res.redirect(`/workflows/runs/${run.id}`);
  } catch (err) { next(err); }
});

app.post('/workflows/runs/:id/cancel', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const run = await loadWorkflowRun(userId, req.params.id);
    await db.query(`UPDATE workflow_runs SET status='cancelled', completed_at=NOW(), updated_at=NOW() WHERE id=$1 AND user_id=$2`, [run.id, userId]);
    await db.query(`UPDATE companion_jobs SET status='cancelled', updated_at=NOW(), completed_at=NOW() WHERE user_id=$1 AND workflow_run_id=$2 AND status NOT IN ('completed','failed','cancelled')`, [userId, run.id]);
    await insertWorkflowRunEvent(userId, run.id, 'cancelled', 'Automation cancelled by user.');
    await activity.log(userId, 'workflow_cancelled', 'workflow_run', run.id, 'Automation cancelled by user');
    res.redirect(`/workflows/runs/${run.id}`);
  } catch (err) { next(err); }
});

app.get('/workflows/:id/edit', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const workflow = await loadWorkflow(userId, req.params.id);
    const steps = await db.query(`SELECT * FROM workflow_steps WHERE user_id=$1 AND workflow_id=$2 ORDER BY step_order`, [userId, workflow.id]);
    res.render('workflows/form', {
      title: 'Edit Automation',
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
    if (!name) throw new Error('Automation name is required.');
    const status = oneOf(req.body.status, workflowDefinitionStatuses, 'active');
    const type = oneOf(req.body.type, workflowTypes, workflow.type || 'custom');
    await db.query(
      `UPDATE workflows SET name=$1, description=$2, type=$3, status=$4, updated_at=NOW() WHERE id=$5 AND user_id=$6`,
      [name, escapeText(req.body.description), type, status, workflow.id, userId]
    );
    const steps = parseWorkflowStepsJson(req.body.steps_json || '[]');
    await replaceWorkflowSteps(userId, workflow.id, steps);
    await activity.log(userId, 'workflow_updated', 'workflow', workflow.id, `Updated automation ${name}`, { type, status });
    res.redirect(`/workflows/${workflow.id}/edit`);
  } catch (err) { next(err); }
});

app.post('/workflows/:id/run', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.browserAutomator) throw new Error('Browser Automator is not available for your subscription tier.');
    if (!access.gates.runBrowserTask) throw new Error('Daily browser task limit reached for your tier.');
    const workflow = await loadWorkflow(userId, req.params.id);
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    const proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : null;
    const deviceId = req.body.companion_device_id ? Number(req.body.companion_device_id) : null;
    if (accountId) await assertAccountOwnership(userId, accountId);
    if (proxyId) await assertProxyOwnership(userId, proxyId);
    if (deviceId) await assertDeviceOwnership(userId, deviceId);
    const steps = await db.query(`SELECT * FROM workflow_steps WHERE user_id=$1 AND workflow_id=$2 ORDER BY step_order`, [userId, workflow.id]);
    if (!steps.rows.length) throw new Error('Automation has no steps.');
    const run = await db.query(
      `INSERT INTO workflow_runs (user_id, workflow_id, account_id, proxy_id, companion_device_id, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'queued', NOW(), NOW())
       RETURNING id`,
      [userId, workflow.id, accountId, proxyId, deviceId]
    );
    const payload = await workflowJobPayload(userId, workflow, steps.rows, { accountId, proxyId, deviceId });
    const job = await db.query(
      `INSERT INTO companion_jobs (user_id, companion_device_id, workflow_id, workflow_run_id, account_id, proxy_id, job_type, status, payload, safe_payload_json, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'workflow_run', 'queued', $7, $7, NOW())
       RETURNING id`,
      [userId, deviceId, workflow.id, run.rows[0].id, accountId, proxyId, payload]
    );
    await insertWorkflowRunEvent(userId, run.rows[0].id, 'queued', 'Automation queued for Local App.', { companion_job_id: job.rows[0].id });
    await activity.log(userId, 'workflow_started', 'workflow_run', run.rows[0].id, `Queued automation ${workflow.name}`, { workflow_id: workflow.id });
    await auditLog(userId, userId, 'workflow_started', 'workflow_run', run.rows[0].id, `Queued automation ${workflow.name}`, { workflow_id: workflow.id });
    res.redirect(`/workflows/runs/${run.rows[0].id}`);
  } catch (err) { next(err); }
});

app.get('/workflow', requireAuth, (req, res) => {
  const accountId = req.query.account_id ? encodeURIComponent(req.query.account_id) : '';
  res.redirect(accountId ? `/workflows?account_id=${accountId}` : '/workflows');
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
    await activity.log(userId, 'workflow_status_changed', 'account', req.params.id, `Manual progress status changed to ${status}`, { status });
    res.redirect(`/workflows?account_id=${encodeURIComponent(req.params.id)}`);
  } catch (err) { next(err); }
});

app.get('/instances', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    await markStaleClientInstancesOffline(userId);
    const [helper, settings, devices, instances, snapshot, jobs, events, accounts, proxies, workflows, stats, access] = await Promise.all([
      helperStatus(userId),
      getSettings(userId),
      db.query(`SELECT id, device_name, companion_version, status, allow_screenshots, last_seen_at FROM companion_devices WHERE user_id=$1 AND status <> 'revoked' ORDER BY last_seen_at DESC NULLS LAST`, [userId]),
      db.query(
        `SELECT ci.*, cp.name profile_name, a.username account_username, a.legacy_login account_legacy_login, a.display_name account_display_name,
                a.gp_amount, a.bank_value, a.wealth_value, a.wealth_amount, a.wealth_source account_wealth_source,
                sa.username suggested_account_username, sa.legacy_login suggested_account_legacy_login, sa.display_name suggested_account_display_name,
                ast.total_level stats_total_level, ast.combat_level stats_combat_level, ast.fetched_at stats_fetched_at,
                ast.status stats_status, ast.error_message stats_error_message,
                p.name proxy_name, p.host proxy_host, p.port proxy_port, p.proxy_type, p.status proxy_status, d.device_name
         FROM client_instances ci
         LEFT JOIN client_profiles cp ON cp.id=ci.client_profile_id AND cp.user_id=ci.user_id
         LEFT JOIN accounts a ON a.id=ci.account_id AND a.user_id=ci.user_id
         LEFT JOIN accounts sa ON sa.id=ci.suggested_account_id AND sa.user_id=ci.user_id
         LEFT JOIN account_stats ast ON ast.account_id=ci.account_id AND ast.user_id=ci.user_id
         LEFT JOIN proxies p ON p.id=ci.proxy_id AND p.user_id=ci.user_id
         LEFT JOIN companion_devices d ON d.id=ci.companion_device_id AND d.user_id=ci.user_id
         WHERE ci.user_id=$1
         ORDER BY
           CASE WHEN ci.status IN ('pending','launching','running','scanning','detected') THEN 0 ELSE 1 END,
           ci.last_seen_at DESC NULLS LAST,
           ci.updated_at DESC
         LIMIT 250`,
        [userId]
      ),
      db.query(
        `SELECT s.id, s.window_title, s.mime_type, s.content_type, COALESCE(s.file_size, s.image_size) file_size, s.created_at,
                ci.instance_name, ci.process_name
         FROM live_snapshots s
         LEFT JOIN client_instances ci ON ci.id=s.client_instance_id AND ci.user_id=s.user_id
         WHERE s.user_id=$1
         ORDER BY s.created_at DESC
         LIMIT 1`,
        [userId]
      ),
      db.query(
        `SELECT j.*, cp.name profile_name, ci.instance_name
         FROM companion_jobs j
         LEFT JOIN client_profiles cp ON cp.id=j.client_profile_id AND cp.user_id=j.user_id
         LEFT JOIN client_instances ci ON ci.id=j.client_instance_id AND ci.user_id=j.user_id
         WHERE j.user_id=$1 AND j.job_type IN ('launch_client','stop_client','detect_clients','request_snapshot')
         ORDER BY j.created_at DESC
         LIMIT 20`,
        [userId]
      ),
      db.query(
        `SELECT e.*, ci.instance_name
         FROM client_instance_events e
         LEFT JOIN client_instances ci ON ci.id=e.client_instance_id AND ci.user_id=e.user_id
         WHERE e.user_id=$1
         ORDER BY e.created_at DESC
         LIMIT 30`,
        [userId]
      ),
      db.query(`SELECT id, username, legacy_login, display_name FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, type, status FROM workflows WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(
        `SELECT
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1) total_instances,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status IN ('pending','launching','running','scanning','detected')) running_instances,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status='stopped') stopped_instances,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status='crashed') crashed_instances,
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_devices,
          (SELECT COUNT(*)::int FROM companion_jobs WHERE user_id=$1 AND job_type IN ('launch_client','stop_client','detect_clients','request_snapshot') AND status IN ('queued','accepted','running','paused','waiting_for_user')) active_jobs`,
        [userId]
      ),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    res.render('instances', {
      title: 'Live Sessions',
      helper,
      settings,
      devices: devices.rows,
      instances: instances.rows,
      snapshot: snapshot.rows[0] || null,
      jobs: jobs.rows,
      events: events.rows,
      accounts: accounts.rows,
      proxies: proxies.rows,
      workflows: workflows.rows,
      stats: stats.rows[0],
      access,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.get('/instances/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [instance, events, jobs, stats, accounts, proxies, access] = await Promise.all([
      db.query(
        `SELECT ci.*, cp.name profile_name, a.username account_username, a.legacy_login account_legacy_login, a.display_name account_display_name,
                a.gp_amount, a.bank_value, a.wealth_value, a.wealth_amount, a.wealth_source account_wealth_source,
                sa.username suggested_account_username, sa.legacy_login suggested_account_legacy_login, sa.display_name suggested_account_display_name,
                ast.total_level stats_total_level, ast.combat_level stats_combat_level, ast.fetched_at stats_fetched_at,
                ast.status stats_status, ast.error_message stats_error_message,
                p.name proxy_name, p.host proxy_host, p.port proxy_port, p.proxy_type, p.status proxy_status, d.device_name
         FROM client_instances ci
         LEFT JOIN client_profiles cp ON cp.id=ci.client_profile_id AND cp.user_id=ci.user_id
         LEFT JOIN accounts a ON a.id=ci.account_id AND a.user_id=ci.user_id
         LEFT JOIN accounts sa ON sa.id=ci.suggested_account_id AND sa.user_id=ci.user_id
         LEFT JOIN account_stats ast ON ast.account_id=ci.account_id AND ast.user_id=ci.user_id
         LEFT JOIN proxies p ON p.id=ci.proxy_id AND p.user_id=ci.user_id
         LEFT JOIN companion_devices d ON d.id=ci.companion_device_id AND d.user_id=ci.user_id
         WHERE ci.id=$1 AND ci.user_id=$2`,
        [req.params.id, userId]
      ),
      db.query(
        `SELECT * FROM client_instance_events
         WHERE client_instance_id=$1 AND user_id=$2
         ORDER BY created_at DESC
         LIMIT 100`,
        [req.params.id, userId]
      ),
      db.query(
        `SELECT * FROM companion_jobs
         WHERE client_instance_id=$1 AND user_id=$2
         ORDER BY updated_at DESC
         LIMIT 50`,
        [req.params.id, userId]
      ),
      db.query(
        `SELECT * FROM account_stats
         WHERE account_id=(SELECT account_id FROM client_instances WHERE id=$1 AND user_id=$2) AND user_id=$2
         LIMIT 1`,
        [req.params.id, userId]
      ),
      db.query(`SELECT id, username, legacy_login, display_name FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    if (!instance.rows[0]) throw new Error('Client instance not found.');
    res.render('instance', {
      title: 'Live Session',
      instance: instance.rows[0],
      events: events.rows,
      jobs: jobs.rows,
      accountStats: stats.rows[0] || null,
      accounts: accounts.rows,
      proxies: proxies.rows,
      access,
      mask
    });
  } catch (err) { next(err); }
});

app.post('/instances/:id/match', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const instance = await loadClientInstance(userId, req.params.id);
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    const proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : null;
    if (accountId) await assertAccountOwnership(userId, accountId);
    if (proxyId) await assertProxyOwnership(userId, proxyId);
    await db.query(
      `UPDATE client_instances
       SET account_id=$1, proxy_id=$2, suggested_account_id=NULL, match_confidence=$3, match_reason=$4, updated_at=NOW()
       WHERE id=$5 AND user_id=$6`,
      [accountId, proxyId, accountId ? 'manual' : null, accountId ? 'User confirmed account match.' : null, instance.id, userId]
    );
    if (accountId) await applyClientInstanceAccountStatus(userId, accountId, {}, instance);
    await insertClientInstanceEvent(userId, instance.id, 'account_matched_to_client', accountId ? 'User matched an account to this live session.' : 'User cleared account match.', { account_id: accountId, proxy_id: proxyId });
    await activity.log(userId, 'account_matched_to_client', 'client_instance', instance.id, 'Matched account to live session', { account_id: accountId });
    res.redirect(`/instances/${instance.id}`);
  } catch (err) { next(err); }
});

app.post('/instances/:id/unmatch', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const instance = await loadClientInstance(userId, req.params.id);
    await db.query(
      `UPDATE client_instances
       SET account_id=NULL, suggested_account_id=NULL, match_confidence=NULL, match_reason=NULL, updated_at=NOW()
       WHERE id=$1 AND user_id=$2`,
      [instance.id, userId]
    );
    await insertClientInstanceEvent(userId, instance.id, 'account_unmatched_from_client', 'User removed account match from this live session.');
    await activity.log(userId, 'account_unmatched_from_client', 'client_instance', instance.id, 'Removed account match from live session');
    res.redirect(`/instances/${instance.id}`);
  } catch (err) { next(err); }
});

app.post('/instances/:id/refresh-stats', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const instance = await loadClientInstance(userId, req.params.id);
    if (!instance.account_id) throw new Error('Match an account before refreshing stats.');
    const result = await refreshAccountStats(userId, instance.account_id);
    await insertClientInstanceEvent(userId, instance.id, 'stats_refreshed', `Stats refresh ${result.status}.`, { account_id: instance.account_id, status: result.status });
    res.redirect(`/instances/${instance.id}?stats_sync=${encodeURIComponent(result.status)}`);
  } catch (err) { next(err); }
});

app.get('/clients', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    await markStaleClientInstancesOffline(userId);
    const [helper, settings, devices, profiles, instances, snapshot, jobs, accounts, proxies, workflows, stats, access] = await Promise.all([
      helperStatus(userId),
      getSettings(userId),
      db.query(`SELECT id, device_name, companion_version, status, allow_screenshots, last_seen_at FROM companion_devices WHERE user_id=$1 AND status <> 'revoked' ORDER BY last_seen_at DESC NULLS LAST`, [userId]),
      db.query(
        `SELECT cp.*, p.name default_proxy_name, p.host default_proxy_host, p.port default_proxy_port, w.name default_workflow_name,
                a.username default_account_username, a.legacy_login default_account_legacy_login, a.display_name default_account_display_name
         FROM client_profiles cp
         LEFT JOIN accounts a ON a.id=cp.default_account_id AND a.user_id=cp.user_id
         LEFT JOIN proxies p ON p.id=cp.default_proxy_id AND p.user_id=cp.user_id
         LEFT JOIN workflows w ON w.id=cp.default_workflow_id AND w.user_id=cp.user_id
         WHERE cp.user_id=$1
         ORDER BY cp.enabled DESC, cp.updated_at DESC`,
        [userId]
      ),
      db.query(
        `SELECT ci.*, cp.name profile_name, a.username account_username, a.legacy_login account_legacy_login, a.display_name account_display_name,
                p.name proxy_name, p.host proxy_host, p.port proxy_port, p.proxy_type, d.device_name
         FROM client_instances ci
         LEFT JOIN client_profiles cp ON cp.id=ci.client_profile_id AND cp.user_id=ci.user_id
         LEFT JOIN accounts a ON a.id=ci.account_id AND a.user_id=ci.user_id
         LEFT JOIN proxies p ON p.id=ci.proxy_id AND p.user_id=ci.user_id
         LEFT JOIN companion_devices d ON d.id=ci.companion_device_id AND d.user_id=ci.user_id
         WHERE ci.user_id=$1
         ORDER BY ci.last_seen_at DESC NULLS LAST, ci.updated_at DESC
         LIMIT 200`,
        [userId]
      ),
      db.query(
        `SELECT s.id, s.window_title, s.mime_type, s.content_type, COALESCE(s.file_size, s.image_size) file_size, s.created_at,
                ci.instance_name, ci.process_name
         FROM live_snapshots s
         LEFT JOIN client_instances ci ON ci.id=s.client_instance_id AND ci.user_id=s.user_id
         WHERE s.user_id=$1
         ORDER BY s.created_at DESC
         LIMIT 1`,
        [userId]
      ),
      db.query(
        `SELECT j.*, cp.name profile_name, ci.instance_name
         FROM companion_jobs j
         LEFT JOIN client_profiles cp ON cp.id=j.client_profile_id AND cp.user_id=j.user_id
         LEFT JOIN client_instances ci ON ci.id=j.client_instance_id AND ci.user_id=j.user_id
         WHERE j.user_id=$1
         ORDER BY j.created_at DESC
         LIMIT 25`,
        [userId]
      ),
      db.query(`SELECT id, username, legacy_login, display_name FROM accounts WHERE user_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, proxy_type, host, port, status FROM proxies WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(`SELECT id, name, type, status FROM workflows WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, [userId]),
      db.query(
        `SELECT
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_devices,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status IN ('pending','running','launching','scanning','detected')) running_clients,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status IN ('stopped','crashed','unknown')) stopped_clients,
          (SELECT COUNT(*)::int FROM companion_jobs WHERE user_id=$1 AND status IN ('queued','accepted','running','paused','waiting_for_user')) active_jobs`,
        [userId]
      ),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    res.render('clients', {
      title: 'Launch Profiles',
      helper,
      settings,
      devices: devices.rows,
      profiles: profiles.rows,
      instances: instances.rows,
      snapshot: snapshot.rows[0] || null,
      jobs: jobs.rows,
      accounts: accounts.rows,
      proxies: proxies.rows,
      workflows: workflows.rows,
      stats: stats.rows[0],
      access,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.post('/clients/profiles', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.clientLauncher) throw new Error('Client Launcher is not available for your subscription tier.');
    const profile = await clientProfileFromBody(userId, req.body);
    const result = await db.query(
      `INSERT INTO client_profiles (user_id, name, client_type, launch_args_encrypted, default_account_id, default_proxy_id, default_workflow_id, notes, enabled, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
       RETURNING id`,
      [
        userId,
        profile.name,
        profile.client_type,
        encrypt(profile.launch_args),
        profile.default_account_id,
        profile.default_proxy_id,
        profile.default_workflow_id,
        profile.notes,
        profile.enabled
      ]
    );
    await activity.log(userId, 'client_profile_created', 'client_profile', result.rows[0].id, `Created launch profile ${profile.name}`, { client_type: profile.client_type });
    await auditLog(userId, userId, 'client_profile_created', 'client_profile', result.rows[0].id, `Created launch profile ${profile.name}`, { client_type: profile.client_type });
    res.redirect('/clients');
  } catch (err) { next(err); }
});

app.post('/clients/profiles/:id', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.clientLauncher) throw new Error('Client Launcher is not available for your subscription tier.');
    const existing = await loadClientProfile(userId, req.params.id);
    const profile = await clientProfileFromBody(userId, req.body);
    await db.query(
      `UPDATE client_profiles
       SET name=$1, client_type=$2, launch_args_encrypted=$3, default_account_id=$4, default_proxy_id=$5, default_workflow_id=$6, notes=$7, enabled=$8, updated_at=NOW()
       WHERE id=$9 AND user_id=$10`,
      [
        profile.name,
        profile.client_type,
        profile.launch_args ? encrypt(profile.launch_args) : existing.launch_args_encrypted,
        profile.default_account_id,
        profile.default_proxy_id,
        profile.default_workflow_id,
        profile.notes,
        profile.enabled,
        req.params.id,
        userId
      ]
    );
    await activity.log(userId, 'client_profile_updated', 'client_profile', req.params.id, `Updated launch profile ${profile.name}`, { client_type: profile.client_type });
    res.redirect('/clients');
  } catch (err) { next(err); }
});

app.post('/clients/profiles/:id/delete', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.clientLauncher) throw new Error('Client Launcher is not available for your subscription tier.');
    const result = await db.query(
      `DELETE FROM client_profiles
       WHERE id=$1 AND user_id=$2
       RETURNING id, name`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Client profile not found.');
    await activity.log(userId, 'client_profile_deleted', 'client_profile', result.rows[0].id, `Deleted launch profile ${result.rows[0].name}`);
    await auditLog(userId, userId, 'client_profile_deleted', 'client_profile', result.rows[0].id, `Deleted launch profile ${result.rows[0].name}`);
    res.redirect('/clients');
  } catch (err) { next(err); }
});

app.post('/clients/profiles/:id/launch', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.clientLauncher) {
      throw new Error('Client launcher is not available for your subscription tier.');
    }
    const profile = await loadClientProfile(userId, req.params.id);
    const deviceId = req.body.companion_device_id ? Number(req.body.companion_device_id) : null;
    const accountId = req.body.account_id ? Number(req.body.account_id) : profile.default_account_id || null;
    let proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : profile.default_proxy_id || null;
    if (deviceId) await assertDeviceOwnership(userId, deviceId);
    if (accountId) await assertAccountOwnership(userId, accountId);
    if (!proxyId && accountId) {
      const accountProxy = await db.query('SELECT COALESCE(assigned_http_proxy_id, proxy_id, assigned_socks5_proxy_id) proxy_id FROM accounts WHERE id=$1 AND user_id=$2', [accountId, userId]);
      proxyId = accountProxy.rows[0] ? accountProxy.rows[0].proxy_id : null;
    }
    if (proxyId) await assertProxyOwnership(userId, proxyId);
    const payload = await clientLaunchPayload(userId, profile, { accountId, proxyId });
    const job = await db.query(
      `INSERT INTO companion_jobs (user_id, companion_device_id, client_profile_id, account_id, proxy_id, job_type, status, payload, safe_payload_json, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'launch_client', 'queued', $6, $6, NOW())
       RETURNING id`,
      [userId, deviceId, profile.id, accountId, proxyId, payload]
    );
    await activity.log(userId, 'client_launch_requested', 'client_profile', profile.id, `Queued launch for ${profile.name}`, { companion_job_id: job.rows[0].id });
    await auditLog(userId, userId, 'client_launch_requested', 'client_profile', profile.id, `Queued launch for ${profile.name}`, { companion_job_id: job.rows[0].id });
    res.redirect(`/local-jobs?launch_job=${job.rows[0].id}`);
  } catch (err) { next(err); }
});

app.post('/clients/instances/:id/attach', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const instance = await loadClientInstance(userId, req.params.id);
    const accountId = req.body.account_id ? Number(req.body.account_id) : null;
    const proxyId = req.body.proxy_id ? Number(req.body.proxy_id) : null;
    if (accountId) await assertAccountOwnership(userId, accountId);
    if (proxyId) await assertProxyOwnership(userId, proxyId);
    await db.query(
      `UPDATE client_instances
       SET account_id=$1, proxy_id=$2, suggested_account_id=NULL, match_confidence=$3, match_reason=$4, updated_at=NOW()
       WHERE id=$5 AND user_id=$6`,
      [accountId, proxyId, accountId ? 'manual' : null, accountId ? 'User confirmed account match.' : null, instance.id, userId]
    );
    if (accountId) await applyClientInstanceAccountStatus(userId, accountId, {}, instance);
    await insertClientInstanceEvent(userId, instance.id, 'account_matched_to_client', 'Attached account/proxy to live session.', { account_id: accountId, proxy_id: proxyId });
    await activity.log(userId, 'account_matched_to_client', 'client_instance', instance.id, 'Attached account/proxy to live session', { account_id: accountId });
    res.redirect('/instances');
  } catch (err) { next(err); }
});

app.post('/clients/instances/:id/stop-tracking', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const instance = await loadClientInstance(userId, req.params.id);
    await db.query(
      `UPDATE client_instances SET status='stopped', stopped_at=NOW(), updated_at=NOW() WHERE id=$1 AND user_id=$2`,
      [instance.id, userId]
    );
    await insertClientInstanceEvent(userId, instance.id, 'stop_tracking', 'User stopped tracking this live session.');
    await activity.log(userId, 'client_stopped_tracking', 'client_instance', instance.id, 'Stopped tracking live session');
    res.redirect('/instances');
  } catch (err) { next(err); }
});

app.post('/clients/instances/:id/request-snapshot', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.snapshots) throw new Error('Live session snapshots are not available for your subscription tier.');
    const instance = await loadClientInstance(userId, req.params.id);
    const settings = await getSettings(userId);
    if (settings.allow_companion_snapshots !== 'true') throw new Error('Snapshots are disabled in Settings.');
    const payload = {
      command: 'request_snapshot',
      client_instance_id: instance.id,
      window_title: instance.window_title,
      safety: {
        user_opt_in_required: true,
        capture_only_selected_window: true,
        no_secret_capture_intent: true
      }
    };
    const job = await db.query(
      `INSERT INTO companion_jobs (user_id, companion_device_id, client_instance_id, account_id, proxy_id, job_type, status, payload, safe_payload_json, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'request_snapshot', 'queued', $6, $6, NOW())
       RETURNING id`,
      [userId, instance.companion_device_id, instance.id, instance.account_id, instance.proxy_id, payload]
    );
    await insertClientInstanceEvent(userId, instance.id, 'snapshot_requested', 'Snapshot requested by user.', { companion_job_id: job.rows[0].id });
    await activity.log(userId, 'snapshot_requested', 'client_instance', instance.id, 'Snapshot requested for live session');
    res.redirect(`/instances?snapshot_job=${job.rows[0].id}`);
  } catch (err) { next(err); }
});

app.get('/local-jobs', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const filters = {
      status: escapeText(req.query.status),
      job_type: escapeText(req.query.job_type)
    };
    const clauses = ['j.user_id=$1'];
    const params = [userId];
    if (companionJobStatuses.includes(filters.status)) {
      params.push(filters.status);
      clauses.push(`j.status=$${params.length}`);
    }
    if (companionJobTypes.includes(filters.job_type)) {
      params.push(filters.job_type);
      clauses.push(`j.job_type=$${params.length}`);
    }
    const where = clauses.join(' AND ');
    const [jobs, stats, events, devices] = await Promise.all([
      db.query(
        `SELECT j.*, d.device_name, w.name workflow_name, wr.status workflow_run_status,
                cp.name profile_name, ci.instance_name, a.username account_username, a.legacy_login account_legacy_login,
                p.name proxy_name, p.host proxy_host, p.port proxy_port
         FROM companion_jobs j
         LEFT JOIN companion_devices d ON d.id=j.companion_device_id AND d.user_id=j.user_id
         LEFT JOIN workflows w ON w.id=j.workflow_id AND w.user_id=j.user_id
         LEFT JOIN workflow_runs wr ON wr.id=j.workflow_run_id AND wr.user_id=j.user_id
         LEFT JOIN client_profiles cp ON cp.id=j.client_profile_id AND cp.user_id=j.user_id
         LEFT JOIN client_instances ci ON ci.id=j.client_instance_id AND ci.user_id=j.user_id
         LEFT JOIN accounts a ON a.id=j.account_id AND a.user_id=j.user_id
         LEFT JOIN proxies p ON p.id=j.proxy_id AND p.user_id=j.user_id
         WHERE ${where}
         ORDER BY j.created_at DESC
         LIMIT 200`,
        params
      ),
      db.query(
        `SELECT
          COUNT(*)::int total,
          COUNT(*) FILTER (WHERE status='queued')::int queued,
          COUNT(*) FILTER (WHERE status IN ('accepted','running','paused','waiting_for_user'))::int running,
          COUNT(*) FILTER (WHERE status='completed')::int completed,
          COUNT(*) FILTER (WHERE status='failed')::int failed,
          COUNT(*) FILTER (WHERE status='cancelled')::int cancelled
         FROM companion_jobs
         WHERE user_id=$1`,
        [userId]
      ),
      db.query(
        `SELECT e.*, j.job_type
         FROM companion_job_events e
         LEFT JOIN companion_jobs j ON j.id=e.companion_job_id AND j.user_id=e.user_id
         WHERE e.user_id=$1
         ORDER BY e.created_at DESC
         LIMIT 80`,
        [userId]
      ),
      db.query(`SELECT id, device_name, status, last_seen_at FROM companion_devices WHERE user_id=$1 AND status <> 'revoked' ORDER BY last_seen_at DESC NULLS LAST`, [userId])
    ]);
    res.render('local-jobs', {
      title: 'Local Jobs',
      jobs: jobs.rows,
      stats: stats.rows[0],
      events: events.rows,
      devices: devices.rows,
      filters,
      companionJobStatuses,
      companionJobTypes,
      jobTypeLabel,
      query: req.query,
      mask
    });
  } catch (err) { next(err); }
});

app.post('/local-jobs/:id/cancel', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const result = await db.query(
      `UPDATE companion_jobs
       SET status='cancelled', completed_at=NOW(), updated_at=NOW(), result=jsonb_set(COALESCE(result, '{}'::jsonb), '{cancelled_by}', '"user"', true), safe_result_json=jsonb_set(COALESCE(safe_result_json, '{}'::jsonb), '{cancelled_by}', '"user"', true)
       WHERE id=$1 AND user_id=$2 AND status IN ('queued','accepted','running','paused','waiting_for_user')
       RETURNING id, workflow_run_id, job_type`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Local job was not found or cannot be cancelled.');
    const job = result.rows[0];
    if (job.workflow_run_id) {
      await db.query(`UPDATE workflow_runs SET status='cancelled', completed_at=NOW(), updated_at=NOW() WHERE id=$1 AND user_id=$2`, [job.workflow_run_id, userId]);
      await insertWorkflowRunEvent(userId, job.workflow_run_id, 'cancelled', 'User cancelled the local job.');
    }
    await insertCompanionJobEvent(userId, job.id, job.workflow_run_id, 'cancelled', 'User cancelled the local job.');
    await activity.log(userId, 'local_job_cancelled', 'companion_job', job.id, `Cancelled local job ${job.job_type}`);
    res.redirect('/local-jobs');
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
        COUNT(*) FILTER (WHERE status IN ('working','online','works'))::int working,
        COUNT(*) FILTER (WHERE status IN ('failed','blocked','banned'))::int failed,
        COUNT(*) FILTER (WHERE status IN ('unchecked','untested','unknown','review'))::int unchecked,
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

app.post('/proxies/bulk-status', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const selected = selectedProxyIds(req.body);
    if (!selected.length) throw new Error('Select at least one proxy.');
    const status = oneOf(req.body.status, proxyStatuses, 'unchecked');
    const result = await db.query(
      `UPDATE proxies SET status=$1, updated_at=NOW()
       WHERE user_id=$2 AND id = ANY($3)
       RETURNING id`,
      [status, userId, selected]
    );
    await activity.log(userId, `proxies_marked_${status}`, 'proxy', null, `Marked ${result.rowCount} proxy/proxies ${status}`, { count: result.rowCount, status });
    await auditLog(userId, userId, 'proxy_bulk_status_changed', 'proxy', null, `Marked ${result.rowCount} proxy/proxies ${status}`, { count: result.rowCount, status });
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

app.get('/local-helper', requireAuth, (req, res) => {
  res.redirect('/companion');
});

app.get('/companion', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const [helper, settings, devices, statuses, snapshot, jobs, stats, access] = await Promise.all([
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
      ),
      db.query(
        `SELECT
          (SELECT COUNT(*)::int FROM companion_devices WHERE user_id=$1 AND status='connected') connected_devices,
          (SELECT COUNT(*)::int FROM companion_jobs WHERE user_id=$1 AND status IN ('queued','accepted','running','paused','waiting_for_user')) active_jobs,
          (SELECT COUNT(*)::int FROM client_instances WHERE user_id=$1 AND status IN ('pending','launching','running','scanning','detected')) running_instances`,
        [userId]
      ),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    const pairingCode = req.session.helperPairingCode || null;
    req.session.helperPairingCode = null;
    res.render('companion', {
      title: 'Client Monitor',
      helper,
      settings,
      devices: devices.rows,
      clientStatuses: statuses.rows,
      snapshot: snapshot.rows[0] || null,
      jobs: jobs.rows,
      stats: stats.rows[0],
      pairingCode,
      download: helperDownloadMetadata(),
      access
    });
  } catch (err) { next(err); }
});

app.post('/companion/pairing-code', requireAuth, async (req, res, next) => {
  try {
    const userId = req.currentUserId;
    const access = await accessSummaryForUser(req.currentUserRecord);
    if (!access.gates.addDevice) {
      req.session.helperPairingCode = null;
      throw new Error('Connected device limit reached for your subscription tier.');
    }
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
    await activity.log(userId, 'companion_pair', 'companion', null, 'Generated a short-lived Local App pairing code');
    await auditLog(userId, userId, 'companion_pair', 'companion', null, 'Generated a short-lived Local App pairing code');
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
    if (!result.rows[0]) throw new Error('Local App device not found.');
    await activity.log(userId, 'companion_revoke', 'companion_device', result.rows[0].id, `Revoked Local App device ${result.rows[0].device_name || result.rows[0].id}`);
    await auditLog(userId, userId, 'companion_revoke', 'companion_device', result.rows[0].id, 'Revoked Local App device');
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
      [escapeText(req.body.device_name) || 'GS Local App', req.body.allow_screenshots === 'yes', req.params.id, userId]
    );
    if (!result.rows[0]) throw new Error('Local App device not found.');
    await activity.log(userId, 'companion_device_updated', 'companion_device', result.rows[0].id, 'Updated Local App device settings');
    res.redirect('/companion');
  } catch (err) { next(err); }
});

app.get('/downloads/helper/windows', requireAuth, (req, res) => {
  const download = helperDownloadMetadata();
  if (download.available) {
    return res.download(download.filePath, download.fileName);
  }
  return res.status(404).render('helper-download', {
    title: 'GS Local App Download',
    download
  });
});

app.get('/downloads', requireAuth, async (req, res, next) => {
  try {
    const [downloadItems, access] = await Promise.all([
      db.query(`SELECT * FROM download_items WHERE status <> 'hidden' ORDER BY sort_order, category, title`),
      accessSummaryForUser(req.currentUserRecord)
    ]);
    res.render('downloads', {
      title: 'Downloads',
      download: helperDownloadMetadata(),
      companionName: 'GS Local App',
      downloadItems: downloadItems.rows,
      access
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
      'client_detection_process_names', 'client_snapshot_retention_hours', 'client_launcher_requires_confirmation',
      'enable_local_client_detection', 'auto_sync_stats_on_client_detected', 'stats_refresh_cooldown_minutes', 'custom_client_process_names',
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
    const admin = false;
    const filters = {
      q: escapeText(req.query.q),
      action: escapeText(req.query.action),
      entity_type: escapeText(req.query.entity_type),
      date: escapeText(req.query.date)
    };
    const clauses = [];
    const params = [userId];
    clauses.push(`l.user_id = $1`);
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
      db.query(`SELECT DISTINCT action FROM activity_logs WHERE user_id=$1 ORDER BY action`, [userId])
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
  client_detection_process_names: 'RuneLite,JagexLauncher,Jagex Launcher,osclient,DreamBot',
  enable_local_client_detection: 'false',
  auto_sync_stats_on_client_detected: 'false',
  stats_refresh_cooldown_minutes: '30',
  custom_client_process_names: 'RuneLite,JagexLauncher,Jagex Launcher,osclient,DreamBot',
  client_snapshot_retention_hours: '24',
  client_launcher_requires_confirmation: 'true',
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
  res.locals.companionJobTypes = companionJobTypes;
  res.locals.clientTypes = clientTypes;
  res.locals.clientInstanceStatuses = clientInstanceStatuses;
  res.locals.clientStates = clientStates;
  res.locals.wealthSources = wealthSources;
  res.locals.paymentMethods = paymentMethods;
  res.locals.downloadStatuses = downloadStatuses;
  res.locals.downloadCategories = downloadCategories;
  res.locals.clientStateLabel = clientStateLabel;
  res.locals.clientStateClass = clientStateClass;
  res.locals.clientStateFromRow = clientStateFromRow;
  res.locals.formatWealthValue = formatWealthValue;
  res.locals.jobTypeLabel = jobTypeLabel;
  res.locals.isAdmin = req.currentUser && req.currentUser.role === 'admin';
  res.locals.hasFullAccess = false;
  res.locals.isLimitedAccess = false;
  res.locals.canExport = false;
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
    res.locals.hasFullAccess = hasFullAppAccess(user);
    res.locals.isLimitedAccess = hasLimitedAccess(user);
    res.locals.canExport = canExportData(user);
    next();
  } catch (error) {
    next(error);
  }
}

function isAdminUser(user) {
  return Boolean(user && user.role === 'admin');
}

function hasFullAppAccess(user) {
  return isAdminUser(user) || activeSubscriptionStatuses.includes(user && user.subscription_status);
}

function hasLimitedAccess(user) {
  return Boolean(user && !isAdminUser(user) && ['inactive', 'expired'].includes(user.subscription_status));
}

function canExportData(user) {
  return hasFullAppAccess(user);
}

function isBlockedUser(user) {
  return Boolean(user && !isAdminUser(user) && (user.subscription_status === 'banned' || user.disabled_at));
}

function requireNotBlocked(req, res, next) {
  if (!isBlockedUser(req.currentUserRecord)) return next();
  return res.redirect('/locked');
}

function limitedAccessAllowed(req) {
  if (!hasLimitedAccess(req.currentUserRecord)) return false;
  return false;
}

function restrictLimitedUsers(req, res, next) {
  if (hasFullAppAccess(req.currentUserRecord) || limitedAccessAllowed(req)) return next();
  return limitedAccessResponse(req, res);
}

function requireFullAccess(req, res, next) {
  if (hasFullAppAccess(req.currentUserRecord)) return next();
  return limitedAccessResponse(req, res);
}

function limitedAccessResponse(req, res) {
  const message = 'GS Account Manager is currently in private build. This account does not have active access yet.';
  const accept = typeof req.get === 'function' ? req.get('accept') || '' : '';
  if (req.path.startsWith('/api/') || accept.includes('application/json')) {
    return res.status(403).json({ error: message });
  }
  return res.redirect('/locked');
}

async function userIdHasFullAccess(userId) {
  const result = await db.query('SELECT role, subscription_status, disabled_at FROM users WHERE id=$1', [userId]);
  return hasFullAppAccess(result.rows[0]) && !isBlockedUser(result.rows[0]);
}

function requireAdmin(req, res, next) {
  if (isAdminUser(req.currentUserRecord)) return next();
  return res.status(403).render('error', { title: 'Admin only', message: 'This page is only available to admins.' });
}

async function subscriptionTierForUser(user) {
  if (!user) return null;
  if (user.subscription_tier_id) {
    const byId = await db.query('SELECT * FROM subscription_tiers WHERE id=$1', [user.subscription_tier_id]);
    if (byId.rows[0]) return byId.rows[0];
  }
  const fallbackSlug = isAdminUser(user) ? 'admin-owner' : 'starter';
  const fallback = await db.query('SELECT * FROM subscription_tiers WHERE slug=$1', [fallbackSlug]);
  return fallback.rows[0] || null;
}

async function browserTaskUsageToday(userId) {
  const result = await db.query(
    `SELECT successful_count, failed_count
     FROM browser_task_usage
     WHERE user_id=$1 AND date=CURRENT_DATE`,
    [userId]
  );
  return result.rows[0] || { successful_count: 0, failed_count: 0 };
}

async function activeDeviceCount(userId) {
  const result = await db.query(
    `SELECT COUNT(*)::int count
     FROM companion_devices
     WHERE user_id=$1 AND status <> 'revoked'`,
    [userId]
  );
  return result.rows[0].count;
}

async function accessSummaryForUser(user) {
  const [tier, usage, deviceCount] = await Promise.all([
    subscriptionTierForUser(user),
    user && user.id ? browserTaskUsageToday(user.id) : Promise.resolve({ successful_count: 0, failed_count: 0 }),
    user && user.id ? activeDeviceCount(user.id) : Promise.resolve(0)
  ]);
  const gates = {
    clientMonitor: canUseClientMonitor(user, tier),
    clientLauncher: canUseClientLauncher(user, tier),
    browserAutomator: canUseBrowserAutomator(user, tier),
    snapshots: canUseSnapshots(user, tier),
    addDevice: canAddDevice(user, tier, deviceCount),
    runBrowserTask: canRunBrowserTask(user, tier, usage)
  };
  return {
    tier,
    usage,
    deviceCount,
    gates,
    dailyTaskLimit: isAdminUser(user) || !tier || tier.daily_successful_browser_task_limit === null
      ? null
      : Number(tier.daily_successful_browser_task_limit),
    dailyTaskLimitLabel: isAdminUser(user) || !tier || tier.daily_successful_browser_task_limit === null
      ? 'Unlimited'
      : String(tier.daily_successful_browser_task_limit)
  };
}

function activeTierAccess(user) {
  return Boolean(user && (isAdminUser(user) || activeSubscriptionStatuses.includes(user.subscription_status)));
}

function canUseBrowserAutomator(user, tier) {
  if (isAdminUser(user)) return true;
  return activeTierAccess(user) && Boolean(tier && tier.active && tier.browser_automator_enabled);
}

function canUseClientMonitor(user, tier) {
  if (isAdminUser(user)) return true;
  return activeTierAccess(user) && Boolean(tier && tier.active);
}

function canUseClientLauncher(user, tier) {
  if (isAdminUser(user)) return true;
  return activeTierAccess(user) && Boolean(tier && tier.active && tier.client_launcher_enabled);
}

function canUseSnapshots(user, tier) {
  if (isAdminUser(user)) return true;
  return activeTierAccess(user) && Boolean(tier && tier.active && tier.snapshots_enabled);
}

function canAddDevice(user, tier, deviceCount = 0) {
  if (isAdminUser(user)) return true;
  if (!activeTierAccess(user) || !tier || !tier.active) return false;
  if (tier.max_devices === null || tier.max_devices === undefined) return true;
  return Number(deviceCount) < Number(tier.max_devices);
}

function canRunBrowserTask(user, tier, usage = {}) {
  if (isAdminUser(user)) return true;
  if (!canUseBrowserAutomator(user, tier)) return false;
  if (!tier || tier.daily_successful_browser_task_limit === null || tier.daily_successful_browser_task_limit === undefined) return true;
  return Number(usage.successful_count || 0) < Number(tier.daily_successful_browser_task_limit);
}

async function recordBrowserTaskUsage(userId, outcome) {
  const successful = outcome === 'successful' ? 1 : 0;
  const failed = outcome === 'failed' ? 1 : 0;
  await db.query(
    `INSERT INTO browser_task_usage (user_id, date, successful_count, failed_count, updated_at)
     VALUES ($1, CURRENT_DATE, $2, $3, NOW())
     ON CONFLICT (user_id, date) DO UPDATE SET
       successful_count=browser_task_usage.successful_count + EXCLUDED.successful_count,
       failed_count=browser_task_usage.failed_count + EXCLUDED.failed_count,
       updated_at=NOW()`,
    [userId, successful, failed]
  );
}

function isBrowserTaskJob(jobType) {
  return ['workflow_run', 'run_workflow', 'open_browser', 'fill_visible_fields'].includes(jobType);
}

function jobTypeLabel(type) {
  return {
    workflow_run: 'Browser Automator',
    run_workflow: 'Browser Automator',
    open_browser: 'Open Browser',
    fill_visible_fields: 'Fill Visible Fields',
    launch_client: 'Launch Client',
    stop_client: 'Stop Client',
    detect_clients: 'Detect Clients',
    request_snapshot: 'Snapshot Request',
    client_status: 'Client Status',
    heartbeat: 'Heartbeat'
  }[type] || String(type || 'Local Job').replace(/_/g, ' ');
}

function helperDownloadMetadata() {
  const distDir = path.join(__dirname, '..', 'companion', 'dist');
  const windowsPath = path.join(distDir, 'GS Local App Setup.exe');
  const legacyWindowsPath = path.join(distDir, 'GS Account Manager Companion Setup.exe');
  const filePath = fs.existsSync(windowsPath) ? windowsPath : legacyWindowsPath;
  const fileName = path.basename(filePath);
  const available = fs.existsSync(windowsPath);
  const legacyAvailable = !available && fs.existsSync(legacyWindowsPath);
  return {
    available: available || legacyAvailable,
    version: available || legacyAvailable ? config.appVersion : 'Coming soon',
    releaseDate: available || legacyAvailable ? 'Packaged locally' : 'Coming soon',
    fileSize: available || legacyAvailable ? `${Math.ceil(fs.statSync(filePath).size / 1024 / 1024)} MB` : '',
    filePath,
    fileName,
    windowsPath: '/downloads/helper/windows'
  };
}

function setupStepsForWorkspace(counts = {}, helper = {}, access = {}) {
  const steps = [
    {
      number: 1,
      title: 'Discord workspace',
      status: 'complete',
      label: 'Ready',
      description: 'Your Discord login owns this workspace and keeps records isolated by user.',
      href: '/',
      action: 'Open Dashboard'
    },
    {
      number: 2,
      title: 'Install GS Local App',
      status: helper && helper.connected ? 'complete' : 'current',
      label: helper && helper.connected ? 'Connected' : 'Required for automation',
      description: 'Browser automation, client monitoring, launch jobs, and live status run locally on your PC.',
      href: '/downloads',
      action: 'Open Downloads'
    },
    {
      number: 3,
      title: 'Pair Local App Device',
      status: Number(counts.devices || 0) > 0 ? 'complete' : helper && helper.connected ? 'complete' : 'current',
      label: `${Number(counts.connected_devices || 0)} connected`,
      description: 'Create a short-lived code on the website, then enter it in GS Local App.',
      href: '/companion',
      action: 'Pair Device'
    },
    {
      number: 4,
      title: 'Add accounts and proxies',
      status: Number(counts.accounts || 0) > 0 ? 'complete' : 'current',
      label: `${Number(counts.accounts || 0)} accounts / ${Number(counts.proxies || 0)} proxies`,
      description: 'Import or add account and proxy records. Sensitive values stay encrypted and masked by default.',
      href: '/accounts',
      secondaryHref: '/proxies',
      action: 'Open Accounts'
    },
    {
      number: 5,
      title: 'Create launch profiles',
      status: Number(counts.launch_profiles || 0) > 0 ? 'complete' : 'next',
      label: `${Number(counts.launch_profiles || 0)} profiles`,
      description: 'Launch profiles describe local client paths and startup options for visible user-triggered launches.',
      href: '/clients',
      action: 'Open Launch Profiles'
    },
    {
      number: 6,
      title: 'Build automation jobs',
      status: Number(counts.automations || 0) > 0 ? 'complete' : 'next',
      label: access && access.gates && access.gates.browserAutomator ? 'Enabled by tier' : 'Tier gated',
      description: 'Browser Automator jobs are queued to GS Local App and must pause for CAPTCHA, 2FA, or security checks.',
      href: '/workflows',
      action: 'Open Browser Automator'
    },
    {
      number: 7,
      title: 'Monitor jobs and sessions',
      status: Number(counts.local_jobs || 0) > 0 || Number(counts.live_sessions || 0) > 0 ? 'complete' : 'next',
      label: `${Number(counts.local_jobs || 0)} jobs / ${Number(counts.live_sessions || 0)} sessions`,
      description: 'Use Local Jobs and Live Sessions to watch status, manual pauses, device heartbeats, and safe events.',
      href: '/local-jobs',
      secondaryHref: '/instances',
      action: 'Open Local Jobs'
    }
  ];

  let foundCurrent = false;
  return steps.map(step => {
    if (step.status === 'complete') return step;
    if (!foundCurrent) {
      foundCurrent = true;
      return { ...step, status: 'current' };
    }
    return { ...step, status: step.status === 'current' ? 'next' : step.status };
  });
}

function automationCompatibilityMatrix() {
  return [
    {
      name: 'GS Local App',
      type: 'Local automation agent',
      detection: 'Supported',
      launchProfiles: 'Supported',
      browserAutomator: 'Foundation ready',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'HTTP proxy handoff planned',
      status: 'working',
      notes: 'Required for paid automation features. Runs locally and reports safe job status to the website.'
    },
    {
      name: 'Automation Browser',
      type: 'Visible controlled browser',
      detection: 'Not applicable',
      launchProfiles: 'Managed by Local App',
      browserAutomator: 'Foundation ready',
      liveSessions: 'Job status only',
      snapshots: 'Opt-in starter',
      proxyMode: 'Planned through Local App launch options',
      status: 'placeholder',
      notes: 'Designed for visible, user-triggered browser tasks. CAPTCHA, 2FA, and security checks must pause for manual completion.'
    },
    {
      name: 'RuneLite',
      type: 'Client tool',
      detection: 'Window/process detection starter',
      launchProfiles: 'Supported',
      browserAutomator: 'Not applicable',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'External/client-dependent',
      status: 'partial',
      notes: 'GS can detect and launch configured local paths. It does not inject, read memory, or control gameplay.'
    },
    {
      name: 'Jagex Launcher',
      type: 'Launcher',
      detection: 'Window/process detection starter',
      launchProfiles: 'Supported',
      browserAutomator: 'Not applicable',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'External/client-dependent',
      status: 'partial',
      notes: 'GS can track visible process/window status only. Login, verification, and security checks remain manual.'
    },
    {
      name: 'Official OSRS Client',
      type: 'Client tool',
      detection: 'Window/process detection starter',
      launchProfiles: 'Supported',
      browserAutomator: 'Not applicable',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'External/client-dependent',
      status: 'partial',
      notes: 'Public stats sync can use display names. Wealth values require manual or safe local reporting.'
    },
    {
      name: 'DreamBot',
      type: 'Third-party client',
      detection: 'Window/process detection starter',
      launchProfiles: 'Configurable',
      browserAutomator: 'Not applicable',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'External/client-dependent',
      status: 'partial',
      notes: 'GS only detects/launches configured local software. No scripts, gameplay automation, injection, memory reads, or bypass behavior are implemented.'
    },
    {
      name: 'Custom Client',
      type: 'User configured',
      detection: 'Configured process names',
      launchProfiles: 'Configurable',
      browserAutomator: 'Not applicable',
      liveSessions: 'Supported starter',
      snapshots: 'Opt-in starter',
      proxyMode: 'External/client-dependent',
      status: 'partial',
      notes: 'Users can add local executable paths and process names. Matching should be confirmed manually unless confidence is high.'
    }
  ];
}

function setupGuideSections() {
  return [
    {
      title: '1. Connect Discord',
      status: 'Working',
      body: 'Sign in with Discord. Your internal user ID scopes all accounts, proxies, settings, logs, devices, jobs, automations, live sessions, and stats.'
    },
    {
      title: '2. Install and pair GS Local App',
      status: 'Foundation ready',
      body: 'Install the Windows Local App when the packaged installer is available. Create a pairing code on Client Monitor, enter it locally, then confirm heartbeat status.'
    },
    {
      title: '3. Import account and proxy data',
      status: 'Working',
      body: 'Use Accounts and Proxies pages for import/export. Passwords, OTP secrets, recovery passwords, and proxy passwords are encrypted at rest and masked in list views.'
    },
    {
      title: '4. Configure launch profiles',
      status: 'Foundation ready',
      body: 'Create Launch Profiles for local client paths and startup options. Launches are queued to a visible Local App device and tracked as Local Jobs.'
    },
    {
      title: '5. Run Browser Automator jobs',
      status: 'Scaffolded',
      body: 'Browser Automator jobs are meant to run in a visible local browser. They may fill visible fields after user action, but must pause for CAPTCHA, 2FA, email verification, phone verification, and security checks.'
    },
    {
      title: '6. Watch Local Jobs and Live Sessions',
      status: 'Working starter',
      body: 'Local Jobs show queued/running/completed work. Live Sessions show detected local client status, linked accounts, public stats sync, and optional snapshots.'
    }
  ];
}

function proxyMode(account, helper, settings) {
  const hasProxy = Boolean(account && account.proxy_host);
  return {
    browserMode: helper && helper.connected ? 'Local App mode' : 'Website-only mode',
    modeDescription: helper && helper.connected
      ? 'Local App mode: opens controlled Chrome through selected proxy when available.'
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

function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || `item-${Date.now()}`;
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

async function clientProfileFromBody(userId, body) {
  const defaultAccountId = body.default_account_id ? Number(body.default_account_id) : null;
  const defaultProxyId = body.default_proxy_id ? Number(body.default_proxy_id) : null;
  const defaultWorkflowId = body.default_workflow_id ? Number(body.default_workflow_id) : null;
  if (defaultAccountId) await assertAccountOwnership(userId, defaultAccountId);
  if (defaultProxyId) await assertProxyOwnership(userId, defaultProxyId);
  if (defaultWorkflowId) await loadWorkflow(userId, defaultWorkflowId);
  const name = escapeText(body.name);
  if (!name) throw new Error('Client profile name is required.');
  return {
    name,
    client_type: oneOf(body.client_type, clientTypes, 'custom'),
    launch_args: escapeText(body.launch_args),
    default_account_id: defaultAccountId,
    default_proxy_id: defaultProxyId,
    default_workflow_id: defaultWorkflowId,
    notes: escapeText(body.notes),
    enabled: Array.isArray(body.enabled) ? body.enabled.includes('yes') : body.enabled !== 'no'
  };
}

async function assertClientProfileOwnership(userId, profileId) {
  const result = await db.query('SELECT id FROM client_profiles WHERE id=$1 AND user_id=$2', [profileId, userId]);
  if (!result.rows[0]) throw new Error('Client profile not found for this user.');
}

async function loadClientProfile(userId, profileId) {
  const result = await db.query('SELECT * FROM client_profiles WHERE id=$1 AND user_id=$2', [profileId, userId]);
  if (!result.rows[0]) throw new Error('Client profile not found.');
  return result.rows[0];
}

async function assertClientInstanceOwnership(userId, instanceId) {
  const result = await db.query('SELECT id FROM client_instances WHERE id=$1 AND user_id=$2', [instanceId, userId]);
  if (!result.rows[0]) throw new Error('Client instance not found for this user.');
}

async function loadClientInstance(userId, instanceId) {
  const result = await db.query('SELECT * FROM client_instances WHERE id=$1 AND user_id=$2', [instanceId, userId]);
  if (!result.rows[0]) throw new Error('Client instance not found.');
  return result.rows[0];
}

async function prepareDetectedClientInstance(userId, item) {
  if (item.account_id) return item;
  const suggestion = await suggestAccountMatch(userId, item);
  if (!suggestion) return item;
  return {
    ...item,
    suggested_account_id: suggestion.account_id,
    match_confidence: suggestion.confidence,
    match_reason: suggestion.reason
  };
}

async function suggestAccountMatch(userId, item) {
  const haystack = normalizeMatchText([
    item.window_title,
    item.instance_name,
    item.process_name,
    item.current_activity,
    item.match_hint
  ].filter(Boolean).join(' '));
  if (!haystack) return null;
  const accounts = await db.query(
    `SELECT id, username, legacy_login, display_name, jagex_name
     FROM accounts
     WHERE user_id=$1 AND archived_at IS NULL
     ORDER BY updated_at DESC
     LIMIT 500`,
    [userId]
  );
  let best = null;
  for (const account of accounts.rows) {
    const candidates = [
      ['display name', account.display_name],
      ['jagex name', account.jagex_name],
      ['legacy login', account.legacy_login],
      ['login username', account.username]
    ];
    for (const [label, value] of candidates) {
      const normalized = normalizeMatchText(value);
      if (!normalized || normalized.length < 3) continue;
      const exact = haystack === normalized;
      const contained = haystack.includes(normalized);
      if (!exact && !contained) continue;
      const score = exact ? 100 : normalized.length + (label.includes('display') ? 20 : 0);
      if (!best || score > best.score) {
        best = {
          account_id: account.id,
          confidence: exact ? 'high' : 'suggested',
          reason: `${label} matched visible client text`,
          score
        };
      }
    }
  }
  if (!best) return null;
  return {
    account_id: best.account_id,
    confidence: best.confidence,
    reason: best.reason
  };
}

function normalizeMatchText(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9@._ -]+/g, ' ').replace(/\s+/g, ' ');
}

async function refreshAccountStats(userId, accountId, options = {}) {
  const accountResult = await db.query(
    `SELECT id, username, legacy_login, display_name, jagex_name
     FROM accounts
     WHERE id=$1 AND user_id=$2`,
    [accountId, userId]
  );
  const account = accountResult.rows[0];
  if (!account) throw new Error('Account not found.');
  const displayName = escapeText(options.displayName) || account.display_name || account.jagex_name || account.legacy_login || account.username;
  if (!displayName) throw new Error('A display name or login is required before refreshing stats.');
  const stats = await osrsStats.fetchPublicStats(displayName);
  const savedDisplayName = stats.display_name || displayName;
  const fetchedAt = new Date();
  await db.query(
    `INSERT INTO account_stats (
       user_id, account_id, display_name, total_level, combat_level, attack, strength, defence,
       ranged, prayer, magic, hitpoints, total_xp, other_skills, fetched_at, source, status, error_message
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
     ON CONFLICT (user_id, account_id) DO UPDATE SET
       display_name=EXCLUDED.display_name,
       total_level=EXCLUDED.total_level,
       combat_level=EXCLUDED.combat_level,
       attack=EXCLUDED.attack,
       strength=EXCLUDED.strength,
       defence=EXCLUDED.defence,
       ranged=EXCLUDED.ranged,
       prayer=EXCLUDED.prayer,
       magic=EXCLUDED.magic,
       hitpoints=EXCLUDED.hitpoints,
       total_xp=EXCLUDED.total_xp,
       other_skills=EXCLUDED.other_skills,
       fetched_at=EXCLUDED.fetched_at,
       source=EXCLUDED.source,
       status=EXCLUDED.status,
       error_message=EXCLUDED.error_message
     RETURNING *`,
    [
      userId,
      account.id,
      savedDisplayName,
      stats.total_level,
      stats.combat_level,
      stats.attack,
      stats.strength,
      stats.defence,
      stats.ranged,
      stats.prayer,
      stats.magic,
      stats.hitpoints,
      stats.total_xp,
      stats.skills || {},
      fetchedAt,
      stats.source || 'osrs_hiscores',
      oneOf(stats.status, ['ok', 'not_found', 'failed'], 'failed'),
      stats.error_message || null
    ]
  );
  await db.query(
    `UPDATE accounts
     SET total_level=$1, combat_level=$2, last_stats_sync_at=$3, stats_sync_status=$4, stats_sync_error=$5, updated_at=NOW()
     WHERE id=$6 AND user_id=$7`,
    [
      stats.total_level,
      stats.combat_level,
      fetchedAt,
      oneOf(stats.status, ['ok', 'not_found', 'failed'], 'failed'),
      stats.error_message || null,
      account.id,
      userId
    ]
  );
  const action = stats.status === 'ok' ? 'stats_refreshed' : 'stats_lookup_failed';
  await activity.log(userId, action, 'account', account.id, stats.status === 'ok' ? 'OSRS stats refreshed' : 'OSRS stats lookup failed', {
    status: stats.status,
    display_name: savedDisplayName
  });
  return {
    ...stats,
    display_name: savedDisplayName,
    fetched_at: fetchedAt
  };
}

async function maybeAutoRefreshStats(userId, accountId, settings) {
  if (!accountId || settings.auto_sync_stats_on_client_detected !== 'true') return;
  const cooldownMinutes = Math.max(1, Number(settings.stats_refresh_cooldown_minutes || 30));
  const account = await db.query(
    `SELECT id, last_stats_sync_at
     FROM accounts
     WHERE id=$1 AND user_id=$2`,
    [accountId, userId]
  );
  if (!account.rows[0]) return;
  const lastSync = account.rows[0].last_stats_sync_at ? new Date(account.rows[0].last_stats_sync_at).getTime() : 0;
  if (lastSync && Date.now() - lastSync < cooldownMinutes * 60 * 1000) return;
  try {
    await refreshAccountStats(userId, accountId);
  } catch (error) {
    await activity.log(userId, 'stats_lookup_failed', 'account', accountId, 'Automatic OSRS stats lookup failed', { reason: 'safe_lookup_failed' });
  }
}

async function clientLaunchPayload(userId, profile, options) {
  let account = null;
  let proxy = null;
  if (options.accountId) {
    const result = await db.query(
      `SELECT id, username, legacy_login, display_name, account_type, status
       FROM accounts WHERE id=$1 AND user_id=$2`,
      [options.accountId, userId]
    );
    account = result.rows[0] || null;
  }
  if (options.proxyId) {
    const result = await db.query(
      `SELECT id, name, proxy_type, host, port, status
       FROM proxies WHERE id=$1 AND user_id=$2`,
      [options.proxyId, userId]
    );
    proxy = result.rows[0] || null;
  }
  return {
    command: 'launch_client',
    client_profile: {
      id: profile.id,
      name: profile.name,
      client_type: profile.client_type,
      local_path_required: true,
      executable_path_source: 'companion_local_settings',
      launch_args_template: decrypt(profile.launch_args_encrypted) || ''
    },
    account: account ? {
      id: account.id,
      label: account.display_name || account.legacy_login || account.username,
      account_type: account.account_type,
      status: account.status
    } : null,
    proxy: proxy ? {
      id: proxy.id,
      name: proxy.name,
      proxy_type: proxy.proxy_type,
      endpoint: `${maskEndpoint(proxy.host)}:${proxy.port}`,
      status: proxy.status
    } : null,
    safety: {
      visible_user_triggered_launch: true,
      no_gameplay_automation: true,
      no_injection: true,
      no_anti_detection_flags: true,
      no_security_bypass: true
    }
  };
}

function normalizeClientStatusPayload(body) {
  const source = Array.isArray(body.instances) ? body.instances : Array.isArray(body.windows) ? body.windows : [body];
  return source.slice(0, 50).map(item => normalizeClientInstance(item));
}

function normalizeClientInstance(item) {
  const running = item.running !== false;
  const clientState = deriveClientState(item, running);
  const status = statusForClientState(clientState, item.status, running);
  const wealthReport = normalizeWealthReport(item);
  return {
    id: item.client_instance_id || item.instance_id || item.id || null,
    client_profile_id: item.client_profile_id || item.profile_id || null,
    account_id: item.account_id || null,
    proxy_id: item.proxy_id || null,
    suggested_account_id: item.suggested_account_id || null,
    instance_name: escapeText(item.instance_name || item.name),
    process_name: escapeText(item.process_name || item.processName),
    process_id: numberOrNull(item.process_id || item.processId || item.pid),
    window_title: escapeText(item.window_title || item.windowTitle),
    status,
    client_state: clientState,
    current_activity: escapeText(item.current_activity || item.activity) || activityForClientState(clientState),
    error_message: escapeText(item.error_message || item.error),
    detected_at: safeDate(item.detected_at || item.detectedAt),
    last_seen_at: safeDate(item.last_seen_at || item.lastSeenAt),
    match_confidence: escapeText(item.match_confidence || item.matchConfidence),
    match_reason: escapeText(item.match_reason || item.matchReason),
    match_hint: escapeText(item.match_hint || item.matched_account_hint || item.account_hint || item.client_label),
    reported_display_name: escapeText(item.reported_display_name || item.display_name || item.displayName),
    ...wealthReport,
    metadata: safeMetadata(item.metadata || {})
  };
}

function deriveClientState(item, running = true) {
  const raw = String(item.client_state || item.game_state || item.state || item.current_state || '').toLowerCase().replace(/[\s-]+/g, '_');
  const status = String(item.status || '').toLowerCase();
  const title = String(item.window_title || item.windowTitle || '').toLowerCase();
  const activity = String(item.current_activity || item.activity || '').toLowerCase();
  if (['offline', 'closed', 'stopped', 'last_seen'].includes(raw) || running === false || status === 'stopped') return 'offline';
  if (['error', 'crashed', 'failed'].includes(raw) || status === 'crashed') return 'error';
  if (['active', 'in_game', 'ingame', 'game', 'running_active'].includes(raw)) return 'active';
  if (['idle', 'login', 'login_screen', 'login_window', 'signed_out'].includes(raw)) return 'idle';
  if (/(login|sign in|signed out|authenticator|launcher)/i.test(title) || /(login screen|signed out|waiting for login)/i.test(activity)) return 'idle';
  if (/(in game|logged in|playing|active session)/i.test(activity)) return 'active';
  return 'unknown';
}

function statusForClientState(clientState, rawStatus, running = true) {
  const status = oneOf(rawStatus, clientInstanceStatuses, '');
  if (clientState === 'active') return 'running';
  if (clientState === 'idle' || clientState === 'unknown') return status || 'detected';
  if (clientState === 'offline') return 'stopped';
  if (clientState === 'error') return 'crashed';
  return running ? (status || 'detected') : 'stopped';
}

function activityForClientState(clientState) {
  return {
    active: 'In Game / Active',
    idle: 'Login Screen / Idle',
    offline: 'Offline / Last Seen',
    error: 'Error / Needs Review',
    unknown: 'Detected / Unknown State'
  }[clientState] || 'Detected / Unknown State';
}

function normalizeWealthReport(item) {
  const gpValue = firstReportValue(item, ['gp_amount', 'gpAmount', 'reported_gp_amount', 'reportedGpAmount']);
  const bankValue = firstReportValue(item, ['bank_value', 'bankValue', 'reported_bank_value', 'reportedBankValue']);
  const wealthValue = firstReportValue(item, ['wealth_value', 'wealthValue', 'wealth_amount', 'wealthAmount', 'reported_wealth_value', 'reportedWealthValue']);
  const hasGp = gpValue !== null;
  const hasBank = bankValue !== null;
  const hasWealth = wealthValue !== null;
  const hasAny = hasGp || hasBank || hasWealth;
  const source = hasAny ? oneOf(item.wealth_source || item.wealthSource, wealthSources, 'companion_reported') : 'unknown';
  return {
    reported_gp_amount: hasGp ? integerOrZero(gpValue) : null,
    reported_bank_value: hasBank ? integerOrZero(bankValue) : null,
    reported_wealth_value: hasWealth ? integerOrZero(wealthValue) : null,
    wealth_source: source,
    wealth_updated_at: hasAny ? (safeDate(item.wealth_updated_at || item.wealthUpdatedAt) || new Date().toISOString()) : null
  };
}

function firstReportValue(item, keys) {
  for (const key of keys) {
    if (hasOwn(item, key) && item[key] !== null && item[key] !== undefined && item[key] !== '') return item[key];
  }
  return null;
}

async function upsertClientInstance(device, item) {
  const userId = device.user_id;
  const clientProfileId = item.client_profile_id ? Number(item.client_profile_id) : null;
  const accountId = item.account_id ? Number(item.account_id) : null;
  const proxyId = item.proxy_id ? Number(item.proxy_id) : null;
  const suggestedAccountId = item.suggested_account_id ? Number(item.suggested_account_id) : null;
  if (clientProfileId) await assertClientProfileOwnership(userId, clientProfileId);
  if (accountId) await assertAccountOwnership(userId, accountId);
  if (proxyId) await assertProxyOwnership(userId, proxyId);
  if (suggestedAccountId) await assertAccountOwnership(userId, suggestedAccountId);
  let result;
  if (item.id) {
    result = await db.query(
      `UPDATE client_instances
       SET companion_device_id=$1, client_profile_id=COALESCE($2, client_profile_id), account_id=COALESCE($3, account_id),
           proxy_id=COALESCE($4, proxy_id), instance_name=COALESCE(NULLIF($5, ''), instance_name),
           process_name=COALESCE(NULLIF($6, ''), process_name), process_id=COALESCE($7, process_id),
           window_title=COALESCE(NULLIF($8, ''), window_title), status=$9, current_activity=COALESCE(NULLIF($10, ''), current_activity),
           error_message=NULLIF($11, ''), detected_at=COALESCE($12, detected_at, NOW()),
           suggested_account_id=COALESCE($13, suggested_account_id), match_confidence=COALESCE(NULLIF($14, ''), match_confidence),
           match_reason=COALESCE(NULLIF($15, ''), match_reason), last_seen_at=COALESCE($16, NOW()),
           client_state=$17, reported_display_name=COALESCE(NULLIF($18, ''), reported_display_name),
           reported_gp_amount=COALESCE($19, reported_gp_amount), reported_bank_value=COALESCE($20, reported_bank_value),
           reported_wealth_value=COALESCE($21, reported_wealth_value), wealth_source=CASE WHEN $23 IS NOT NULL THEN $22 ELSE wealth_source END,
           wealth_updated_at=COALESCE($23, wealth_updated_at),
           started_at=CASE WHEN $9 IN ('pending','running','launching','scanning','detected') THEN COALESCE(started_at, NOW()) ELSE started_at END,
           stopped_at=CASE WHEN $9='stopped' THEN NOW() ELSE stopped_at END, updated_at=NOW()
       WHERE id=$24 AND user_id=$25
       RETURNING *`,
      [
        device.id,
        clientProfileId,
        accountId,
        proxyId,
        item.instance_name,
        item.process_name,
        item.process_id,
        item.window_title,
        item.status,
        item.current_activity,
        item.error_message,
        item.detected_at,
        suggestedAccountId,
        item.match_confidence,
        item.match_reason,
        item.last_seen_at,
        item.client_state,
        item.reported_display_name,
        item.reported_gp_amount,
        item.reported_bank_value,
        item.reported_wealth_value,
        item.wealth_source,
        item.wealth_updated_at,
        item.id,
        userId
      ]
    );
  }
  if (!result || !result.rows[0]) {
    result = await db.query(
      `INSERT INTO client_instances (
         user_id, companion_device_id, client_profile_id, account_id, proxy_id, instance_name,
         process_name, process_id, window_title, status, current_activity, last_seen_at,
         started_at, stopped_at, error_message, detected_at, suggested_account_id, match_confidence, match_reason,
         client_state, reported_display_name, reported_gp_amount, reported_bank_value, reported_wealth_value, wealth_source, wealth_updated_at, updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12, NOW()),
               CASE WHEN $10 IN ('pending','running','launching','scanning','detected') THEN NOW() ELSE NULL END,
               CASE WHEN $10='stopped' THEN NOW() ELSE NULL END, NULLIF($13, ''), COALESCE($14, NOW()), $15, NULLIF($16, ''), NULLIF($17, ''),
               $18, NULLIF($19, ''), $20, $21, $22, $23, $24, NOW())
       RETURNING *`,
      [
        userId,
        device.id,
        clientProfileId,
        accountId,
        proxyId,
        item.instance_name || item.window_title || item.process_name || 'Client instance',
        item.process_name,
        item.process_id,
        item.window_title,
        item.status,
        item.current_activity,
        item.last_seen_at,
        item.error_message,
        item.detected_at,
        suggestedAccountId,
        item.match_confidence,
        item.match_reason,
        item.client_state,
        item.reported_display_name,
        item.reported_gp_amount,
        item.reported_bank_value,
        item.reported_wealth_value,
        item.wealth_source,
        item.wealth_updated_at
      ]
    );
  }
  const instance = result.rows[0];
  if (instance.account_id) await applyClientInstanceAccountStatus(userId, instance.account_id, item, instance);
  const statusEvent = instance.client_state === 'offline' ? 'client_stopped' : 'client_detected';
  await insertClientInstanceEvent(userId, instance.id, statusEvent, `Client instance reported ${instance.status}.`, {
    process_name: instance.process_name,
    process_id: instance.process_id,
    window_title: instance.window_title,
    companion_device_id: device.id,
    client_state: instance.client_state,
    suggested_account_id: instance.suggested_account_id,
    match_confidence: instance.match_confidence,
    wealth_source: instance.wealth_source
  });
  await activity.log(userId, statusEvent, 'client_instance', instance.id, `Client instance ${clientStateLabel(instance.client_state)}`, { status: instance.status, client_state: instance.client_state, companion_device_id: device.id });
  return safeClientInstance(instance);
}

async function applyClientInstanceAccountStatus(userId, accountId, item, instance) {
  const wealthReported = item.reported_gp_amount !== null || item.reported_bank_value !== null || item.reported_wealth_value !== null;
  const lastSeen = instance.last_seen_at || item.last_seen_at || new Date();
  if (!wealthReported) {
    await db.query(
      `UPDATE accounts
       SET client_state=$1, client_last_seen_at=$2, updated_at=NOW()
       WHERE id=$3 AND user_id=$4`,
      [instance.client_state || 'unknown', lastSeen, accountId, userId]
    );
    return;
  }
  await db.query(
    `UPDATE accounts
     SET client_state=$1,
         client_last_seen_at=$2,
         gp_amount=COALESCE($3, gp_amount),
         bank_value=COALESCE($4, bank_value),
         wealth_value=COALESCE($5, wealth_value),
         wealth_amount=COALESCE($5, wealth_amount),
         wealth_source=$6,
         wealth_updated_at=COALESCE($7, NOW()),
         updated_at=NOW()
     WHERE id=$8 AND user_id=$9`,
    [
      instance.client_state || 'unknown',
      lastSeen,
      item.reported_gp_amount,
      item.reported_bank_value,
      item.reported_wealth_value,
      oneOf(item.wealth_source, wealthSources, 'companion_reported'),
      item.wealth_updated_at,
      accountId,
      userId
    ]
  );
  await activity.log(userId, 'wealth_reported', 'account', accountId, 'Wealth values updated from allowed client status report', {
    source: oneOf(item.wealth_source, wealthSources, 'companion_reported'),
    client_instance_id: instance.id
  });
}

async function markStaleClientInstancesOffline(userId, staleMinutes = 5) {
  const result = await db.query(
    `UPDATE client_instances
     SET status='stopped',
         client_state='offline',
         current_activity='Offline / Last Seen',
         stopped_at=COALESCE(stopped_at, last_seen_at, NOW()),
         updated_at=NOW()
     WHERE user_id=$1
       AND status IN ('pending','launching','running','scanning','detected')
       AND last_seen_at IS NOT NULL
       AND last_seen_at < NOW() - ($2::int * INTERVAL '1 minute')
     RETURNING id, account_id, last_seen_at`,
    [userId, Math.max(1, Number(staleMinutes || 5))]
  );
  const accountIds = [...new Set(result.rows.map(row => Number(row.account_id)).filter(Boolean))];
  for (const accountId of accountIds) {
    const latest = result.rows.find(row => Number(row.account_id) === accountId);
    await db.query(
      `UPDATE accounts
       SET client_state='offline', client_last_seen_at=COALESCE($1, client_last_seen_at), updated_at=NOW()
       WHERE id=$2 AND user_id=$3`,
      [latest ? latest.last_seen_at : null, accountId, userId]
    );
  }
}

async function insertClientInstanceEvent(userId, clientInstanceId, eventType, message, metadata = {}) {
  await db.query(
    `INSERT INTO client_instance_events (user_id, client_instance_id, event_type, message, safe_metadata_json)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, clientInstanceId, escapeText(eventType), escapeText(message), safeMetadata(metadata)]
  );
}

function safeClientInstance(instance) {
  return {
    id: instance.id,
    client_profile_id: instance.client_profile_id,
    account_id: instance.account_id,
    proxy_id: instance.proxy_id,
    instance_name: instance.instance_name,
    process_name: instance.process_name,
    process_id: instance.process_id,
    window_title: instance.window_title,
    status: instance.status,
    client_state: instance.client_state,
    current_activity: instance.current_activity,
    detected_at: instance.detected_at,
    last_seen_at: instance.last_seen_at,
    started_at: instance.started_at,
    stopped_at: instance.stopped_at,
    suggested_account_id: instance.suggested_account_id,
    match_confidence: instance.match_confidence,
    match_reason: instance.match_reason,
    reported_display_name: instance.reported_display_name,
    reported_gp_amount: instance.reported_gp_amount,
    reported_bank_value: instance.reported_bank_value,
    reported_wealth_value: instance.reported_wealth_value,
    wealth_source: instance.wealth_source,
    wealth_updated_at: instance.wealth_updated_at
  };
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
  if (!result.rows[0]) throw new Error('Local App device not found for this user.');
}

async function loadWorkflow(userId, workflowId) {
  const result = await db.query('SELECT * FROM workflows WHERE id=$1 AND user_id=$2', [workflowId, userId]);
  if (!result.rows[0]) throw new Error('Automation not found.');
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
  if (!result.rows[0]) throw new Error('Job not found.');
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
    custom: 'Custom automation'
  }[type] || 'Custom automation';
}

function workflowTemplateDescription(type) {
  return {
    login_fill: 'Open a login page and fill visible login fields after a user-started run.',
    account_creation_fill: 'Open a signup page and fill selected visible fields, then pause for manual checks.',
    generic_form_fill: 'Fill a generic form from selected account field references.',
    custom: 'User-controlled visible browser automation.'
  }[type] || 'User-controlled visible browser automation.';
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
      { step_type: 'note', label: 'Manual-safe automation note', config: { message: 'Add steps. Keep CAPTCHA, 2FA, email, and phone verification manual.' } }
    ]
  };
  return templates[type] || templates.custom;
}

function parseWorkflowStepsJson(raw) {
  let parsed;
  try { parsed = JSON.parse(raw || '[]'); } catch (error) { throw new Error('Automation steps JSON is invalid.'); }
  if (!Array.isArray(parsed)) throw new Error('Automation steps JSON must be an array.');
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
  if (!result.rows[0]) throw new Error('Local App job not found.');
  return result.rows[0];
}

function safeCompanionJob(job) {
  return {
    id: job.id,
    job_type: job.job_type,
    status: job.status,
    workflow_id: job.workflow_id,
    workflow_run_id: job.workflow_run_id,
    client_profile_id: job.client_profile_id,
    client_instance_id: job.client_instance_id,
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

function statusToClientInstanceStatus(status) {
  if (status === 'completed') return 'running';
  if (status === 'failed') return 'crashed';
  if (status === 'cancelled') return 'stopped';
  if (status === 'queued' || status === 'accepted') return 'launching';
  if (status === 'paused' || status === 'waiting_for_user') return 'running';
  return 'running';
}

function clientStateFromJobStatus(status) {
  if (status === 'failed') return 'error';
  if (status === 'cancelled') return 'offline';
  if (status === 'paused' || status === 'waiting_for_user') return 'idle';
  if (status === 'completed' || status === 'running') return 'active';
  return 'unknown';
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
    email_creation_status: oneOf(body.email_creation_status, workflowStatuses, 'pending'),
    verified: oneOf(body.verified, ['yes', 'no', 'unknown'], 'unknown'),
    character_type: keep(body.character_type),
    gp_amount: integerOrZero(body.gp_amount),
    platinum_amount: integerOrZero(body.platinum_amount),
    wealth_amount: integerOrZero(body.wealth_amount),
    bank_value: optionalInteger(body.bank_value),
    wealth_value: optionalInteger(body.wealth_value || body.wealth_amount),
    wealth_source: oneOf(body.wealth_source, wealthSources, hasManualWealthBody(body) ? 'manual' : 'unknown'),
    wealth_updated_at: hasManualWealthBody(body) ? new Date() : null,
    ban_status: oneOf(body.ban_status, ['none', 'temp', 'perm', 'unknown'], 'none'),
    completed_tutorial: body.completed_tutorial === 'yes',
    total_level: numberOrNull(body.total_level),
    tags: keep(body.tags)
  };
}

function accountParams(account, userId) {
  return [
    userId, account.username, encrypt(account.password), account.legacy_login, encrypt(account.legacy_password), account.account_type,
    encrypt(account.bank_pin), encrypt(account.otp_secret), account.display_name || null, account.category || null, account.country_code || null, account.notes || null,
    encrypt(account.recovery_email), encrypt(account.recovery_email_password), encrypt(account.target_email), encrypt(account.target_email_password), encrypt(account.email_password),
    encrypt(account.jagex_email), encrypt(account.jagex_password), account.jagex_name || null, account.first_name || null, account.last_name || null,
    account.birth_month, account.birth_day, account.birth_year, account.proxy_id, account.assigned_http_proxy_id, account.assigned_socks5_proxy_id,
    account.status, account.credential_status, account.upgrade_status, account.email_creation_status,
    account.verified || 'unknown', account.character_type || null, account.gp_amount || 0, account.platinum_amount || 0,
    account.wealth_amount || 0, account.bank_value, account.wealth_value, account.wealth_source || 'unknown', account.wealth_updated_at,
    account.ban_status || 'none', account.completed_tutorial === true, account.total_level || null, account.tags || null
  ];
}

function accountColumns() {
  return [
    'user_id', 'username', 'password_encrypted', 'legacy_login', 'legacy_password_encrypted', 'account_type',
    'bank_pin_encrypted', 'otp_secret_encrypted', 'display_name', 'category', 'country_code', 'notes',
    'recovery_email_encrypted', 'recovery_email_password_encrypted', 'target_email_encrypted', 'target_email_password_encrypted', 'email_password_encrypted',
    'jagex_email_encrypted', 'jagex_password_encrypted', 'jagex_name', 'first_name', 'last_name',
    'birth_month', 'birth_day', 'birth_year', 'proxy_id', 'assigned_http_proxy_id', 'assigned_socks5_proxy_id',
    'status', 'credential_status', 'upgrade_status', 'email_creation_status',
    'verified', 'character_type', 'gp_amount', 'platinum_amount', 'wealth_amount',
    'bank_value', 'wealth_value', 'wealth_source', 'wealth_updated_at', 'ban_status',
    'completed_tutorial', 'total_level', 'tags'
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
    email_creation_status: 'pending',
    verified: 'unknown',
    character_type: escapeText(body.character_type || body.category),
    gp_amount: 0,
    platinum_amount: 0,
    wealth_amount: 0,
    bank_value: null,
    wealth_value: null,
    wealth_source: 'unknown',
    wealth_updated_at: null,
    ban_status: 'none',
    completed_tutorial: false,
    total_level: null,
    tags: ''
  };
}

async function markDuplicates(userId, rows) {
  const names = [...new Set(rows.filter(row => row.username).map(row => row.username))];
  if (!names.length) return;
  const existing = await db.query('SELECT username, legacy_login FROM accounts WHERE user_id=$1 AND (username = ANY($2) OR legacy_login = ANY($2))', [userId, names]);
  const found = new Set(existing.rows.flatMap(row => [row.username, row.legacy_login]).filter(Boolean));
  rows.forEach(row => { row.duplicate = found.has(row.username); });
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
    character_type: escapeText(source.character_type),
    country_code: escapeText(source.country_code),
    has_proxy: escapeText(source.has_proxy),
    has_otp: escapeText(source.has_otp),
    has_notes: escapeText(source.has_notes),
    completed_tutorial: escapeText(source.completed_tutorial),
    has_active_instance: escapeText(source.has_active_instance),
    verified: escapeText(source.verified),
    authenticator: escapeText(source.authenticator),
    bans: escapeText(source.bans),
    min_total_level: escapeText(source.min_total_level),
    max_total_level: escapeText(source.max_total_level),
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
  if (filters.character_type) {
    params.push(`%${filters.character_type}%`);
    clauses.push(`(character_type ILIKE $${params.length} OR category ILIKE $${params.length})`);
  }
  if (filters.country_code) add('country_code ILIKE ?', filters.country_code.toUpperCase());
  if (filters.has_proxy === 'yes') clauses.push('(assigned_http_proxy_id IS NOT NULL OR proxy_id IS NOT NULL OR assigned_socks5_proxy_id IS NOT NULL)');
  if (filters.has_proxy === 'no') clauses.push('assigned_http_proxy_id IS NULL AND proxy_id IS NULL AND assigned_socks5_proxy_id IS NULL');
  if (filters.has_otp === 'yes') clauses.push('otp_secret_encrypted IS NOT NULL');
  if (filters.has_otp === 'no') clauses.push('otp_secret_encrypted IS NULL');
  if (filters.has_notes === 'yes') clauses.push("(COALESCE(notes, '') <> '' OR private_notes_encrypted IS NOT NULL)");
  if (filters.has_notes === 'no') clauses.push("COALESCE(notes, '') = '' AND private_notes_encrypted IS NULL");
  if (filters.completed_tutorial === 'yes') clauses.push('completed_tutorial IS TRUE');
  if (filters.completed_tutorial === 'no') clauses.push('completed_tutorial IS FALSE');
  if (filters.has_active_instance === 'yes') clauses.push("EXISTS (SELECT 1 FROM client_instances ci WHERE ci.user_id=accounts.user_id AND ci.account_id=accounts.id AND ci.status IN ('pending','launching','running','scanning','detected'))");
  if (filters.has_active_instance === 'no') clauses.push("NOT EXISTS (SELECT 1 FROM client_instances ci WHERE ci.user_id=accounts.user_id AND ci.account_id=accounts.id AND ci.status IN ('pending','launching','running','scanning','detected'))");
  if (['yes', 'no', 'unknown'].includes(filters.verified)) add('verified = ?', filters.verified);
  if (filters.authenticator === 'yes') clauses.push('otp_secret_encrypted IS NOT NULL');
  if (filters.authenticator === 'no') clauses.push('otp_secret_encrypted IS NULL');
  if (filters.bans === 'any') clauses.push("(status IN ('banned_temp','banned_perm') OR ban_status <> 'none')");
  if (filters.bans === 'temp') clauses.push("(status='banned_temp' OR ban_status='temp')");
  if (filters.bans === 'perm') clauses.push("(status='banned_perm' OR ban_status='perm')");
  if (filters.bans === 'none') clauses.push("(status NOT IN ('banned_temp','banned_perm') AND ban_status='none')");
  const minTotalLevel = Number(filters.min_total_level);
  const maxTotalLevel = Number(filters.max_total_level);
  if (Number.isFinite(minTotalLevel) && minTotalLevel >= 0) add('COALESCE(total_level, 0) >= ?', minTotalLevel);
  if (Number.isFinite(maxTotalLevel) && maxTotalLevel >= 0) add('COALESCE(total_level, 0) <= ?', maxTotalLevel);
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

function safeDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function hasOwn(value, key) {
  return value && Object.prototype.hasOwnProperty.call(value, key);
}

function clientStateLabel(state) {
  const normalized = oneOf(state, clientStates, 'unknown');
  const labels = {
    active: 'Active',
    idle: 'Idle',
    offline: 'Offline',
    unknown: 'Unknown',
    error: 'Error'
  };
  return labels[normalized] || labels.unknown;
}

function clientStateClass(state) {
  const normalized = oneOf(state, clientStates, 'unknown');
  if (normalized === 'active') return 'active running';
  if (normalized === 'idle') return 'idle';
  if (normalized === 'offline') return 'offline stopped';
  if (normalized === 'error') return 'error crashed';
  return 'unknown detected';
}

function clientStateFromRow(row, staleMinutes = 5) {
  if (!row) return 'unknown';
  const explicit = oneOf(row.client_state || row.active_instance_client_state, clientStates, 'unknown');
  const status = String(row.status || row.active_instance_status || '').toLowerCase();
  if (explicit === 'offline' || explicit === 'error') return explicit;
  if (status === 'stopped') return 'offline';
  if (['crashed', 'failed'].includes(status)) return 'error';
  const lastSeenRaw = row.last_seen_at || row.active_instance_last_seen_at || row.client_last_seen_at;
  if (lastSeenRaw) {
    const lastSeen = new Date(lastSeenRaw).getTime();
    if (!Number.isNaN(lastSeen) && Date.now() - lastSeen > Math.max(1, staleMinutes) * 60 * 1000) return 'offline';
  }
  return explicit;
}

function formatWealthValue(value, source = 'unknown') {
  const numeric = value === null || value === undefined || value === '' ? null : Number(value);
  if (!Number.isFinite(numeric) || (source === 'unknown' && numeric === 0)) return 'Unknown';
  return Math.floor(Math.max(0, numeric)).toLocaleString();
}

function integerOrZero(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.floor(number);
}

function optionalInteger(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return null;
  return Math.floor(number);
}

function hasManualWealthBody(body) {
  return ['gp_amount', 'bank_value', 'wealth_value', 'wealth_amount'].some(key => hasOwn(body, key) && body[key] !== '');
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
    hasFullAppAccess,
    hasLimitedAccess,
    canExportData,
    isBlockedUser,
    requireNotBlocked,
    restrictLimitedUsers,
    requireFullAccess,
    isAdminUser,
    requireAdmin,
    loadAccount,
    getSettings,
    deriveClientState,
    activityForClientState,
    normalizeClientInstance,
    formatWealthValue,
    canUseBrowserAutomator,
    canUseClientMonitor,
    canUseClientLauncher,
    canUseSnapshots,
    canAddDevice,
    canRunBrowserTask,
    isBrowserTaskJob,
    jobTypeLabel,
    setupStepsForWorkspace,
    automationCompatibilityMatrix
  }
};
