process.env.DATABASE_URL ||= 'postgres://postgres:postgres@localhost:5432/gs_account_manager';
process.env.ENCRYPTION_KEY ||= 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
process.env.SESSION_SECRET ||= 'smoke-test-session-secret';
process.env.ADMIN_USERNAME ||= 'admin';
process.env.ADMIN_PASSWORD ||= 'admin';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { parseAccountImport, parseProxyImport } = require('../src/parsers');
const { currentTotp } = require('../src/otp');
const { generatePassword } = require('../src/generators');
const { parseHiscoreLite, estimateCombatLevel, fetchPublicStats } = require('../src/osrs-stats');

const discordAuthSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'discord-auth.js'), 'utf8');
assert(!discordAuthSource.includes('unowned_logs`,\n      [user.id]'));
const browserAutomatorSource = fs.readFileSync(path.join(__dirname, '..', 'companion', 'src', 'browser-automator.js'), 'utf8');
assert(browserAutomatorSource.includes('runBrowserAutomationJob'));
assert(browserAutomatorSource.includes('manualCheckPatterns'));
assert(browserAutomatorSource.includes('click_skipped_for_manual_submit'));
assert(browserAutomatorSource.includes('bypass CAPTCHA, 2FA, email verification, phone verification, or security checks'));
assert(browserAutomatorSource.includes('configuredValueRefs'));
assert(browserAutomatorSource.includes('optional_fill_skipped'));
assert(browserAutomatorSource.includes('proxyLaunchOptions'));
assert(browserAutomatorSource.includes('browser_proxy_enabled'));
assert(browserAutomatorSource.includes('normalizeWebsiteUrl'));
assert(browserAutomatorSource.includes('www.gsaccountmanager.com'));
const companionRendererSource = fs.readFileSync(path.join(__dirname, '..', 'companion', 'src', 'renderer', 'renderer.js'), 'utf8');
assert(companionRendererSource.includes('safeJobDetails'));
assert(companionRendererSource.includes('safeClientDetails'));
assert(companionRendererSource.includes('normalizeWebsiteUrl'));
assert(!companionRendererSource.includes('JSON.stringify(currentJob'));

let requireAuth;
let db;
let app;
let testInternals;
let fullServerChecksAvailable = true;

try {
  ({ requireAuth } = require('../src/security'));
  db = require('../src/db');
  ({ app, testInternals } = require('../src/server'));
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
  fullServerChecksAvailable = false;
}

const rows = parseAccountImport([
  'user1:pass1',
  'user2:pass2:OTPSECRET',
  'user3:pass3:1234:JBSWY3DPEHPK3PXP',
  'user4:pass4:JBSWY3DPEHPK3PXP:review note',
  'user5:pass5:otp:extra:note',
  'badrow'
].join('\n'));

assert.strictEqual(rows.length, 6);
assert.strictEqual(rows[0].valid, true);
assert.strictEqual(rows[2].bank_pin, '1234');
assert.strictEqual(rows[3].notes, 'review note');
assert.strictEqual(rows[4].extra_fields.length, 2);
assert.strictEqual(rows[5].valid, false);

const jagexRows = parseAccountImport('email@example.com:pass:recovery@example.com:recoverypass', ':', { account_type: 'jagex' });
assert.strictEqual(jagexRows[0].recovery_email, 'recovery@example.com');
assert.strictEqual(jagexRows[0].recovery_email_password, 'recoverypass');

const targetEmailRows = parseAccountImport('legacy:pass:target@example.com:emailpass:First:Last:1/2/1999', ':', { account_type: 'legacy' });
assert.strictEqual(targetEmailRows[0].target_email, 'target@example.com');
assert.strictEqual(targetEmailRows[0].first_name, 'First');

const jagexLegacyRows = parseAccountImport('jagex@example.com:jpass:legacylogin:lpass:JBSWY3DPEHPK3PXP', ':', { account_type: 'jagex', import_format: 'jagex_legacy' });
assert.strictEqual(jagexLegacyRows[0].legacy_login, 'legacylogin');
assert.strictEqual(jagexLegacyRows[0].legacy_password, 'lpass');

const proxies = parseProxyImport([
  '127.0.0.1:8080',
  '127.0.0.2:8080:user:pass',
  'http://user:pass@127.0.0.3:8080'
].join('\n'));

assert.strictEqual(proxies.length, 3);
assert.strictEqual(proxies.every(proxy => proxy.valid), true);
assert.strictEqual(proxies[2].username, 'user');

const otp = currentTotp('JBSWY3DPEHPK3PXP', 0);
assert.match(otp.code, /^\d{6}$/);

const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
assert.strictEqual(encryptionKey.length, 32);
assert.strictEqual(generatePassword(9).length, 9);

const hiscoreFixture = [
  '1,2277,4600000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000',
  '1,99,200000000'
].join('\n');
const parsedStats = parseHiscoreLite(hiscoreFixture);
assert.strictEqual(parsedStats.total_level, 2277);
assert.strictEqual(parsedStats.attack, 99);
assert.strictEqual(parsedStats.combat_level, estimateCombatLevel(parsedStats));

function fakeResponse() {
  return {
    redirected: null,
    rendered: null,
    statusCode: 200,
    redirect(path) {
      this.redirected = path;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    render(view, data) {
      this.rendered = { view, data };
      return this;
    }
  };
}

function invokeMiddleware(fn, req) {
  const res = fakeResponse();
  let nextCalled = false;
  fn(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

function routeExists(method, path) {
  return app._router.stack.some(layer => layer.route && layer.route.path === path && layer.route.methods[method]);
}

async function healthCheckWorks() {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/healthz`);
    const body = await response.text();
    assert([200, 503].includes(response.status));
    assert(response.status === 200 ? body === 'OK' : body.includes('database'));
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function main() {
  const successfulStats = await fetchPublicStats('Example', async () => ({
    ok: true,
    status: 200,
    text: async () => hiscoreFixture
  }));
  assert.strictEqual(successfulStats.status, 'ok');
  assert.strictEqual(successfulStats.display_name, 'Example');
  assert.strictEqual(successfulStats.total_level, 2277);

  const missingStats = await fetchPublicStats('Missing Name', async () => ({
    ok: false,
    status: 404,
    text: async () => ''
  }));
  assert.strictEqual(missingStats.status, 'not_found');

  if (!fullServerChecksAvailable) {
    const serverSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
    assert(serverSource.includes("app.get('/healthz'"));
    assert(serverSource.includes("app.get('/login'"));
    assert(serverSource.includes("app.get('/auth/discord'"));
    assert(serverSource.includes("app.get('/auth/discord/callback'"));
    assert(serverSource.includes("app.get('/locked'"));
    assert(serverSource.includes("app.get('/admin'"));
    assert(serverSource.includes("app.get('/admin/users'"));
    assert(serverSource.includes("app.get('/admin/logs'"));
    assert(serverSource.includes("app.get('/admin/system'"));
    assert(serverSource.includes("app.get('/admin/subscriptions'"));
    assert(serverSource.includes("app.get('/admin/downloads'"));
    assert(serverSource.includes("app.get('/setup'"));
    assert(serverSource.includes("app.get('/setup-guide'"));
    assert(serverSource.includes("app.get('/compatibility'"));
    assert(serverSource.includes("app.get('/accounts'"));
    assert(serverSource.includes("app.get('/proxies'"));
    assert(serverSource.includes("app.get('/clients'"));
    assert(serverSource.includes("app.get('/instances'"));
    assert(serverSource.includes("app.get('/instances/:id'"));
    assert(serverSource.includes("app.post('/instances/:id/match'"));
    assert(serverSource.includes("app.post('/instances/:id/unmatch'"));
    assert(serverSource.includes("app.post('/instances/:id/refresh-stats'"));
    assert(serverSource.includes("app.get('/local-jobs'"));
    assert(serverSource.includes("app.get('/settings'"));
    assert(serverSource.includes("app.get('/logs'"));
    assert(serverSource.includes("app.get('/downloads'"));
    assert(serverSource.includes("app.get('/companion'"));
    assert(serverSource.includes("app.get('/workflows'"));
    assert(serverSource.includes("app.get('/accounts/:id/email-upgrade'"));
    assert(serverSource.includes("app.post('/accounts/:id/email-upgrade'"));
    assert(serverSource.includes("app.get('/api/companion/proxies/:id/credentials'"));
    assert(serverSource.includes('companionHasActiveJobDataAccess'));
    assert(serverSource.includes('Proxy credential access requires an active GS Agent job'));
    assert(serverSource.includes('email_upgrade'));
    assert(serverSource.includes('Email upgrade / change email'));
    assert(serverSource.includes('emailUpgradeRunSteps'));
    assert(serverSource.includes('account.otp_code'));
    assert(serverSource.includes("app.post('/accounts/import'"));
    assert(serverSource.includes("app.post('/accounts/export'"));
    assert(serverSource.includes("app.post('/accounts/:id/refresh-stats'"));
    assert(serverSource.includes("app.post('/accounts/bulk'"));
    assert(serverSource.includes("app.post('/proxies/import'"));
    assert(serverSource.includes("app.post('/proxies/export'"));
    assert(serverSource.includes("app.post('/proxies/bulk-status'"));
    assert(serverSource.includes("app.post('/clients/profiles/:id/delete'"));
    assert(serverSource.includes("app.post('/local-jobs/:id/cancel'"));
    assert(serverSource.includes("app.post('/api/companion/pair/complete'"));
    assert(serverSource.includes('device_install_id_hash'));
    assert(serverSource.includes('hashDeviceInstallId'));
    assert(serverSource.includes('reused_existing_device'));
    assert(serverSource.includes("app.post('/api/companion/heartbeat'"));
    assert(serverSource.includes("app.post('/api/companion/clients/status'"));
    assert(serverSource.includes("app.post('/api/companion/clients/instance'"));
    assert(serverSource.includes("app.post('/api/companion/snapshots'"));
    assert(serverSource.includes("app.get('/api/companion/jobs/next'"));
    assert(serverSource.includes("app.get('/api/companion/jobs/poll'"));
    assert(serverSource.includes("app.post('/api/companion/jobs/:id/status'"));
    assert(serverSource.includes('client_profiles'));
    assert(serverSource.includes('client_instances'));
    assert(serverSource.includes('account_stats'));
    assert(serverSource.includes('subscription_tiers'));
    assert(serverSource.includes('download_items'));
    assert(serverSource.includes('payment_settings'));
    assert(serverSource.includes('browser_task_usage'));
    assert(serverSource.includes('canRunBrowserTask'));
    assert(serverSource.includes('setupStepsForWorkspace'));
    assert(serverSource.includes('automationCompatibilityMatrix'));
    assert(serverSource.includes('enable_local_client_detection'));
    assert(serverSource.includes('restrictLimitedUsers'));
    assert(serverSource.includes('requireNotBlocked'));
    assert(serverSource.includes('requireAdmin'));
    assert(serverSource.includes('a.user_id=$2'));
    assert(serverSource.includes('WHERE id=$1 AND user_id=$2'));
    console.log('Dependency-backed Express checks skipped because npm install has not been run locally.');
    console.log('Smoke checks passed');
    return;
  }

  assert(routeExists('get', '/healthz'));
  assert(routeExists('get', '/login'));
  assert(routeExists('get', '/auth/discord'));
  assert(routeExists('get', '/auth/discord/callback'));
  assert(routeExists('get', '/locked'));
  assert(routeExists('get', '/'));
  assert(routeExists('get', '/accounts'));
  assert(routeExists('get', '/proxies'));
  assert(routeExists('get', '/settings'));
  assert(routeExists('get', '/logs'));
  assert(routeExists('get', '/downloads'));
  assert(routeExists('get', '/setup'));
  assert(routeExists('get', '/setup-guide'));
  assert(routeExists('get', '/compatibility'));
  assert(routeExists('get', '/companion'));
  assert(routeExists('get', '/clients'));
  assert(routeExists('get', '/instances'));
  assert(routeExists('get', '/instances/:id'));
  assert(routeExists('post', '/instances/:id/match'));
  assert(routeExists('post', '/instances/:id/unmatch'));
  assert(routeExists('post', '/instances/:id/refresh-stats'));
  assert(routeExists('get', '/local-jobs'));
  assert(routeExists('get', '/workflows'));
  assert(routeExists('get', '/admin'));
  assert(routeExists('get', '/admin/users'));
  assert(routeExists('get', '/admin/logs'));
  assert(routeExists('get', '/admin/system'));
  assert(routeExists('get', '/admin/subscriptions'));
  assert(routeExists('get', '/admin/downloads'));
  assert(routeExists('post', '/admin/downloads'));
  assert(routeExists('post', '/admin/downloads/:id'));
  assert(routeExists('post', '/admin/subscriptions/users/:id'));
  assert(routeExists('post', '/admin/subscriptions/tiers/:id'));
  assert(routeExists('post', '/admin/subscriptions/payment-settings/:id'));
  assert(routeExists('post', '/accounts/import'));
  assert(routeExists('post', '/accounts/export'));
  assert(routeExists('get', '/accounts/:id/email-upgrade'));
  assert(routeExists('post', '/accounts/:id/email-upgrade'));
  assert(routeExists('post', '/accounts/:id/refresh-stats'));
  assert(routeExists('post', '/accounts/bulk'));
  assert(routeExists('post', '/proxies/import'));
  assert(routeExists('post', '/proxies/export'));
  assert(routeExists('post', '/proxies/bulk-status'));
  assert(routeExists('post', '/clients/profiles/:id/delete'));
  assert(routeExists('post', '/local-jobs/:id/cancel'));
  assert(routeExists('post', '/api/companion/pair/complete'));
  assert(routeExists('post', '/api/companion/heartbeat'));
  assert(routeExists('post', '/api/companion/clients/status'));
  assert(routeExists('post', '/api/companion/clients/instance'));
  assert(routeExists('post', '/api/companion/snapshots'));
  assert(routeExists('get', '/api/companion/proxies/:id/credentials'));
  assert(routeExists('get', '/api/companion/jobs/next'));
  assert(routeExists('get', '/api/companion/jobs/poll'));
  assert(routeExists('post', '/api/companion/jobs/:id/status'));

  assert.strictEqual(testInternals.deriveClientState({ window_title: 'RuneLite Login Screen' }, true), 'idle');
  assert.strictEqual(testInternals.deriveClientState({ client_state: 'in_game' }, true), 'active');
  assert.strictEqual(testInternals.deriveClientState({ process_name: 'RuneLite', window_title: 'RuneLite' }, true), 'unknown');
  assert.strictEqual(testInternals.deriveClientState({ process_name: 'RuneLite', running: false }, false), 'offline');
  assert.strictEqual(testInternals.normalizeClientInstance({ process_name: 'RuneLite', window_title: 'RuneLite' }).current_activity, 'Detected / Unknown State');
  const reportedWealth = testInternals.normalizeClientInstance({ client_state: 'in_game', gp_amount: 100, bank_value: 200, wealth_value: 300, wealth_source: 'client_reported' });
  assert.strictEqual(reportedWealth.client_state, 'active');
  assert.strictEqual(reportedWealth.reported_gp_amount, 100);
  assert.strictEqual(reportedWealth.reported_bank_value, 200);
  assert.strictEqual(reportedWealth.reported_wealth_value, 300);
  assert.strictEqual(reportedWealth.wealth_source, 'client_reported');
  assert.strictEqual(testInternals.formatWealthValue(null, 'unknown'), 'Unknown');
  assert.strictEqual(testInternals.formatWealthValue(123456, 'companion_reported'), '123,456');
  const starterTier = {
    active: true,
    max_devices: 1,
    daily_successful_browser_task_limit: 50,
    snapshots_enabled: false,
    client_launcher_enabled: false,
    browser_automator_enabled: true
  };
  const standardTier = { ...starterTier, max_devices: 2, snapshots_enabled: true, client_launcher_enabled: true, daily_successful_browser_task_limit: 200 };
  const activeUser = { role: 'user', subscription_status: 'active' };
  const inactiveUser = { role: 'user', subscription_status: 'inactive' };
  const adminUser = { role: 'admin', subscription_status: 'inactive' };
  assert.strictEqual(testInternals.canUseBrowserAutomator(activeUser, starterTier), true);
  assert.strictEqual(testInternals.canUseClientMonitor(activeUser, starterTier), true);
  assert.strictEqual(testInternals.canUseClientLauncher(activeUser, starterTier), false);
  assert.strictEqual(testInternals.canUseClientLauncher(activeUser, standardTier), true);
  assert.strictEqual(testInternals.canUseSnapshots(activeUser, starterTier), false);
  assert.strictEqual(testInternals.canUseSnapshots(activeUser, standardTier), true);
  assert.strictEqual(testInternals.canAddDevice(activeUser, starterTier, 0), true);
  assert.strictEqual(testInternals.canAddDevice(activeUser, starterTier, 1), false);
  assert.strictEqual(testInternals.canRunBrowserTask(activeUser, starterTier, { successful_count: 49 }), true);
  assert.strictEqual(testInternals.canRunBrowserTask(activeUser, starterTier, { successful_count: 50 }), false);
  assert.strictEqual(testInternals.canRunBrowserTask(inactiveUser, starterTier, { successful_count: 0 }), false);
  assert.strictEqual(testInternals.canAddDevice(adminUser, starterTier, 99), true);
  assert.strictEqual(testInternals.canRunBrowserTask(adminUser, starterTier, { successful_count: 9999 }), true);
  assert.strictEqual(testInternals.isBrowserTaskJob('workflow_run'), true);
  assert.strictEqual(testInternals.isBrowserTaskJob('launch_client'), false);
  assert.strictEqual(testInternals.jobTypeLabel('workflow_run'), 'Browser Automator');
  assert.strictEqual(testInternals.workflowTemplateName('email_upgrade'), 'Email upgrade / change email');
  const emailUpgradeSteps = testInternals.workflowTemplateSteps('email_upgrade');
  assert(emailUpgradeSteps.some(step => step.step_type === 'fill_field' && Array.isArray(step.config.value_refs)));
  assert(emailUpgradeSteps.some(step => step.config.value_ref === 'account.otp_code' && step.config.optional === true));
  assert(emailUpgradeSteps.some(step => step.step_type === 'pause_for_user' && /email verification/i.test(step.config.message)));
  const emailUpgradeWithoutOtp = testInternals.emailUpgradeRunSteps({ includeOtp: false });
  assert(!emailUpgradeWithoutOtp.some(step => step.config.value_ref === 'account.otp_code'));
  assert.deepStrictEqual(
    testInternals.accountValueRefsFromConfig({ value_refs: ['account.target_email', 'account.jagex_email'], value_ref: 'account.login_email' }),
    ['account.target_email', 'account.jagex_email', 'account.login_email']
  );
  assert.strictEqual(testInternals.readableAccountRef('account.target_email'), 'target email');
  assert.throws(() => testInternals.accountValueRefsFromConfig({ value_ref: 'profile.secret' }), /Unsupported workflow value reference/);
  assert(testInternals.automationCompatibilityMatrix().some(item => item.name === 'GS Agent'));
  const setupSteps = testInternals.setupStepsForWorkspace({ accounts: 1, devices: 1, connected_devices: 1, launch_profiles: 0 }, { connected: true }, { gates: { browserAutomator: true } });
  assert(setupSteps.some(step => step.title === 'Build automation jobs'));

  const loginLayer = app._router.stack.find(layer => layer.route && layer.route.path === '/login');
  const loginRes = fakeResponse();
  loginLayer.route.stack[0].handle({ currentUserId: null }, loginRes);
  assert.strictEqual(loginRes.rendered.view, 'login');

  const protectedCheck = invokeMiddleware(requireAuth, { session: {} });
  assert.strictEqual(protectedCheck.res.redirected, '/login');

  const inactiveHome = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'GET',
    path: '/',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveHome.res.redirected, '/locked');

  const inactiveExport = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'POST',
    path: '/accounts/export',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveExport.res.redirected, '/locked');

  const inactiveImport = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'POST',
    path: '/accounts/import',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveImport.res.redirected, '/locked');

  const inactiveSettings = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'GET',
    path: '/settings',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveSettings.res.redirected, '/locked');

  const inactiveClients = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'GET',
    path: '/clients',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveClients.res.redirected, '/locked');

  const inactiveFullAccess = invokeMiddleware(testInternals.requireFullAccess, {
    method: 'GET',
    path: '/workflows',
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveFullAccess.res.redirected, '/locked');

  const bannedCheck = invokeMiddleware(testInternals.requireNotBlocked, {
    currentUserRecord: { role: 'user', subscription_status: 'banned' }
  });
  assert.strictEqual(bannedCheck.res.redirected, '/locked');

  const activeCheck = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'GET',
    path: '/settings',
    currentUserRecord: { role: 'user', subscription_status: 'active' }
  });
  assert.strictEqual(activeCheck.nextCalled, true);

  const trialCheck = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'POST',
    path: '/accounts/import',
    currentUserRecord: { role: 'user', subscription_status: 'trial' }
  });
  assert.strictEqual(trialCheck.nextCalled, true);

  const adminBypass = invokeMiddleware(testInternals.restrictLimitedUsers, {
    method: 'GET',
    path: '/settings',
    currentUserRecord: { role: 'admin', subscription_status: 'banned' }
  });
  assert.strictEqual(adminBypass.nextCalled, true);

  const adminOnlyBlocked = invokeMiddleware(testInternals.requireAdmin, {
    currentUserRecord: { role: 'user', subscription_status: 'active' }
  });
  assert.strictEqual(adminOnlyBlocked.res.statusCode, 403);
  assert.strictEqual(adminOnlyBlocked.res.rendered.view, 'error');

  const adminOnlyAllowed = invokeMiddleware(testInternals.requireAdmin, {
    currentUserRecord: { role: 'admin', subscription_status: 'inactive' }
  });
  assert.strictEqual(adminOnlyAllowed.nextCalled, true);

  const originalQuery = db.query;
  let captured;
  db.query = async (text, params) => {
    captured = { text, params };
    return { rows: [] };
  };
  await assert.rejects(() => testInternals.loadAccount(42, 99), /Account not found/);
  assert(captured.text.includes('a.user_id=$2'));
  assert.deepStrictEqual(captured.params, [99, 42]);
  db.query = originalQuery;

  await healthCheckWorks();
  await db.close();
  console.log('Smoke checks passed');
}

main().catch(async error => {
  try { if (db) await db.close(); } catch (_) {}
  console.error(error);
  process.exit(1);
});
