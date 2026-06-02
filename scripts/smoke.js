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
  'badrow'
].join('\n'));

assert.strictEqual(rows.length, 5);
assert.strictEqual(rows[0].valid, true);
assert.strictEqual(rows[2].bank_pin, '1234');
assert.strictEqual(rows[3].notes, 'review note');
assert.strictEqual(rows[4].valid, false);

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
  if (!fullServerChecksAvailable) {
    const serverSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
    assert(serverSource.includes("app.get('/healthz'"));
    assert(serverSource.includes("app.get('/login'"));
    assert(serverSource.includes("app.get('/admin/users'"));
    assert(serverSource.includes("app.get('/downloads'"));
    assert(serverSource.includes("app.post('/api/companion/pair/complete'"));
    assert(serverSource.includes("app.post('/api/companion/heartbeat'"));
    assert(serverSource.includes('requireActiveSubscription'));
    assert(serverSource.includes('requireAdmin'));
    assert(serverSource.includes('a.user_id=$2'));
    assert(serverSource.includes('WHERE id=$1 AND user_id=$2'));
    console.log('Dependency-backed Express checks skipped because npm install has not been run locally.');
    console.log('Smoke checks passed');
    return;
  }

  assert(routeExists('get', '/login'));
  assert(routeExists('get', '/auth/discord'));
  assert(routeExists('get', '/auth/discord/callback'));
  assert(routeExists('get', '/downloads'));
  assert(routeExists('get', '/admin/users'));
  assert(routeExists('post', '/api/companion/pair/complete'));
  assert(routeExists('post', '/api/companion/heartbeat'));

  const loginLayer = app._router.stack.find(layer => layer.route && layer.route.path === '/login');
  const loginRes = fakeResponse();
  loginLayer.route.stack[0].handle({ currentUserId: null }, loginRes);
  assert.strictEqual(loginRes.rendered.view, 'login');

  const protectedCheck = invokeMiddleware(requireAuth, { session: {} });
  assert.strictEqual(protectedCheck.res.redirected, '/login');

  const inactiveCheck = invokeMiddleware(testInternals.requireActiveSubscription, {
    currentUserRecord: { role: 'user', subscription_status: 'inactive' }
  });
  assert.strictEqual(inactiveCheck.res.redirected, '/locked');

  const bannedCheck = invokeMiddleware(testInternals.requireActiveSubscription, {
    currentUserRecord: { role: 'user', subscription_status: 'banned' }
  });
  assert.strictEqual(bannedCheck.res.redirected, '/locked');

  const activeCheck = invokeMiddleware(testInternals.requireActiveSubscription, {
    currentUserRecord: { role: 'user', subscription_status: 'active' }
  });
  assert.strictEqual(activeCheck.nextCalled, true);

  const trialCheck = invokeMiddleware(testInternals.requireActiveSubscription, {
    currentUserRecord: { role: 'user', subscription_status: 'trial' }
  });
  assert.strictEqual(trialCheck.nextCalled, true);

  const adminBypass = invokeMiddleware(testInternals.requireActiveSubscription, {
    currentUserRecord: { role: 'admin', subscription_status: 'banned' }
  });
  assert.strictEqual(adminBypass.nextCalled, true);

  const adminOnlyBlocked = invokeMiddleware(testInternals.requireAdmin, {
    currentUserRecord: { role: 'user', subscription_status: 'active' }
  });
  assert.strictEqual(adminOnlyBlocked.statusCode, 403);
  assert.strictEqual(adminOnlyBlocked.rendered.view, 'error');

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
