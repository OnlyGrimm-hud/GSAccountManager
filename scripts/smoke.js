process.env.DATABASE_URL ||= 'postgres://postgres:postgres@localhost:5432/gs_account_manager';
process.env.ENCRYPTION_KEY ||= 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
process.env.SESSION_SECRET ||= 'smoke-test-session-secret';
process.env.ADMIN_USERNAME ||= 'admin';
process.env.ADMIN_PASSWORD ||= 'admin';

const assert = require('assert');
const { parseAccountImport, parseProxyImport } = require('../src/parsers');
const { currentTotp } = require('../src/otp');
const { generatePassword } = require('../src/generators');

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

console.log('Smoke checks passed');
