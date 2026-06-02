process.env.DATABASE_URL ||= 'postgres://postgres:postgres@localhost:5432/gs_account_manager';
process.env.ENCRYPTION_KEY ||= 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
process.env.SESSION_SECRET ||= 'smoke-test-session-secret';
process.env.ADMIN_USERNAME ||= 'admin';
process.env.ADMIN_PASSWORD ||= 'admin';

const assert = require('assert');
const { parseImport } = require('../src/server');
const { currentTotp } = require('../src/otp');

const rows = parseImport([
  'user1:pass1',
  'user2:pass2:OTPSECRET',
  'user3:pass3:1234:JBSWY3DPEHPK3PXP',
  'user4:pass4:1234:JBSWY3DPEHPK3PXP:recovery@example.com:recoverpass'
].join('\n'));

assert.strictEqual(rows.length, 4);
assert.strictEqual(rows[0].valid, true);
assert.strictEqual(rows[2].bank_pin, '1234');
assert.strictEqual(rows[3].recovery_email, 'recovery@example.com');

const otp = currentTotp('JBSWY3DPEHPK3PXP', 0);
assert.match(otp.code, /^\d{6}$/);

console.log('Smoke checks passed');
