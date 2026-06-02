const crypto = require('crypto');

function csrf(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.body && req.body._csrf === req.session.csrfToken) return next();
  return res.status(403).render('error', { title: 'Security check failed', message: 'The form security token was missing or expired.' });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated && req.session.userId) return next();
  return res.redirect('/login');
}

function escapeText(value) {
  return String(value || '').trim();
}

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function verifyAdminPassword(candidate, config) {
  if (config.adminPasswordHash) {
    const [scheme, salt, key] = config.adminPasswordHash.split(':');
    if (scheme === 'scrypt' && salt && key) {
      const derived = crypto.scryptSync(String(candidate || ''), salt, Buffer.from(key, 'hex').length).toString('hex');
      return safeEqual(derived, key);
    }
  }
  return safeEqual(candidate, config.adminPassword);
}

module.exports = { csrf, requireAuth, escapeText, oneOf, safeEqual, verifyAdminPassword };
