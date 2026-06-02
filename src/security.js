const crypto = require('crypto');

function csrf(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.body && req.body._csrf === req.session.csrfToken) return next();
  return res.status(403).render('error', { title: 'Security check failed', message: 'The form security token was missing or expired.' });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  return res.redirect('/login');
}

function escapeText(value) {
  return String(value || '').trim();
}

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

module.exports = { csrf, requireAuth, escapeText, oneOf };
