const db = require('./db');

async function log(userId, action, entityType, entityId, message, metadata = {}) {
  await db.query(
    `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, message, metadata)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId || null, action, entityType || null, entityId || null, message || null, safeMetadata(metadata)]
  );
}

function safeMetadata(value) {
  if (Array.isArray(value)) return value.map(item => safeMetadata(item));
  if (!value || typeof value !== 'object') return value;
  const clean = {};
  for (const [key, item] of Object.entries(value)) {
    if (/password|secret|token|cookie|session|encrypted|otp/i.test(key)) clean[key] = '[redacted]';
    else clean[key] = safeMetadata(item);
  }
  return clean;
}

module.exports = { log };
