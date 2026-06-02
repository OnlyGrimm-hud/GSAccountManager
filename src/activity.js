const db = require('./db');

async function log(userId, action, entityType, entityId, message, metadata = {}) {
  await db.query(
    `INSERT INTO activity_logs (user_id, action, entity_type, entity_id, message, metadata)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId || null, action, entityType || null, entityId || null, message || null, metadata]
  );
}

module.exports = { log };
