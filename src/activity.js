const db = require('./db');

async function log(action, entityType, entityId, message, metadata = {}) {
  await db.query(
    `INSERT INTO activity_logs (action, entity_type, entity_id, message, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [action, entityType || null, entityId || null, message || null, metadata]
  );
}

module.exports = { log };
