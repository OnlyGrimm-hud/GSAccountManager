const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.nodeEnv === 'production' ? { rejectUnauthorized: false } : false
});

async function migrate() {
  if (!config.autoMigrate) return;
  const schema = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.sql'), 'utf8');
  await pool.query(schema);
  try {
    await pool.query(
      `INSERT INTO activity_logs (action, entity_type, message, metadata)
       VALUES ($1, $2, $3, $4)`,
      [
        'app_started',
        'system',
        `GS Account Manager v${config.appVersion} started`,
        { version: config.appVersion, node_env: config.nodeEnv }
      ]
    );
  } catch (error) {
    console.error(`Startup log skipped: ${error.message}`);
  }
}

async function query(text, params) {
  return pool.query(text, params);
}

async function close() {
  await pool.end();
}

module.exports = { pool, query, migrate, close };
