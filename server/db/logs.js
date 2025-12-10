const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.LOGS_DB_PATH || path.join(__dirname, '../../data/logs.db');

// Ensure data directory exists
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL,
    invalidated_at INTEGER,
    invalidated_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    ip TEXT,
    user_agent TEXT,
    duration_ms INTEGER,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  );

  CREATE TABLE IF NOT EXISTS user_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL,
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    target_name TEXT,
    details TEXT,
    ip TEXT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(user_id, invalidated_at);
  CREATE INDEX IF NOT EXISTS idx_access_logs_user ON access_logs(user_id, timestamp);
  CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_user_actions_actor ON user_actions(actor_id, timestamp);
  CREATE INDEX IF NOT EXISTS idx_user_actions_timestamp ON user_actions(timestamp);
`);

// Prepared statements
const stmts = {
  // Sessions
  createSession: db.prepare(`
    INSERT INTO sessions (token, user_id, username, ip, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  findSession: db.prepare(`SELECT * FROM sessions WHERE token = ? AND invalidated_at IS NULL`),
  invalidateSession: db.prepare(`
    UPDATE sessions SET invalidated_at = ?, invalidated_reason = ? WHERE token = ?
  `),
  invalidateUserSessions: db.prepare(`
    UPDATE sessions SET invalidated_at = ?, invalidated_reason = ? 
    WHERE user_id = ? AND invalidated_at IS NULL
  `),
  getUserActiveSessions: db.prepare(`
    SELECT * FROM sessions WHERE user_id = ? AND invalidated_at IS NULL ORDER BY created_at DESC
  `),
  cleanExpiredSessions: db.prepare(`
    DELETE FROM sessions WHERE expires_at < ? OR invalidated_at IS NOT NULL AND invalidated_at < ?
  `),
  
  // Access logs
  logAccess: db.prepare(`
    INSERT INTO access_logs (user_id, username, method, path, status_code, ip, user_agent, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  getAccessLogs: db.prepare(`
    SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT ?
  `),
  getAccessLogsByUser: db.prepare(`
    SELECT * FROM access_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?
  `),
  cleanOldAccessLogs: db.prepare(`DELETE FROM access_logs WHERE timestamp < ?`),
  
  // User actions
  logAction: db.prepare(`
    INSERT INTO user_actions (actor_id, actor_username, action, target_type, target_id, target_name, details, ip)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  getActions: db.prepare(`
    SELECT * FROM user_actions ORDER BY timestamp DESC LIMIT ?
  `),
  getActionsByActor: db.prepare(`
    SELECT * FROM user_actions WHERE actor_id = ? ORDER BY timestamp DESC LIMIT ?
  `),
  getActionsByType: db.prepare(`
    SELECT * FROM user_actions WHERE action = ? ORDER BY timestamp DESC LIMIT ?
  `),
  cleanOldActions: db.prepare(`DELETE FROM user_actions WHERE timestamp < ?`)
};

// Session operations
const sessionOps = {
  create(token, userId, username, ip, userAgent, expiresAt) {
    return stmts.createSession.run(token, userId, username, ip, userAgent, expiresAt);
  },
  
  find(token) {
    return stmts.findSession.get(token);
  },
  
  invalidate(token, reason = 'logout') {
    const now = Math.floor(Date.now() / 1000);
    return stmts.invalidateSession.run(now, reason, token);
  },
  
  invalidateAllForUser(userId, reason = 'new_login') {
    const now = Math.floor(Date.now() / 1000);
    return stmts.invalidateUserSessions.run(now, reason, userId);
  },
  
  getActiveForUser(userId) {
    return stmts.getUserActiveSessions.all(userId);
  },
  
  cleanup(retentionDays = 7) {
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - (retentionDays * 24 * 60 * 60);
    return stmts.cleanExpiredSessions.run(now, cutoff);
  }
};

// Access log operations
const accessOps = {
  log(userId, username, method, path, statusCode, ip, userAgent, durationMs) {
    return stmts.logAccess.run(userId, username, method, path, statusCode, ip, userAgent, durationMs);
  },
  
  getRecent(limit = 100) {
    return stmts.getAccessLogs.all(limit);
  },
  
  getByUser(userId, limit = 100) {
    return stmts.getAccessLogsByUser.all(userId, limit);
  },
  
  cleanup(retentionDays = 30) {
    const cutoff = Math.floor(Date.now() / 1000) - (retentionDays * 24 * 60 * 60);
    return stmts.cleanOldAccessLogs.run(cutoff);
  }
};

// User action operations
const actionOps = {
  log(actorId, actorUsername, action, targetType, targetId, targetName, details, ip) {
    const detailsJson = details ? JSON.stringify(details) : null;
    return stmts.logAction.run(actorId, actorUsername, action, targetType, targetId, targetName, detailsJson, ip);
  },
  
  getRecent(limit = 100) {
    return stmts.getActions.all(limit).map(row => ({
      ...row,
      details: row.details ? JSON.parse(row.details) : null
    }));
  },
  
  getByActor(actorId, limit = 100) {
    return stmts.getActionsByActor.all(actorId, limit).map(row => ({
      ...row,
      details: row.details ? JSON.parse(row.details) : null
    }));
  },
  
  getByType(action, limit = 100) {
    return stmts.getActionsByType.all(action, limit).map(row => ({
      ...row,
      details: row.details ? JSON.parse(row.details) : null
    }));
  },
  
  cleanup(retentionDays = 90) {
    const cutoff = Math.floor(Date.now() / 1000) - (retentionDays * 24 * 60 * 60);
    return stmts.cleanOldActions.run(cutoff);
  }
};

module.exports = {
  db,
  sessionOps,
  accessOps,
  actionOps
};
