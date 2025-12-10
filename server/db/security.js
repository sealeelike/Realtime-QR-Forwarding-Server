const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.SECURITY_DB_PATH || path.join(__dirname, '../../data/security.db');

// Ensure data directory exists
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    banned_by TEXT
  );

  CREATE TABLE IF NOT EXISTS banned_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    reason TEXT,
    banned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    banned_by TEXT,
    unbanned_at INTEGER,
    unbanned_by TEXT
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,
    failure_reason TEXT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  );

  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor TEXT,
    actor_id INTEGER,
    target TEXT,
    target_id INTEGER,
    ip TEXT,
    details TEXT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_banned_users_user_id ON banned_users(user_id);
  CREATE INDEX IF NOT EXISTS idx_banned_users_active ON banned_users(user_id, unbanned_at);
  CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id, timestamp);
  CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, timestamp);
  CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type, timestamp);
  CREATE INDEX IF NOT EXISTS idx_security_events_actor ON security_events(actor_id, timestamp);
`);

// Prepared statements
const stmts = {
  // IP bans
  banIP: db.prepare(`INSERT OR REPLACE INTO banned_ips (ip, reason, banned_by) VALUES (?, ?, ?)`),
  unbanIP: db.prepare(`DELETE FROM banned_ips WHERE ip = ?`),
  isIPBanned: db.prepare(`SELECT * FROM banned_ips WHERE ip = ?`),
  listBannedIPs: db.prepare(`SELECT * FROM banned_ips ORDER BY banned_at DESC`),
  
  // User bans
  banUser: db.prepare(`
    INSERT INTO banned_users (user_id, username, reason, banned_by) VALUES (?, ?, ?, ?)
  `),
  unbanUser: db.prepare(`
    UPDATE banned_users SET unbanned_at = ?, unbanned_by = ? 
    WHERE user_id = ? AND unbanned_at IS NULL
  `),
  isUserBanned: db.prepare(`
    SELECT * FROM banned_users WHERE user_id = ? AND unbanned_at IS NULL
  `),
  getUserBanHistory: db.prepare(`
    SELECT * FROM banned_users WHERE user_id = ? ORDER BY banned_at DESC
  `),
  listBannedUsers: db.prepare(`
    SELECT * FROM banned_users WHERE unbanned_at IS NULL ORDER BY banned_at DESC
  `),
  
  // Login attempts
  recordLoginAttempt: db.prepare(`
    INSERT INTO login_attempts (user_id, username, ip, success, failure_reason) VALUES (?, ?, ?, ?, ?)
  `),
  getRecentFailures: db.prepare(`
    SELECT COUNT(*) as count FROM login_attempts 
    WHERE user_id = ? AND success = 0 AND timestamp > ?
  `),
  getRecentIPFailures: db.prepare(`
    SELECT COUNT(*) as count FROM login_attempts 
    WHERE ip = ? AND success = 0 AND timestamp > ?
  `),
  clearUserFailures: db.prepare(`
    UPDATE login_attempts SET success = -1 WHERE user_id = ? AND success = 0
  `),
  
  // Security events
  logEvent: db.prepare(`
    INSERT INTO security_events (event_type, actor, actor_id, target, target_id, ip, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `),
  getEventsByType: db.prepare(`
    SELECT * FROM security_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?
  `),
  getRecentEvents: db.prepare(`
    SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?
  `)
};

// IP ban operations
const ipOps = {
  ban(ip, reason, bannedBy) {
    return stmts.banIP.run(ip, reason, bannedBy);
  },
  
  unban(ip) {
    return stmts.unbanIP.run(ip);
  },
  
  isBanned(ip) {
    return stmts.isIPBanned.get(ip);
  },
  
  listAll() {
    return stmts.listBannedIPs.all();
  }
};

// User ban operations
const userBanOps = {
  ban(userId, username, reason, bannedBy) {
    return stmts.banUser.run(userId, username, reason, bannedBy);
  },
  
  unban(userId, unbannedBy) {
    const now = Math.floor(Date.now() / 1000);
    return stmts.unbanUser.run(now, unbannedBy, userId);
  },
  
  isBanned(userId) {
    return stmts.isUserBanned.get(userId);
  },
  
  getHistory(userId) {
    return stmts.getUserBanHistory.all(userId);
  },
  
  listBanned() {
    return stmts.listBannedUsers.all();
  }
};

// Login attempt operations
const loginOps = {
  record(userId, username, ip, success, failureReason = null) {
    return stmts.recordLoginAttempt.run(userId, username, ip, success ? 1 : 0, failureReason);
  },
  
  // Get recent failures within time window (in seconds)
  getRecentFailures(userId, windowSeconds = 3600) {
    const since = Math.floor(Date.now() / 1000) - windowSeconds;
    return stmts.getRecentFailures.get(userId, since);
  },
  
  getRecentIPFailures(ip, windowSeconds = 3600) {
    const since = Math.floor(Date.now() / 1000) - windowSeconds;
    return stmts.getRecentIPFailures.get(ip, since);
  },
  
  clearFailures(userId) {
    return stmts.clearUserFailures.run(userId);
  }
};

// Security event logging
const securityOps = {
  log(eventType, actor, actorId, target, targetId, ip, details = null) {
    const detailsJson = details ? JSON.stringify(details) : null;
    return stmts.logEvent.run(eventType, actor, actorId, target, targetId, ip, detailsJson);
  },
  
  getByType(eventType, limit = 100) {
    return stmts.getEventsByType.all(eventType, limit).map(row => ({
      ...row,
      details: row.details ? JSON.parse(row.details) : null
    }));
  },
  
  getRecent(limit = 100) {
    return stmts.getRecentEvents.all(limit).map(row => ({
      ...row,
      details: row.details ? JSON.parse(row.details) : null
    }));
  }
};

module.exports = {
  db,
  ipOps,
  userBanOps,
  loginOps,
  securityOps
};
