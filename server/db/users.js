const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

const dbPath = process.env.USERS_DB_PATH || path.join(__dirname, '../../data/users.db');

// Ensure data directory exists
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    must_change_password INTEGER NOT NULL DEFAULT 1,
    username_changed INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
`);

// Role hierarchy: owner > admin > user
const ROLES = {
  owner: 3,
  admin: 2,
  user: 1
};

// Password hashing utilities
async function hashPassword(plainPassword) {
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
}

function hashPasswordSync(plainPassword) {
  return bcrypt.hashSync(plainPassword, SALT_ROUNDS);
}

async function verifyPassword(plainPassword, hash) {
  // Support legacy plain text passwords during migration
  if (!hash.startsWith('$2')) {
    return plainPassword === hash;
  }
  return bcrypt.compare(plainPassword, hash);
}

function verifyPasswordSync(plainPassword, hash) {
  // Support legacy plain text passwords during migration
  if (!hash.startsWith('$2')) {
    return plainPassword === hash;
  }
  return bcrypt.compareSync(plainPassword, hash);
}

// Prepared statements
const stmts = {
  create: db.prepare(`
    INSERT INTO users (username, password_hash, role, must_change_password, created_by)
    VALUES (?, ?, ?, ?, ?)
  `),
  
  findByUsername: db.prepare(`SELECT * FROM users WHERE username = ?`),
  
  findById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  
  updatePassword: db.prepare(`
    UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?
  `),
  
  listAll: db.prepare(`
    SELECT id, username, role, must_change_password, username_changed, notes, created_at, created_by 
    FROM users WHERE role != 'owner'
  `),
  
  listAllWithoutNotes: db.prepare(`
    SELECT id, username, role, must_change_password, username_changed, created_at, created_by 
    FROM users WHERE role != 'owner'
  `),
  
  deleteUser: db.prepare(`DELETE FROM users WHERE id = ? AND role = 'user'`),
  
  countByRole: db.prepare(`SELECT role, COUNT(*) as count FROM users GROUP BY role`),
  
  updateRole: db.prepare(`UPDATE users SET role = ? WHERE id = ?`),
  
  updateUsername: db.prepare(`UPDATE users SET username = ?, username_changed = 1 WHERE id = ?`),
  
  updateNotes: db.prepare(`UPDATE users SET notes = ? WHERE id = ?`),
  
  countCreatedToday: db.prepare(`
    SELECT COUNT(*) as count FROM users 
    WHERE created_by = ? AND created_at >= ?
  `)
};

// User operations
const userOps = {
  create(username, passwordHash, role, mustChangePassword, createdBy) {
    return stmts.create.run(username, passwordHash, role, mustChangePassword, createdBy);
  },
  
  findByUsername(username) {
    return stmts.findByUsername.get(username);
  },
  
  findById(id) {
    return stmts.findById.get(id);
  },
  
  updatePassword(passwordHash, userId) {
    return stmts.updatePassword.run(passwordHash, userId);
  },
  
  // isOwner: whether the requester is owner (to include notes)
  listAll(isOwner = false) {
    if (isOwner) {
      return stmts.listAll.all();
    }
    return stmts.listAllWithoutNotes.all();
  },
  
  deleteUser(id) {
    return stmts.deleteUser.run(id);
  },
  
  countByRole() {
    return stmts.countByRole.all();
  },
  
  updateRole(role, userId) {
    return stmts.updateRole.run(role, userId);
  },
  
  updateUsername(username, userId) {
    return stmts.updateUsername.run(username, userId);
  },
  
  updateNotes(notes, userId) {
    return stmts.updateNotes.run(notes, userId);
  },
  
  countCreatedToday(createdBy, todayStart) {
    return stmts.countCreatedToday.get(createdBy, todayStart);
  }
};

// Initialize owner account from environment variables
function initOwner() {
  const ownerUsername = process.env.OWNER_USERNAME;
  const ownerPassword = process.env.OWNER_PASSWORD;
  
  if (!ownerUsername || !ownerPassword) {
    console.warn('WARNING: OWNER_USERNAME and OWNER_PASSWORD not set in environment variables!');
    console.warn('Please set them to create the owner account.');
    return false;
  }
  
  const passwordHash = hashPasswordSync(ownerPassword);
  
  const existing = userOps.findByUsername(ownerUsername);
  if (!existing) {
    userOps.create(ownerUsername, passwordHash, 'owner', 0, 'system');
    console.log(`Owner account "${ownerUsername}" created.`);
  } else if (existing.role !== 'owner') {
    db.prepare(`UPDATE users SET role = 'owner', password_hash = ? WHERE username = ?`)
      .run(passwordHash, ownerUsername);
    console.log(`Account "${ownerUsername}" promoted to owner.`);
  } else {
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?`)
      .run(passwordHash, ownerUsername);
    console.log(`Owner account "${ownerUsername}" synced from environment.`);
  }
  return true;
}

module.exports = {
  db,
  ROLES,
  userOps,
  hashPassword,
  hashPasswordSync,
  verifyPassword,
  verifyPasswordSync,
  initOwner
};
