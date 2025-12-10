const crypto = require('crypto');

// Import all database modules
const { 
  db: usersDb, 
  ROLES, 
  userOps, 
  hashPassword, 
  hashPasswordSync, 
  verifyPassword, 
  verifyPasswordSync,
  initOwner 
} = require('./users');

const { 
  db: securityDb, 
  ipOps, 
  userBanOps, 
  loginOps, 
  securityOps 
} = require('./security');

const { 
  db: logsDb, 
  sessionOps, 
  accessOps, 
  actionOps 
} = require('./logs');

// Username/password generation utilities
function generateRandomString(length = 8) {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
}

function generateUsername() {
  return 'user_' + generateRandomString(6);
}

function generatePassword() {
  return generateRandomString(12);
}

// Cleanup routine for logs database
function runCleanup() {
  try {
    sessionOps.cleanup(7);     // 7 days for sessions
    accessOps.cleanup(30);     // 30 days for access logs
    actionOps.cleanup(90);     // 90 days for user actions
    console.log('Database cleanup completed');
  } catch (err) {
    console.error('Database cleanup failed:', err);
  }
}

// Run cleanup on startup and every 24 hours
setTimeout(runCleanup, 5000); // 5s after startup
setInterval(runCleanup, 24 * 60 * 60 * 1000); // Every 24 hours

module.exports = {
  // Database connections
  usersDb,
  securityDb,
  logsDb,
  
  // Constants
  ROLES,
  
  // User operations
  userOps,
  
  // Security operations
  ipOps,
  userBanOps,
  loginOps,
  securityOps,
  
  // Logs operations
  sessionOps,
  accessOps,
  actionOps,
  
  // Password utilities
  hashPassword,
  hashPasswordSync,
  verifyPassword,
  verifyPasswordSync,
  
  // Generation utilities
  generateUsername,
  generatePassword,
  
  // Initialization
  initOwner
};
