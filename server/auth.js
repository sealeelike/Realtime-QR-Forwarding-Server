const jwt = require('jsonwebtoken');
const fp = require('fastify-plugin');
const crypto = require('crypto');

const { 
  ROLES, 
  userOps, 
  ipOps, 
  userBanOps, 
  loginOps, 
  securityOps,
  sessionOps,
  verifyPasswordSync 
} = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production-' + crypto.randomBytes(16).toString('hex');
const JWT_EXPIRES = process.env.JWT_EXPIRES || '24h';
const MAX_LOGIN_FAILURES = 4;
const FAILURE_WINDOW_SECONDS = 3600; // 1 hour

if (!process.env.JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET not set. Using random secret (sessions will invalidate on restart).');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createToken(user, sessionToken, options = {}) {
  return jwt.sign(
    { 
      id: user.id, 
      username: user.username, 
      role: user.role,
      mustChangePassword: !!user.must_change_password,
      sessionToken,
      passwordChangedThisSession: !!options.passwordChangedThisSession
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function login(username, password, ip, userAgent = null) {
  // Check if IP is banned
  const bannedIp = ipOps.isBanned(ip);
  if (bannedIp) {
    securityOps.log('login_blocked_ip', username, null, null, null, ip, { reason: 'ip_banned' });
    return { success: false, error: 'IP banned', code: 'IP_BANNED' };
  }

  const user = userOps.findByUsername(username);
  
  if (!user) {
    loginOps.record(null, username, ip, false, 'unknown_user');
    securityOps.log('login_failed', username, null, null, null, ip, { reason: 'unknown_user' });
    return { success: false, error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' };
  }

  // Check if user is banned
  const userBan = userBanOps.isBanned(user.id);
  if (userBan) {
    loginOps.record(user.id, username, ip, false, 'user_banned');
    securityOps.log('login_blocked_banned', user.username, user.id, null, null, ip, { banId: userBan.id });
    return { success: false, error: 'Account banned', code: 'ACCOUNT_BANNED' };
  }

  // Check password
  if (!verifyPasswordSync(password, user.password_hash)) {
    loginOps.record(user.id, username, ip, false, 'wrong_password');
    
    // Check recent failures
    const failures = loginOps.getRecentFailures(user.id, FAILURE_WINDOW_SECONDS);
    const failureCount = failures.count + 1;
    
    securityOps.log('login_failed', user.username, user.id, null, null, ip, { 
      reason: 'wrong_password', 
      failures: failureCount 
    });

    if (failureCount >= MAX_LOGIN_FAILURES) {
      userBanOps.ban(user.id, user.username, 'Too many login failures', 'system');
      securityOps.log('user_auto_banned', user.username, user.id, null, null, ip, { 
        reason: 'too_many_failures',
        failures: failureCount
      });
      return { success: false, error: 'Account banned due to too many failed attempts', code: 'ACCOUNT_BANNED' };
    }

    return { 
      success: false, 
      error: 'Invalid credentials', 
      code: 'INVALID_CREDENTIALS',
      remainingAttempts: MAX_LOGIN_FAILURES - failureCount
    };
  }

  // Login successful - clear previous failures
  loginOps.clearFailures(user.id);
  loginOps.record(user.id, username, ip, true, null);
  
  // Invalidate old sessions (single session enforcement)
  sessionOps.invalidateAllForUser(user.id, 'new_login');
  
  // Create new session
  const sessionToken = generateSessionToken();
  const expiresAt = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // 24 hours
  sessionOps.create(sessionToken, user.id, user.username, ip, userAgent, expiresAt);
  
  securityOps.log('login_success', user.username, user.id, null, null, ip, null);

  const token = createToken(user, sessionToken);
  return {
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      mustChangePassword: !!user.must_change_password
    }
  };
}

function changePassword(userId, oldPassword, newPassword, ip = null) {
  const { hashPasswordSync } = require('./db');
  
  const user = userOps.findById(userId);
  if (!user) {
    return { success: false, error: 'User not found' };
  }

  // Verify old password (skip for must_change_password on first login)
  if (!user.must_change_password && !verifyPasswordSync(oldPassword, user.password_hash)) {
    securityOps.log('password_change_failed', user.username, user.id, null, null, ip, { 
      reason: 'wrong_old_password' 
    });
    return { success: false, error: 'Current password is incorrect' };
  }

  if (newPassword.length < 6) {
    return { success: false, error: 'Password must be at least 6 characters' };
  }

  const newHash = hashPasswordSync(newPassword);
  userOps.updatePassword(newHash, userId);
  
  securityOps.log('password_changed', user.username, user.id, null, null, ip, null);
  
  // Get current active session
  const sessions = sessionOps.getActiveForUser(userId);
  const currentSessionToken = sessions.length > 0 ? sessions[0].token : generateSessionToken();
  
  // Return new token with passwordChangedThisSession flag
  const updatedUser = userOps.findById(userId);
  const token = createToken(updatedUser, currentSessionToken, { passwordChangedThisSession: true });
  
  return { success: true, token };
}

// Check if user has required role level
function hasRole(userRole, requiredRole) {
  return ROLES[userRole] >= ROLES[requiredRole];
}

// Fastify authentication decorator
function authPlugin(fastify, opts, done) {
  // Decorate request with user
  fastify.decorateRequest('user', null);

  // Auth hook - use onRequest to run before static file serving
  fastify.addHook('onRequest', async (request, reply) => {
    // Parse URL path without query string
    const urlPath = request.url.split('?')[0];
    
    // Skip auth for login and public routes
    const publicRoutes = ['/api/auth/login', '/api/health', '/login.html', '/css/', '/js/'];
    const isPublic = publicRoutes.some(route => urlPath.startsWith(route));
    
    if (isPublic) return;

    // Check if it's a page request (HTML or root)
    const isPageRequest = urlPath.endsWith('.html') || urlPath === '/';
    
    // For non-API, non-WS requests
    if (!urlPath.startsWith('/api/') && !urlPath.startsWith('/ws')) {
      if (isPageRequest) {
        // Check auth for HTML pages - redirect if not authenticated
        const token = request.cookies?.token;
        if (!token) {
          return reply.redirect('/login.html');
        }
        const payload = verifyToken(token);
        if (!payload) {
          reply.clearCookie('token', { path: '/' });
          return reply.redirect('/login.html');
        }
        // Check if user is banned or session invalidated
        const user = userOps.findById(payload.id);
        const isBanned = userBanOps.isBanned(payload.id);
        const session = sessionOps.find(payload.sessionToken);
        
        if (!user || isBanned || !session) {
          reply.clearCookie('token', { path: '/' });
          return reply.redirect('/login.html');
        }
        request.user = payload;
        return;
      }
      // Allow other static files (images, etc.)
      return;
    }

    // Get token from cookie or header
    const token = request.cookies?.token || 
                  request.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return reply.code(401).send({ error: 'Authentication required' });
    }

    const payload = verifyToken(token);
    if (!payload) {
      return reply.code(401).send({ error: 'Invalid or expired token' });
    }

    // Check if user still exists and not banned
    const user = userOps.findById(payload.id);
    const isBanned = userBanOps.isBanned(payload.id);
    
    if (!user || isBanned) {
      return reply.code(401).send({ error: 'Account not available' });
    }
    
    // Check if session is still valid
    const session = sessionOps.find(payload.sessionToken);
    if (!session) {
      return reply.code(401).send({ error: 'Session expired (logged in elsewhere)', code: 'SESSION_EXPIRED' });
    }

    request.user = payload;
  });

  done();
}

// Role check middleware factory
function requireRole(role) {
  return async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required' });
    }
    if (!hasRole(request.user.role, role)) {
      securityOps.log('unauthorized_access', request.user.username, request.user.id, null, null, request.ip, {
        requiredRole: role,
        userRole: request.user.role,
        path: request.url
      });
      return reply.code(403).send({ error: 'Insufficient permissions' });
    }
  };
}

module.exports = {
  createToken,
  verifyToken,
  login,
  changePassword,
  hasRole,
  authPlugin: fp(authPlugin),
  requireRole,
  JWT_SECRET
};
