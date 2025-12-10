const { 
  userOps, 
  ipOps, 
  userBanOps,
  securityOps,
  actionOps,
  ROLES, 
  generateUsername, 
  generatePassword,
  hashPasswordSync
} = require('../db');
const { login, changePassword, requireRole, hasRole } = require('../auth');

async function userRoutes(fastify) {
  // Login
  fastify.post('/api/auth/login', async (request, reply) => {
    const { username, password } = request.body || {};
    const ip = request.ip;
    const userAgent = request.headers['user-agent'];

    if (!username || !password) {
      return reply.code(400).send({ error: 'Username and password required' });
    }

    const result = login(username, password, ip, userAgent);
    
    if (result.success) {
      reply.setCookie('token', result.token, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60
      });
    }

    return result;
  });

  // Logout
  fastify.post('/api/auth/logout', async (request, reply) => {
    reply.clearCookie('token', { path: '/' });
    return { success: true };
  });

  // Get current user
  fastify.get('/api/auth/me', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }
    const dbUser = userOps.findById(request.user.id);
    return { 
      user: {
        ...request.user,
        username: dbUser ? dbUser.username : request.user.username,
        mustChangePassword: dbUser ? !!dbUser.must_change_password : false,
        usernameChanged: dbUser ? !!dbUser.username_changed : false,
        passwordChangedThisSession: !!request.user.passwordChangedThisSession
      }
    };
  });

  // Change password
  fastify.post('/api/auth/change-password', async (request, reply) => {
    const { oldPassword, newPassword, confirmPassword } = request.body || {};

    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }

    if (request.user.passwordChangedThisSession) {
      return reply.code(403).send({ error: 'Password can only be changed once per session. Please re-login to change again.' });
    }

    if (!newPassword || !confirmPassword) {
      return reply.code(400).send({ error: 'New password and confirmation required' });
    }

    if (newPassword !== confirmPassword) {
      return reply.code(400).send({ error: 'Passwords do not match' });
    }

    const user = userOps.findById(request.user.id);
    const needOldPassword = !user.must_change_password;

    if (needOldPassword && !oldPassword) {
      return reply.code(400).send({ error: 'Current password required' });
    }

    const result = changePassword(request.user.id, oldPassword || '', newPassword, request.ip);
    
    if (result.success) {
      reply.setCookie('token', result.token, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60
      });
    }

    return result;
  });

  // === Admin routes ===

  // Create user (admin+)
  fastify.post('/api/admin/users', { preHandler: requireRole('admin') }, async (request, reply) => {
    const { role = 'user' } = request.body || {};
    
    // Admins can only create users, owners can create admins too
    if (role === 'admin' && !hasRole(request.user.role, 'owner')) {
      return reply.code(403).send({ error: 'Only owner can create admin accounts' });
    }
    
    if (role === 'owner') {
      return reply.code(403).send({ error: 'Cannot create owner accounts' });
    }

    // Admin daily limit: 3 users per day (owner unlimited)
    if (request.user.role === 'admin') {
      const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);
      const created = userOps.countCreatedToday(request.user.username, todayStart);
      if (created.count >= 3) {
        return reply.code(403).send({ error: 'Daily limit reached. Admins can only create 3 users per day.' });
      }
    }

    const username = generateUsername();
    const password = generatePassword();
    const passwordHash = hashPasswordSync(password);

    try {
      userOps.create(username, passwordHash, role, 1, request.user.username);
      
      actionOps.log(
        request.user.id, 
        request.user.username, 
        'user_created', 
        'user', 
        null, 
        username, 
        { role },
        request.ip
      );

      return {
        success: true,
        user: { username, password, role },
        message: 'User created. They must change password on first login.'
      };
    } catch (err) {
      return reply.code(500).send({ error: 'Failed to create user' });
    }
  });

  // List users (admin+)
  fastify.get('/api/admin/users', { preHandler: requireRole('admin') }, async (request) => {
    const isOwner = request.user.role === 'owner';
    const users = userOps.listAll(isOwner);
    
    // Add ban status and login failures from security db
    const usersWithStatus = users.map(user => {
      const banInfo = userBanOps.isBanned(user.id);
      const { loginOps } = require('../db');
      const failures = loginOps.getRecentFailures(user.id, 3600);
      
      return {
        ...user,
        is_banned: !!banInfo,
        login_failures: failures.count,
        // notes is already included/excluded by listAll based on isOwner
      };
    });
    
    return { users: usersWithStatus };
  });

  // Ban user (admin+)
  fastify.post('/api/admin/users/:id/ban', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const { reason } = request.body || {};
    const user = userOps.findById(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    // Admin can ONLY ban users (not admin or owner)
    // Owner can ban users and admins (but not other owners)
    if (request.user.role === 'admin') {
      if (user.role !== 'user') {
        return reply.code(403).send({ error: 'Admins can only ban regular users' });
      }
    } else if (request.user.role === 'owner') {
      if (user.role === 'owner') {
        return reply.code(403).send({ error: 'Cannot ban owner accounts' });
      }
    }

    userBanOps.ban(userId, user.username, reason || 'Manual ban', request.user.username);
    
    actionOps.log(
      request.user.id,
      request.user.username,
      'user_banned',
      'user',
      userId,
      user.username,
      { reason },
      request.ip
    );

    securityOps.log('user_banned', request.user.username, request.user.id, user.username, userId, request.ip, { reason });

    return { success: true };
  });

  // Unban user (admin+)
  fastify.post('/api/admin/users/:id/unban', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const user = userOps.findById(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    userBanOps.unban(userId, request.user.username);
    
    // Clear login failures
    const { loginOps } = require('../db');
    loginOps.clearFailures(userId);
    
    actionOps.log(
      request.user.id,
      request.user.username,
      'user_unbanned',
      'user',
      userId,
      user.username,
      null,
      request.ip
    );

    return { success: true };
  });

  // Delete user (admin+, only regular users)
  fastify.delete('/api/admin/users/:id', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const user = userOps.findById(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    if (user.role !== 'user') {
      return reply.code(403).send({ error: 'Can only delete regular users' });
    }

    userOps.deleteUser(userId);
    
    actionOps.log(
      request.user.id,
      request.user.username,
      'user_deleted',
      'user',
      userId,
      user.username,
      null,
      request.ip
    );

    return { success: true };
  });

  // === IP Ban management ===

  // Ban IP (admin+)
  fastify.post('/api/admin/ip-bans', { preHandler: requireRole('admin') }, async (request, reply) => {
    const { ip, reason } = request.body || {};

    if (!ip) {
      return reply.code(400).send({ error: 'IP address required' });
    }

    ipOps.ban(ip, reason || 'Manual ban', request.user.username);
    
    securityOps.log('ip_banned', request.user.username, request.user.id, ip, null, request.ip, { reason });

    return { success: true };
  });

  // Unban IP (admin+)
  fastify.delete('/api/admin/ip-bans/:ip', { preHandler: requireRole('admin') }, async (request, reply) => {
    const ip = request.params.ip;

    ipOps.unban(ip);
    
    securityOps.log('ip_unbanned', request.user.username, request.user.id, ip, null, request.ip, null);

    return { success: true };
  });

  // List banned IPs (admin+)
  fastify.get('/api/admin/ip-bans', { preHandler: requireRole('admin') }, async () => {
    const bans = ipOps.listAll();
    return { bans };
  });

  // === Logs (owner only) ===
  fastify.get('/api/admin/logs/:type', { preHandler: requireRole('owner') }, async (request, reply) => {
    const { type } = request.params;
    const limit = parseInt(request.query.limit) || 200;
    
    let logs;
    switch (type) {
      case 'security':
        logs = securityOps.getRecent(limit);
        break;
      case 'user-actions':
        logs = actionOps.getRecent(limit);
        break;
      case 'access':
        const { accessOps } = require('../db');
        logs = accessOps.getRecent(limit);
        break;
      default:
        return reply.code(400).send({ error: 'Invalid log type. Use: security, user-actions, access' });
    }

    return { logs };
  });

  // === Role management (owner only) ===
  fastify.put('/api/admin/users/:id/role', { preHandler: requireRole('owner') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const { role } = request.body || {};
    const user = userOps.findById(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    if (user.role === 'owner') {
      return reply.code(403).send({ error: 'Cannot change owner role' });
    }

    if (!['admin', 'user'].includes(role)) {
      return reply.code(400).send({ error: 'Invalid role. Must be admin or user' });
    }

    const oldRole = user.role;
    userOps.updateRole(role, userId);
    
    actionOps.log(
      request.user.id,
      request.user.username,
      'role_changed',
      'user',
      userId,
      user.username,
      { oldRole, newRole: role },
      request.ip
    );

    return { success: true, message: `User ${user.username} is now ${role}` };
  });

  // === Notes management (owner only) ===
  fastify.put('/api/admin/users/:id/notes', { preHandler: requireRole('owner') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const { notes } = request.body || {};
    const user = userOps.findById(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    userOps.updateNotes(notes || '', userId);
    
    actionOps.log(
      request.user.id,
      request.user.username,
      'notes_updated',
      'user',
      userId,
      user.username,
      null,
      request.ip
    );

    return { success: true };
  });

  // === Username change ===
  fastify.post('/api/auth/change-username', async (request, reply) => {
    const { newUsername } = request.body || {};

    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }

    if (!newUsername || newUsername.trim().length < 3) {
      return reply.code(400).send({ error: 'Username must be at least 3 characters' });
    }

    const trimmedUsername = newUsername.trim();
    
    const existing = userOps.findByUsername(trimmedUsername);
    if (existing && existing.id !== request.user.id) {
      return reply.code(400).send({ error: 'Username already taken' });
    }

    const currentUser = userOps.findById(request.user.id);
    if (currentUser.role === 'user' && currentUser.username_changed) {
      return reply.code(403).send({ error: 'You can only change your username once' });
    }

    const oldUsername = currentUser.username;
    userOps.updateUsername(trimmedUsername, request.user.id);
    
    actionOps.log(
      request.user.id,
      oldUsername,
      'username_changed',
      'user',
      request.user.id,
      trimmedUsername,
      { oldUsername },
      request.ip
    );

    return { success: true, newUsername: trimmedUsername };
  });
}

module.exports = userRoutes;
