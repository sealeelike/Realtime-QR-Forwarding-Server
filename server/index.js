require('dotenv').config();
const Fastify = require('fastify');
const fastifyStatic = require('@fastify/static');
const fastifyWebsocket = require('@fastify/websocket');
const fastifyCookie = require('@fastify/cookie');
const fastifyRateLimit = require('@fastify/rate-limit');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const { initOwner, securityOps } = require('./db');
const { authPlugin, verifyToken } = require('./auth');
const userRoutes = require('./routes/user');

const generateId = () => crypto.randomBytes(4).toString('hex');

// HTTPS support - check for certificates
const certPath = path.join(__dirname, '../certs');
let httpsOptions = null;

if (fs.existsSync(path.join(certPath, 'key.pem')) && fs.existsSync(path.join(certPath, 'cert.pem'))) {
  httpsOptions = {
    key: fs.readFileSync(path.join(certPath, 'key.pem')),
    cert: fs.readFileSync(path.join(certPath, 'cert.pem'))
  };
  console.log('HTTPS certificates found, enabling HTTPS');
}

const fastify = Fastify({ 
  logger: true,
  trustProxy: true,
  ...(httpsOptions && { https: httpsOptions })
});

// In-memory channel storage (can be replaced with SQLite later)
const channels = new Map();

// Server config (can be set via admin panel)
let serverConfig = {
  domain: ''
};

// Channel structure:
// {
//   id: string,
//   password: string | null,
//   producer: WebSocket | null,
//   consumers: Set<WebSocket>,
//   lastUrl: { url: string, timestamp: number, expireTime: number } | null,
//   createdAt: number,
//   createdBy: string (username)
// }

const EXPIRE_TIME_MS = 10000; // 10 seconds

// Register plugins
fastify.register(fastifyCookie);

// Rate limiting - protect against brute force
fastify.register(fastifyRateLimit, {
  max: 100, // max requests per window
  timeWindow: '1 minute',
  keyGenerator: (request) => request.ip,
  errorResponseBuilder: (request, context) => {
    securityOps.log('rate_limit_exceeded', null, null, null, null, request.ip, { url: request.url });
    return {
      code: 429,
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Try again in ${Math.round(context.after / 1000)} seconds.`
    };
  }
});

// Stricter rate limit for login
fastify.register(async function (fastify) {
  fastify.register(fastifyRateLimit, {
    max: 10,
    timeWindow: '5 minutes',
    keyGenerator: (request) => request.ip
  });
  
  fastify.post('/api/auth/login-limited', async (request, reply) => {
    // This route is just to apply stricter rate limit, actual login handled elsewhere
    return reply.callNotFound();
  });
});

fastify.register(fastifyWebsocket);
fastify.register(fastifyStatic, {
  root: path.join(__dirname, '../public'),
  prefix: '/'
});

// Auth plugin - must be after cookie but before routes
fastify.register(authPlugin);

// User routes
fastify.register(userRoutes);

// WebSocket endpoint
fastify.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (socket, req) => {
    // Authenticate WebSocket connection via token in query or cookie
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || req.cookies?.token;
    
    const user = token ? verifyToken(token) : null;
    if (!user) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    let currentChannel = null;
    let role = null;

    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        
        switch (data.type) {
          case 'create_channel': {
            let channelId = data.channelId;
            
            // Validate custom channel ID if provided
            if (channelId) {
              if (!/^[a-zA-Z0-9]+$/.test(channelId)) {
                socket.send(JSON.stringify({ type: 'error', message: 'Channel ID can only contain letters and numbers' }));
                return;
              }
              if (channelId.length < 2 || channelId.length > 32) {
                socket.send(JSON.stringify({ type: 'error', message: 'Channel ID must be 2-32 characters' }));
                return;
              }
              if (channels.has(channelId)) {
                socket.send(JSON.stringify({ type: 'error', message: 'Channel ID already exists' }));
                return;
              }
            } else {
              channelId = generateId();
            }
            
            channels.set(channelId, {
              id: channelId,
              password: data.password || null,
              producer: socket,
              consumers: new Set(),
              lastUrl: null,
              createdAt: Date.now(),
              createdBy: user.username
            });
            currentChannel = channelId;
            role = 'producer';
            socket.send(JSON.stringify({
              type: 'channel_created',
              channelId,
              message: 'Channel created successfully'
            }));
            break;
          }

          case 'join_channel': {
            const channel = channels.get(data.channelId);
            if (!channel) {
              socket.send(JSON.stringify({ type: 'error', message: 'Channel not found' }));
              return;
            }
            if (channel.password && channel.password !== data.password) {
              socket.send(JSON.stringify({ type: 'error', message: 'Invalid password' }));
              return;
            }
            channel.consumers.add(socket);
            currentChannel = data.channelId;
            role = 'consumer';
            socket.send(JSON.stringify({
              type: 'channel_joined',
              channelId: data.channelId,
              message: 'Joined channel successfully'
            }));
            // Send last URL if available and not expired
            if (channel.lastUrl) {
              const remaining = channel.lastUrl.expireTime - Date.now();
              if (remaining > 0) {
                socket.send(JSON.stringify({
                  type: 'url_update',
                  url: channel.lastUrl.url,
                  timestamp: channel.lastUrl.timestamp,
                  remainingMs: remaining
                }));
              }
            }
            // Notify producer about new consumer
            if (channel.producer && channel.producer.readyState === 1) {
              channel.producer.send(JSON.stringify({
                type: 'consumer_count',
                count: channel.consumers.size
              }));
            }
            break;
          }

          case 'url_update': {
            if (role !== 'producer' || !currentChannel) {
              socket.send(JSON.stringify({ type: 'error', message: 'Not authorized' }));
              return;
            }
            const channel = channels.get(currentChannel);
            if (!channel) return;

            const now = Date.now();
            channel.lastUrl = {
              url: data.url,
              timestamp: data.timestamp || now,
              expireTime: now + EXPIRE_TIME_MS
            };

            // Forward to all consumers
            const payload = JSON.stringify({
              type: 'url_update',
              url: data.url,
              timestamp: channel.lastUrl.timestamp,
              remainingMs: EXPIRE_TIME_MS
            });
            channel.consumers.forEach((consumer) => {
              if (consumer.readyState === 1) {
                consumer.send(payload);
              }
            });
            break;
          }

          case 'ping': {
            socket.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
            break;
          }
        }
      } catch (err) {
        fastify.log.error(err);
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });

    socket.on('close', () => {
      if (!currentChannel) return;
      const channel = channels.get(currentChannel);
      if (!channel) return;

      if (role === 'producer') {
        // Notify consumers that producer left
        channel.consumers.forEach((consumer) => {
          if (consumer.readyState === 1) {
            consumer.send(JSON.stringify({ type: 'producer_left' }));
          }
        });
        channels.delete(currentChannel);
      } else if (role === 'consumer') {
        channel.consumers.delete(socket);
        // Notify producer about consumer count
        if (channel.producer && channel.producer.readyState === 1) {
          channel.producer.send(JSON.stringify({
            type: 'consumer_count',
            count: channel.consumers.size
          }));
        }
      }
    });
  });
});

// API endpoint to check channel existence
fastify.get('/api/channel/:id', async (req, reply) => {
  const channel = channels.get(req.params.id);
  if (!channel) {
    return reply.code(404).send({ exists: false });
  }
  return { exists: true, hasPassword: !!channel.password, consumerCount: channel.consumers.size };
});

// Health check
fastify.get('/api/health', async () => ({ status: 'ok', timestamp: Date.now() }));

// Admin API - get/set config
fastify.get('/api/admin/config', async () => serverConfig);

fastify.post('/api/admin/config', async (req, reply) => {
  const { domain } = req.body || {};
  if (domain !== undefined) {
    serverConfig.domain = domain.replace(/\/+$/, ''); // Remove trailing slashes
  }
  return { success: true, config: serverConfig };
});

// Get active channels list (for admin)
fastify.get('/api/admin/channels', async () => {
  const list = [];
  channels.forEach((ch, id) => {
    list.push({
      id,
      hasPassword: !!ch.password,
      consumerCount: ch.consumers.size,
      createdAt: ch.createdAt,
      createdBy: ch.createdBy
    });
  });
  return { channels: list };
});

const start = async () => {
  try {
    // Initialize owner account from environment
    initOwner();
    
    const port = process.env.PORT || 3000;
    const host = process.env.HOST || '0.0.0.0';
    await fastify.listen({ port, host });
    const protocol = httpsOptions ? 'https' : 'http';
    console.log(`Server running at ${protocol}://${host}:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
