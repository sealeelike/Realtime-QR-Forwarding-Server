# Realtime QR Forwarding Server

A realtime QR code URL forwarding server that scans QR codes and instantly forwards URLs to other devices.

## Features

### Core Functionality
- **Realtime URL Forwarding**: Producer scans QR code and the URL is pushed to all Consumers in real-time
- **Channel System**: Support for private channels with optional password protection
- **End-to-End Latency Display**: Precise measurement of transmission latency from Producer to Consumer
- **10-Second Expiration**: URLs automatically expire to prevent stale links
- **Auto-Jump**: Consumers can choose to auto-open URLs (Safari/iOS displays browser popup warning)

### User Management
- **Three-Tier Roles**: Owner > Admin > User
- **User Creation**: Admin can create max 3 users per day, Owner unlimited
- **Username Change**: Regular users can change username once, Admin/Owner unlimited times
- **Password Security**: Bcrypt hash storage, mandatory password change on first login
- **Single Device Login**: New login invalidates previous sessions

### Security Features
- **Login Protection**: Auto-ban account after 4 consecutive failed attempts
- **IP Blocking**: Support manual blocking of malicious IPs
- **Permission Isolation**: Admin can only ban Users, not other Admins
- **Session Management**: JWT tokens + server-side session validation
- **Rate Limiting**: Protection against brute force attacks

## Quick Start

### Requirements
- Node.js >= 18.0.0

### Installation
```bash
npm install
```

### Configuration
Create `.env` file:
```env
OWNER_USERNAME=admin
OWNER_PASSWORD=your-secure-password
JWT_SECRET=your-jwt-secret-change-in-production
PORT=3000
```

### Running
```bash
npm start
```

### HTTPS Support
Place certificates in `certs/` directory:
- `certs/key.pem`
- `certs/cert.pem`

## Database Structure

The system uses three separate SQLite databases for better organization and data sharing:

### 1. users.db - User Data (Long-term storage / Shareable)

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,      -- Username
    password_hash TEXT NOT NULL,        -- Bcrypt hashed password
    role TEXT NOT NULL DEFAULT 'user',  -- Role: owner/admin/user
    must_change_password INTEGER DEFAULT 1,  -- Must change password on first login
    username_changed INTEGER DEFAULT 0,      -- Has username been changed
    notes TEXT,                         -- Notes (Owner only)
    created_at INTEGER,                 -- Creation timestamp
    created_by TEXT                     -- Creator username
);
```

### 2. security.db - Risk Control Data (Long-term storage)

```sql
-- Banned IPs table
CREATE TABLE banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER,
    banned_by TEXT
);

-- User bans table (maintains history)
CREATE TABLE banned_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    reason TEXT,
    banned_at INTEGER,
    banned_by TEXT,
    unbanned_at INTEGER,    -- NULL if still banned
    unbanned_by TEXT
);

-- Login attempts tracking
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,   -- 1 success, 0 failure
    failure_reason TEXT,
    timestamp INTEGER
);

-- Security events log
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,   -- login_success, login_failed, user_banned, etc.
    actor TEXT,                 -- Operator
    actor_id INTEGER,
    target TEXT,                -- Target
    target_id INTEGER,
    ip TEXT,
    details TEXT,               -- JSON details
    timestamp INTEGER
);
```

### 3. logs.db - Operational Logs (Can be periodically cleaned)

```sql
-- Sessions table
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    invalidated_at INTEGER,     -- Invalidation timestamp
    invalidated_reason TEXT     -- logout/new_login, etc.
);

-- Access logs
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    ip TEXT,
    user_agent TEXT,
    duration_ms INTEGER,
    timestamp INTEGER
);

-- User actions log
CREATE TABLE user_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL,
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,       -- user_created, user_banned, password_changed, etc.
    target_type TEXT,
    target_id INTEGER,
    target_name TEXT,
    details TEXT,               -- JSON details
    ip TEXT,
    timestamp INTEGER
);
```

### Auto-Cleanup Policy
- **sessions**: Cleaned after 7 days
- **access_logs**: Cleaned after 30 days
- **user_actions**: Cleaned after 90 days
- **security.db**: Not auto-cleaned (risk control data retained long-term)

## Permission Matrix

| Feature | User | Admin | Owner |
|---------|:----:|:-----:|:-----:|
| Use Producer/Consumer | ✓ | ✓ | ✓ |
| Create regular users | - | ✓ (3/day) | ✓ |
| Create Admin | - | - | ✓ |
| Ban users | - | ✓ | ✓ |
| Ban Admins | - | - | ✓ |
| Change user roles | - | - | ✓ |
| View/Edit Notes | - | - | ✓ |
| View security logs | - | - | ✓ |
| IP blocking | - | ✓ | ✓ |

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user
- `POST /api/auth/change-password` - Change password
- `POST /api/auth/change-username` - Change username

### Management (Admin+)
- `GET /api/admin/users` - User list
- `POST /api/admin/users` - Create user
- `POST /api/admin/users/:id/ban` - Ban user
- `POST /api/admin/users/:id/unban` - Unban user
- `DELETE /api/admin/users/:id` - Delete user
- `GET /api/admin/ip-bans` - IP ban list
- `POST /api/admin/ip-bans` - Ban IP
- `DELETE /api/admin/ip-bans/:ip` - Unban IP

### Management (Owner Only)
- `PUT /api/admin/users/:id/role` - Change user role
- `PUT /api/admin/users/:id/notes` - Edit user notes
- `GET /api/admin/logs/:type` - View logs (security/user-actions/access)

### WebSocket
- `ws://host/ws` - Realtime communication endpoint

## Pages

- `/login.html` - Login page
- `/index.html` - Home page (channel selection)
- `/producer.html` - Producer page (QR code scanning)
- `/consumer.html` - Consumer page (receive URLs)
- `/admin.html` - Admin panel

## License

MIT License
