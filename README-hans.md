# Realtime QR Forwarding Server

实时QR码URL转发服务器 - 扫描QR码后将URL实时转发给其他设备。

## 功能特性

### 核心功能
- **实时URL转发**: Producer扫描QR码后，URL实时推送给所有Consumer
- **频道系统**: 支持创建私有频道，可设置密码保护
- **端到端延迟显示**: 精确计算Producer到Consumer的传输延迟
- **10秒有效期**: URL自动过期，防止过时链接
- **自动跳转**: Consumer可选择自动打开URL（Safari/iOS有弹窗限制提示）

### 用户管理
- **三级角色**: Owner > Admin > User
- **用户创建**: Admin每日限创建3个用户，Owner无限制
- **用户名修改**: 普通用户仅可修改一次，Admin/Owner无限制
- **密码安全**: bcrypt哈希存储，首次登录强制修改密码
- **单设备登录**: 新登录会踢掉旧会话

### 安全特性
- **登录保护**: 连续4次失败自动封禁账户
- **IP封禁**: 支持手动封禁恶意IP
- **权限隔离**: Admin只能封禁普通用户，不能封禁Admin
- **会话管理**: JWT令牌 + 服务端会话验证
- **速率限制**: 防止暴力破解

## 快速开始

### 环境要求
- Node.js >= 18.0.0

### 安装
```bash
npm install
```

### 配置
创建 `.env` 文件：
```env
OWNER_USERNAME=admin
OWNER_PASSWORD=your-secure-password
JWT_SECRET=your-jwt-secret-change-in-production
PORT=3000
```

### 启动
```bash
npm start
```

### HTTPS支持
将证书放入 `certs/` 目录：
- `certs/key.pem`
- `certs/cert.pem`

## 数据库结构

系统使用三个独立的SQLite数据库，便于分类管理和数据共享：

### 1. users.db - 用户数据（长期保存/可共享）

```sql
-- 用户表
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,      -- 用户名
    password_hash TEXT NOT NULL,        -- bcrypt哈希密码
    role TEXT NOT NULL DEFAULT 'user',  -- 角色: owner/admin/user
    must_change_password INTEGER DEFAULT 1,  -- 是否需要修改密码
    username_changed INTEGER DEFAULT 0,      -- 是否已修改过用户名
    notes TEXT,                         -- 备注（仅Owner可见）
    created_at INTEGER,                 -- 创建时间
    created_by TEXT                     -- 创建者
);
```

### 2. security.db - 风控数据（长期保存）

```sql
-- IP封禁表
CREATE TABLE banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER,
    banned_by TEXT
);

-- 用户封禁表（保留历史记录）
CREATE TABLE banned_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    reason TEXT,
    banned_at INTEGER,
    banned_by TEXT,
    unbanned_at INTEGER,    -- NULL表示仍被封禁
    unbanned_by TEXT
);

-- 登录尝试记录
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,   -- 1成功, 0失败
    failure_reason TEXT,
    timestamp INTEGER
);

-- 安全事件日志
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,   -- login_success, login_failed, user_banned等
    actor TEXT,                 -- 操作者
    actor_id INTEGER,
    target TEXT,                -- 目标
    target_id INTEGER,
    ip TEXT,
    details TEXT,               -- JSON详情
    timestamp INTEGER
);
```

### 3. logs.db - 运维日志（可定期清理）

```sql
-- 会话表
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    invalidated_at INTEGER,     -- 失效时间
    invalidated_reason TEXT     -- logout/new_login等
);

-- 访问日志
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

-- 用户操作日志
CREATE TABLE user_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL,
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,       -- user_created, user_banned, password_changed等
    target_type TEXT,
    target_id INTEGER,
    target_name TEXT,
    details TEXT,               -- JSON详情
    ip TEXT,
    timestamp INTEGER
);
```

### 自动清理策略
- **sessions**: 7天后清理
- **access_logs**: 30天后清理
- **user_actions**: 90天后清理
- **security.db**: 不自动清理（风控数据长期保存）

## 权限矩阵

| 功能 | User | Admin | Owner |
|------|:----:|:-----:|:-----:|
| 使用Producer/Consumer | ✓ | ✓ | ✓ |
| 创建普通用户 | - | ✓ (3/天) | ✓ |
| 创建Admin | - | - | ✓ |
| 封禁普通用户 | - | ✓ | ✓ |
| 封禁Admin | - | - | ✓ |
| 修改用户角色 | - | - | ✓ |
| 查看/编辑Notes | - | - | ✓ |
| 查看安全日志 | - | - | ✓ |
| IP封禁管理 | - | ✓ | ✓ |

## API端点

### 认证
- `POST /api/auth/login` - 登录
- `POST /api/auth/logout` - 登出
- `GET /api/auth/me` - 获取当前用户
- `POST /api/auth/change-password` - 修改密码
- `POST /api/auth/change-username` - 修改用户名

### 管理 (Admin+)
- `GET /api/admin/users` - 用户列表
- `POST /api/admin/users` - 创建用户
- `POST /api/admin/users/:id/ban` - 封禁用户
- `POST /api/admin/users/:id/unban` - 解封用户
- `DELETE /api/admin/users/:id` - 删除用户
- `GET /api/admin/ip-bans` - IP封禁列表
- `POST /api/admin/ip-bans` - 封禁IP
- `DELETE /api/admin/ip-bans/:ip` - 解封IP

### 管理 (Owner Only)
- `PUT /api/admin/users/:id/role` - 修改角色
- `PUT /api/admin/users/:id/notes` - 修改备注
- `GET /api/admin/logs/:type` - 查看日志 (security/user-actions/access)

### WebSocket
- `ws://host/ws` - 实时通信端点

## 页面

- `/login.html` - 登录页
- `/index.html` - 首页（频道选择）
- `/producer.html` - 生产者页面（扫描QR码）
- `/consumer.html` - 消费者页面（接收URL）
- `/admin.html` - 管理面板

## 许可证

MIT License
