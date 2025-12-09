# Roadmap

## Completed

### Core Features
- [x] WebSocket real-time communication
- [x] Channel creation with custom ID (letters & numbers, 2-32 chars)
- [x] Channel password protection
- [x] Random channel ID generation
- [x] URL forwarding with 10s expiration
- [x] Remaining time countdown (adjusted for latency)
- [x] End-to-end latency display

### Producer
- [x] Camera access and QR code scanning (jsQR)
- [x] Event-driven URL sending (only on change)
- [x] Consumer count display
- [x] Share link with copy button

### Consumer
- [x] Join channel by ID + password
- [x] Real-time URL reception
- [x] Countdown timer
- [x] Open URL button

### Admin & Infrastructure
- [x] Admin panel (hidden from nav, accessible via /admin.html)
- [x] Custom domain configuration for share links
- [x] Active channels overview
- [x] HTTPS support (self-signed certificates)
- [x] Docker & docker-compose support

### User System
- [x] Invite-only registration (admin creates users with random credentials)
- [x] User login with JWT authentication
- [x] Role hierarchy: Owner > Admin > User
- [x] Owner account from environment variables
- [x] Mandatory password change on first login
- [x] Login required for all pages (server-side redirect)

### Security
- [x] Login failure limit (4 attempts, auto-ban)
- [x] User ban/unban by admin
- [x] IP rate limiting (100 req/min general, 10/5min for login)
- [x] IP ban management
- [x] Security event logging (file-based)
- [x] Single-session enforcement (new login kicks old session)

### Database
- [x] SQLite integration for persistence
- [x] User data storage

### Admin Panel
- [x] User management (create, ban, unban, delete)
- [x] IP ban management
- [x] Security logs viewer (owner only)
- [x] User action logs viewer (owner only)
- [x] Role promotion/demotion (owner only)
- [x] Server-side role verification for admin access
- [x] Dynamic admin link injection (hidden from regular users)

### User Features
- [x] Username change (once for users, unlimited for admin/owner)

---

## Pending

### User System (Extended)
- [ ] User profile (customized bios)
- [ ] User contribution count
- [ ] Password bcrypt hashing

### Statistics
- [ ] Total number of users
- [ ] Number of live users
- [ ] Number of live Producers
- [ ] Leaderboard

### Logging (Extended)
- [ ] Record URL with timestamp
- [ ] URL history storage

### Other
- [ ] Fetch standard time for Producer
- [ ] Privacy policy page
- [ ] Cloudflare Worker compatibility

### Future Considerations
- [ ] Hall (marketplace for Producers and Consumers) - *low priority*
