# Realtime-QR-Forwarding-Server
Forward the URL obtained after parsing the QR code to other users.

## Quick Start with Docker

Create a `docker-compose.yml` file:

```yaml
services:
  qr-server:
    image: lslsls/qr-server:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - OWNER_USERNAME=admin
      - OWNER_PASSWORD=your-secure-password
      - JWT_SECRET=your-random-secret-key
      - JWT_EXPIRES=24h
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
```

Then run:

```bash
docker-compose up -d
```

Access the server at `http://localhost:3000`

> **Note:** Change `OWNER_PASSWORD` and `JWT_SECRET` to secure values before deployment.
