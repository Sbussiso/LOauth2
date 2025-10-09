# Docker Deployment Guide

Complete guide to deploying the OAuth2 server using Docker and Docker Compose.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Sbussiso/LOauth2.git
cd LOauth2

# Optional: set a strong secret (no .env required)
export APP_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Start with Docker Compose (SQLite by default, persisted in a volume)
docker compose up -d --build

# Check logs
docker compose logs -f oauth2

# Access the server at http://localhost:8000
```

## Prerequisites

- Docker Engine 20.10+
- Docker Compose V2 (or docker-compose 1.29+)

## Configuration

### Environment Variables

You can set variables directly in your shell; a `.env` file is optional.

Recommended:

```bash
export APP_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
# Optional: enable dev helpers (seed, pkce)
export ENABLE_DEV_ENDPOINTS=true
# Optional: override SQLite path inside container
# export DATABASE_URL=sqlite:////data/custom.db
```

### Docker Compose Configuration

The `docker-compose.yml` includes:

- **oauth2** service: The OAuth2 server (port 8000)
- **app_data** volume: Persistent SQLite database at `/data/oauth.db`
- **oauth2-network**: Internal network for the service

## Deployment Options

### Option 1: Docker Compose (Recommended)

**Start services:**
```bash
docker compose up -d
```

**View logs:**
```bash
docker compose logs -f oauth2
```

**Stop services:**
```bash
docker compose down
```

**Rebuild after code changes:**
```bash
docker compose build
docker compose up -d
```

### Option 2: Standalone Docker

**Build image:**
```bash
docker build -t oauth2-server .
```

**Run with SQLite (development):**
```bash
docker run -d -p 8000:8000 \
  -e APP_SECRET="your-secret-key" \
  -e DATABASE_URL="sqlite:////data/oauth.db" \
  -v oauth2_app_data:/data \
  --name oauth2 \
  oauth2-server
```

**Run with external PostgreSQL:**
```bash
docker run -d -p 8000:8000 \
  -e APP_SECRET="your-secret-key" \
  -e DATABASE_URL="postgresql://user:pass@host:5432/oauth" \
  --name oauth2 \
  oauth2-server
```

## First-Time Setup

### 1. Complete Initial Setup

Open http://localhost:8000/setup in your browser:

- System generates Admin Token (shown once)
- Copy and save the token securely
- Token is hashed and stored in database

### 2. Seed Demo Data (Optional)

```bash
# Enable dev endpoints in .env
echo "ENABLE_DEV_ENDPOINTS=true" >> .env
docker compose restart oauth2

# Seed demo data
curl http://localhost:8000/dev/seed \
  -H "X-Admin-Token: YOUR_ADMIN_TOKEN"
```

This creates:
- Demo users: `alice/alice`, `bob/bob`
- Demo client: `demo-web`
- Default scopes: `openid`, `profile`, `email`, `offline_access`

### 3. Access Admin UI

Open http://localhost:8000/admin/login and use your Admin Token.

## Production Deployment

### Using Docker Compose with Custom Configuration

**docker-compose.prod.yml:**
```yaml
version: '3.8'

services:
  oauth2:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://oauth:${DB_PASSWORD}@db:5432/oauth
      APP_SECRET: ${APP_SECRET}
      ENABLE_DEV_ENDPOINTS: false
    depends_on:
      db:
        condition: service_healthy
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: oauth
      POSTGRES_USER: oauth
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - /data/oauth2/postgres:/var/lib/postgresql/data
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Optional: Nginx reverse proxy with TLS
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - oauth2
    restart: always
```

**Deploy:**
```bash
docker compose -f docker-compose.prod.yml up -d
```

### Behind a Reverse Proxy

#### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name oauth.yourdomain.com;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://oauth2:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name oauth.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

#### Traefik Configuration

Add labels to docker-compose.yml:

```yaml
services:
  oauth2:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.oauth2.rule=Host(`oauth.yourdomain.com`)"
      - "traefik.http.routers.oauth2.entrypoints=websecure"
      - "traefik.http.routers.oauth2.tls=true"
      - "traefik.http.routers.oauth2.tls.certresolver=letsencrypt"
      - "traefik.http.services.oauth2.loadbalancer.server.port=8000"
```

## Volume Management

### Backup Database

```bash
# Create backup
docker compose exec db pg_dump -U oauth oauth > backup_$(date +%Y%m%d).sql

# Restore backup
docker compose exec -T db psql -U oauth oauth < backup.sql
```

### Persistent Data Locations

With Docker Compose (SQLite), data is stored in the named volume `app_data`:

```bash
# List volumes
docker volume ls | grep oauth2_app_data

# Inspect volume
docker volume inspect oauth2_app_data

# Remove everything (containers, network, and volumes)
docker compose down -v   # WARNING: deletes data
```

## Scaling and High Availability

### Multiple OAuth2 Instances

```yaml
services:
  oauth2:
    deploy:
      replicas: 3
    # ... rest of config

  # Load balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - oauth2
```

**nginx-lb.conf:**
```nginx
upstream oauth2_backend {
    least_conn;
    server oauth2:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    location / {
        proxy_pass http://oauth2_backend;
    }
}
```

### Database Replication

For production, use managed PostgreSQL or configure replication:

```yaml
services:
  db-primary:
    image: postgres:15-alpine
    # Primary configuration

  db-replica:
    image: postgres:15-alpine
    environment:
      POSTGRES_REPLICATION_MODE: replica
      POSTGRES_MASTER_HOST: db-primary
    # Replica configuration
```

## Monitoring and Logs

### View Logs

```bash
# All services
docker compose logs -f

# OAuth2 server only
docker compose logs -f oauth2

# Database only
docker compose logs -f db

# Last 100 lines
docker compose logs --tail=100 oauth2
```

### Health Checks

```bash
# Check service health
docker compose ps

# Manual health check
curl http://localhost:8000/health
```

### Monitor Resource Usage

```bash
# Real-time stats
docker stats

# Specific container
docker stats oauth2-server
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs oauth2

# Check if port is already in use
sudo netstat -tlnp | grep 8000

# Inspect container
docker compose ps
docker inspect oauth2-server
```

### Database configuration (SQLite)

```bash
# Check environment variables inside the container
docker compose exec oauth2 env | grep -E 'APP_SECRET|DATABASE_URL|ENABLE_DEV_ENDPOINTS'

# DATABASE_URL should default to sqlite:////data/oauth.db
# Verify the DB file exists
docker compose exec oauth2 ls -l /data
```

### Permission issues with volumes

```bash
# Fix volume permissions
docker compose down
docker volume rm oauth2_postgres_data
docker compose up -d
```

### Reset everything

```bash
# Stop and remove all containers, networks, and volumes
docker compose down -v

# Remove images
docker compose down --rmi all

# Clean rebuild
docker compose build --no-cache
docker compose up -d
```

## Security Best Practices

- [ ] Use strong `APP_SECRET` (32+ random bytes)
- [ ] Change default database passwords
- [ ] Disable `ENABLE_DEV_ENDPOINTS` in production
- [ ] Use HTTPS/TLS (reverse proxy)
- [ ] Keep Docker images updated
- [ ] Use Docker secrets for sensitive data
- [ ] Enable Docker content trust
- [ ] Regular security scanning: `docker scan oauth2-server`
- [ ] Restrict network access with firewall rules
- [ ] Regular database backups

## Updates and Maintenance

### Update to Latest Version

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose build
docker compose up -d

# Check logs
docker compose logs -f oauth2
```

### Database Migrations

Database schema is auto-created/updated on startup. For manual control:

```bash
# Access database
docker compose exec db psql -U oauth oauth

# Run SQL migrations manually
docker compose exec -T db psql -U oauth oauth < migrations/001_add_column.sql
```

## Development with Docker

### Hot Reload (Development Mode)

Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  oauth2:
    build: .
    command: uv run flask --app server run --host 0.0.0.0 --port 8000 --reload
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://oauth:oauth_password@db:5432/oauth
      APP_SECRET: dev-secret-do-not-use-in-production
      ENABLE_DEV_ENDPOINTS: true
      FLASK_ENV: development
    volumes:
      - .:/app
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: oauth
      POSTGRES_USER: oauth
      POSTGRES_PASSWORD: oauth_password
    ports:
      - "5432:5432"
```

Run development environment:
```bash
docker compose -f docker-compose.dev.yml up
```

---

[← Back to Main README](../README.md)
