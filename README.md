# Auth Microservice

Production-ready **Authentication Microservice** built with **NestJS**, **MongoDB** (Mongoose), **Redis**, **JWT** (access + refresh token rotation), **Docker**, **Swagger**, and **Winston** logging. It follows clean architecture and a scalable folder structure.

---

## Architecture Overview

- **Modular structure**: Auth, Users, Tokens, Health as separate modules with clear boundaries.
- **Dependency Injection**: All services and repositories are injected via NestJS DI.
- **Security**: bcrypt password hashing, JWT with short-lived access (15m) and refresh (7d), refresh token rotation, token blacklist on logout, account lockout after 5 failed logins, rate limiting, Helmet, CORS.
- **RBAC**: Role-based access with `@Roles()` decorator and `RolesGuard`; admin-only route example.
- **Observability**: Winston logger (auth attempts, errors, suspicious activity), health check endpoint, graceful shutdown.

---

## Folder Structure

```
src/
├── main.ts                 # Bootstrap, validation pipe, helmet, CORS, Swagger, shutdown hooks
├── app.module.ts           # Root module, global filter, interceptor, guards
├── config/                 # Configuration and env validation
│   ├── configuration.ts
│   ├── config.module.ts
│   └── env.validation.ts
├── common/                 # Shared interfaces, constants, logger
│   ├── interfaces/
│   ├── constants/
│   └── logger/
├── database/               # Mongoose connection and schemas
│   ├── schemas/
│   └── database.module.ts
├── redis/                  # Redis service (blacklist, cache)
├── auth/                   # Auth module (register, login, logout, refresh, change/forgot/reset password)
├── users/                  # Users module (profile, admin-only example)
├── tokens/                 # Tokens module (refresh & password reset token persistence)
├── guards/                 # JWT, JWT-Refresh, Roles guards
├── decorators/             # @CurrentUser, @Roles, @Public
├── strategies/             # Passport JWT and JWT-Refresh strategies
├── filters/                # Global HTTP exception filter
├── interceptors/           # Standard response format interceptor
└── health/                 # Health check (DB, Redis, memory)
```

---

## Setup Instructions

### Prerequisites

- **Node.js** (LTS, e.g. 20.x)
- **MongoDB** 6+
- **Redis** 6+
- **Docker** & **Docker Compose** (optional, for running everything in containers)

### Local development

1. **Clone and install**

   ```bash
   cd production-ready-auth-microservice-nestjs
   npm install
   ```

2. **Environment**

   Copy the example env and adjust:

   ```bash
   cp .env.example .env
   ```

   Set at least:

   - `MONGODB_URI` for MongoDB
   - `REDIS_*` for Redis
   - `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` (use strong, unique values in production)

3. **Database**

   Ensure MongoDB is running. The app uses Mongoose and will use the database from `MONGODB_URI` (e.g. `mongodb://localhost:27017/auth_db`). Collections are created automatically when documents are first written.

4. **Run**

   ```bash
   npm run start:dev
   ```

   The API will be available at `http://localhost:3000` with global prefix `api/v1`.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment | `development` |
| `PORT` | Server port | `3000` |
| `API_PREFIX` | URL prefix | `api` |
| `API_VERSION` | Version segment | `v1` |
| `MONGODB_URI` | MongoDB connection URI | `mongodb://localhost:27017/auth_db` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password | - |
| `REDIS_DB` | Redis DB index | `0` |
| `JWT_ACCESS_SECRET` | Access token secret | **Required** |
| `JWT_REFRESH_SECRET` | Refresh token secret | **Required** |
| `JWT_ACCESS_EXPIRES_IN` | Access token TTL | `15m` |
| `JWT_REFRESH_EXPIRES_IN` | Refresh token TTL | `7d` |
| `BCRYPT_SALT_ROUNDS` | bcrypt rounds | `12` |
| `MAX_LOGIN_ATTEMPTS` | Lockout after N failures | `5` |
| `LOCKOUT_DURATION_MINUTES` | Lockout duration | `15` |
| `PASSWORD_RESET_TOKEN_EXPIRY_MINUTES` | Reset token TTL | `60` |
| `THROTTLE_TTL` | Rate limit window (seconds) | `60` |
| `THROTTLE_LIMIT` | Max requests per window | `100` |
| `CORS_ORIGIN` | Allowed origins | `*` |
| `SWAGGER_ENABLED` | Enable Swagger | `true` |
| `SWAGGER_PATH` | Swagger UI path | `api/docs` |
| `LOG_DIR` | Log file directory | `logs` |

---

## API Documentation (Swagger)

When `SWAGGER_ENABLED` is true:

- **URL**: `http://localhost:3000/api/docs`
- **Production**: Set `SWAGGER_ENABLED=false` to disable.

Swagger includes request/response examples and Bearer auth for protected routes.

---

## API Endpoints

Base path: **`/api/v1`**

### Public

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register (body: email, password, optional role) |
| POST | `/auth/login` | Login (body: email, password) |
| POST | `/auth/refresh` | Refresh tokens (body: refreshToken) |
| POST | `/auth/forgot-password` | Request reset (body: email) |
| POST | `/auth/reset-password` | Reset password (body: token, newPassword) |
| GET | `/health` | Health check (DB, Redis, memory) |

### Protected (Bearer token)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users/profile` | Current user profile |
| POST | `/auth/logout` | Logout (blacklist current access token) |
| POST | `/auth/change-password` | Change password (body: currentPassword, newPassword) |
| GET | `/users/admin-only` | Admin-only example (RBAC) |

---

## Standard API Response Format

All responses follow:

```json
{
  "success": true,
  "message": "Success",
  "data": { ... },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Errors use the same shape with `success: false` and appropriate HTTP status.

---

## Docker

Run the whole stack (app + PostgreSQL + Redis) with one command:

```bash
docker-compose up --build
```

- **App**: `http://localhost:3000`
- **MongoDB**: `localhost:27017`
- **Redis**: `localhost:6379`

Override secrets via env or a `.env` file:

```bash
export JWT_ACCESS_SECRET=your-secret
export JWT_REFRESH_SECRET=your-refresh-secret
docker-compose up --build
```

---

## Testing

```bash
npm test
```

- **Unit tests**: Auth service (register, login, refresh, logout), User service (findByEmail, findById, getProfile, cache).
- **Coverage**: `npm run test:cov`

---

## Code Quality

- **ESLint** + **Prettier**: `npm run lint`, `npm run format`
- **TypeScript**: Strict mode, no `any`
- **NestJS**: Pipes, guards, filters, interceptors used consistently

---

## Security Summary

- Passwords hashed with **bcrypt** (configurable salt rounds).
- **JWT**: Access 15 min, refresh 7 days; refresh tokens stored hashed in DB and rotated on each refresh; old refresh token invalidated.
- **Logout**: Access token JTI blacklisted in Redis until expiry.
- **Account lockout**: After 5 failed logins, account locked for 15 minutes (configurable).
- **Rate limiting**: Throttler guard (configurable TTL/limit).
- **Helmet**: Security headers.
- **CORS**: Configurable origin and credentials.
- **Strong password**: Validation (length, upper/lower/digit/special) on register, change-password, reset-password.

---

## License

MIT
