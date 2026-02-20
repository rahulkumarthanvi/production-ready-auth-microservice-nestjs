# API cURL Examples for Postman

Base URL: `http://localhost:3000/api/v1`  
Content-Type: `application/json`

Use these cURL commands in Postman: **Import → Raw text → paste cURL**.

---

## 1. Health Check (Public)

```bash
curl -X GET "http://localhost:3000/api/v1/health" \
  -H "Content-Type: application/json"
```

---

## 2. Register (Public)

```bash
curl -X POST "http://localhost:3000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss1",
    "role": "USER"
  }'
```

**Admin registration (optional role):**

```bash
curl -X POST "http://localhost:3000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "AdminP@ss1",
    "role": "ADMIN"
  }'
```

**Note:** Save `accessToken` and `refreshToken` from the response for subsequent requests.

---

## 3. Login (Public)

```bash
curl -X POST "http://localhost:3000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss1"
  }'
```

Copy `data.accessToken` for protected endpoints.

---

## 4. Get Profile (Protected – Bearer Token)

Replace `YOUR_ACCESS_TOKEN` with the token from login/register.

```bash
curl -X GET "http://localhost:3000/api/v1/users/profile" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 5. Logout (Protected – Bearer Token)

```bash
curl -X POST "http://localhost:3000/api/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 6. Refresh Token (Public – body with refreshToken)

Replace `YOUR_REFRESH_TOKEN` with the refresh token from login/register.

```bash
curl -X POST "http://localhost:3000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

---

## 7. Change Password (Protected – Bearer Token)

```bash
curl -X POST "http://localhost:3000/api/v1/auth/change-password" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "currentPassword": "SecureP@ss1",
    "newPassword": "NewSecureP@ss2"
  }'
```

**Password rules:** Min 8 chars, one uppercase, one lowercase, one number, one special character (`@$!%*?&`).

---

## 8. Forgot Password (Public)

```bash
curl -X POST "http://localhost:3000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

Response includes `data.token` – use it in **Reset Password**.

---

## 9. Reset Password (Public)

Replace `TOKEN_FROM_FORGOT_PASSWORD` with the token from the forgot-password response.

```bash
curl -X POST "http://localhost:3000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "TOKEN_FROM_FORGOT_PASSWORD",
    "newPassword": "NewSecureP@ss2"
  }'
```

---

## 10. Admin-Only Route (Protected – Bearer Token, ADMIN role)

Only users with role `ADMIN` get 200; others get 403.

```bash
curl -X GET "http://localhost:3000/api/v1/users/admin-only" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_ACCESS_TOKEN"
```

---

## Quick Test Flow

1. **Health:** `GET /api/v1/health`
2. **Register:** `POST /api/v1/auth/register` → save `accessToken` and `refreshToken`
3. **Profile:** `GET /api/v1/users/profile` with `Authorization: Bearer <accessToken>`
4. **Refresh:** `POST /api/v1/auth/refresh` with `{ "refreshToken": "<refreshToken>" }`
5. **Logout:** `POST /api/v1/auth/logout` with `Authorization: Bearer <accessToken>`
6. **Login again:** `POST /api/v1/auth/login` then repeat profile/refresh/logout as needed.

---

## Postman Tips

- **Import cURL:** Postman → Import → Raw text → paste any curl from above.
- **Environment:** Create variables `baseUrl` = `http://localhost:3000/api/v1`, `accessToken`, `refreshToken` and use `{{baseUrl}}`, `{{accessToken}}`, `{{refreshToken}}` in requests.
- **Tests tab:** On login/register, add:  
  `pm.environment.set("accessToken", pm.response.json().data.accessToken);`  
  `pm.environment.set("refreshToken", pm.response.json().data.refreshToken);`
