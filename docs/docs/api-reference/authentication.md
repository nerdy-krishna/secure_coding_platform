---
sidebar_position: 1
title: Authentication
---

# Authentication

SCCAP uses [fastapi-users](https://fastapi-users.github.io/fastapi-users/)
with a **JWT Bearer** transport. The first user to register becomes
the superuser and is routed through `/setup` before the rest of the
app unlocks for anyone else.

## Register

```http
POST /api/v1/auth/register
Content-Type: application/json

{ "email": "user@example.com", "password": "..." }
```

Returns the created user (no token). Registration can be disabled by
setting `auth.allow_registration` to `false` in system config once
setup completes.

## Login

```http
POST /api/v1/auth/jwt/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=...
```

Returns `{ "access_token": "...", "token_type": "bearer",
"refresh_token": "..." }`.

Access token lifetime defaults to 30 minutes
(`ACCESS_TOKEN_LIFETIME_SECONDS`); refresh token lifetime defaults to
7 days (`REFRESH_TOKEN_LIFETIME_SECONDS`).

## Refresh

fastapi-users doesn't ship a refresh endpoint for the Bearer
transport, so SCCAP adds one at `refresh.py`:

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{ "refresh_token": "..." }
```

Returns a fresh `{ access_token, refresh_token }` pair. Rotating the
refresh token with each use keeps replay attacks from surviving a
single use.

## Logout

```http
POST /api/v1/auth/jwt/logout
Authorization: Bearer <access_token>
```

Invalidates the server-side session row. Clients should also discard
their stored refresh token.

## Password reset

Requires SMTP to be configured. The flow:

1. User submits their email to `/auth/forgot-password`.
2. Backend emails them a short-lived reset token.
3. UI calls `/auth/reset-password` with `{ token, password }`.

## Admin-created users

Admins can create accounts directly from **Admin → Users** via
`POST /admin/users`. The response shape matches the regular
registration response; the new user receives an invite email (when
SMTP is configured) with a password-reset link.

## Setup gate

Until the first-run wizard finishes, the backend returns `403` from
every authenticated endpoint except `/auth/*` and `/setup/*`. The UI
polls `/setup/status` on every mount and forces a redirect to
`/setup` when `is_setup_completed === false`.

## MCP authentication

The MCP tool surface at `/mcp` accepts the same JWT Bearer tokens
via a custom `TokenVerifier` wrapping `CustomCookieJWTStrategy`.
Connect a Claude Code client with:

```json
{
  "mcpServers": {
    "sccap": {
      "url": "https://<your-host>/mcp",
      "headers": { "Authorization": "Bearer <jwt>" }
    }
  }
}
```

Expired tokens return `401` (not `500`) and can be refreshed through
the regular `/auth/refresh` path.
