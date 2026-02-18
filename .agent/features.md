# Features to Implement

This file tracks new feature requests and technical implementation plans.

**Agent Instructions:** Analyze the features below. When starting work, ask the user *which one* to implement first. Implement strictly one feature at a time, verify it, and only then ask for the next.

---

## [COMPLETED] 1. Log Generation Settings
**Goal:** Control console output verbosity and enable full database logging for advanced troubleshooting.

**Technical Implementation:**
- **Console Logging:**
  - **Start-up Mode (Default):** Only clean startup messages and essential info logs are displayed.
  - **Debug Mode:** When enabled, outputs all log levels (DEBUG, INFO, etc.) to the console.
- **Database Storage:**
  - **Full Log Persistence:** continuous option to store complete logs in the database, including full LLM prompts and raw model outputs for auditing and debugging.
- **Access Control:**
  - **Admin Restricted:** This feature must only be accessible to the superuser (Admin) account.

---

## 2. Easy Installation Script
**Goal:** Simplify deployment for new developers. Clone -> Run Script -> Ready.

**Technical Implementation:**
- **Script:** Create `./setup.sh` (Mac/Linux) and `./setup.bat` (Windows).
- **Prerequisites Check:** Script verifies `docker`, `docker compose`, `node`, `python3` versions.
- **Environment Setup:** 
  - Check if `.env` exists. If not, copy `.env.example` -> `.env`.
  - Perform substitution for dynamic secrets (generate `SECRET_KEY`, `ENCRYPTION_KEY` via openssl/python).
- **Docker Build:** Run `docker compose build --no-cache` (optional flag) or just `docker compose up -d --build`.
- **Database Migrations:** Wait for DB health, run `alembic upgrade head`.
- **UI Install:** `cd secure-code-ui && npm install`.
- **Completion:** Print "App running at http://localhost:5173".

---

## 3. Onboarding / Setup Wizard
**Goal:** A UI-driven first-time setup for Admin credentials and external service connections.

**Technical Implementation:**
- **State Check:** Middleware checks a flag (e.g., `SETUP_COMPLETED` in DB or absence of Admin user). If false, redirect all FE routes to `/setup`.
- **UI Page (`/setup`):** React form capturing:
  - Admin Email & Password (for App & Grafana).
  - Database Password (updates `.env`).
  - LLM Platform (OpenAI/Gemini/Anthropic) & API Key (initial key).
- **Backend Handler (`POST /api/v1/setup`):** 
  - Create the initial Super Admin user in Postgres.
  - Initial configuration of `LLMConfig`.
  - **Restart Strategy:** For structural changes (DB/Grafana passwords), the backend writes to `.env` and triggers a Docker restart (via shell command or Docker socket, restricted). *Simpler alternative:* Just handle App-level config (LLM, Users) via DB, and rely on `setup.sh` for infrastructure credentials.

---

## 4. Admin Configuration Dashboard
**Goal:** Centralized management of system secrets, API keys, and integrations after setup.

**Technical Implementation:**
- **Database Schema:** 
  - `system_configurations` table (key-value or structured JSON) for runtime config.
  - Enhanced `llm_configurations` table for managing multiple providers.
- **Backend API:** 
  - `GET /api/v1/admin/config`: Fetch current (masked) config.
  - `PUT /api/v1/admin/config`: Update keys/settings. Requires `superuser` scope.
  - **Dynamic Reloading:** Ensure services (Reasoning/Discovery engines) reload configurations from DB on request (no restart needed).
- **Frontend:** 
  - New "Admin Settings" route (guarded by Admin role).
  - Forms for "LLM Providers", "Database Connections", "Security Scanners".
  
---

## 5. User Management & RBAC
**Goal:** Admin controls user access. Regular users can run scans but cannot modify system config.

**Technical Implementation:**
- **Database Schema:** 
  - Add `role` column to `users` table (`enum: ADMIN, USER`).
  - Add `is_active` boolean for soft deletion/banning.
- **API Authorization:** 
  - Update `files` (dependencies.py) `get_current_active_user` to check `is_active`.
  - New dependency `get_current_admin_user` for verifying `role == ADMIN`.
- **Endpoints:**
  - `GET /api/v1/admin/users`: List all users.
  - `POST /api/v1/admin/users`: Create user (invite flow or direct creation).
  - `PATCH /api/v1/admin/users/{id}`: Update role/status.
  - `DELETE /api/v1/admin/users/{id}`: Soft delete.
- **Frontend:** 
  - "User Management" table in Admin Dashboard.
  - Role-based UI elements (hide "Settings" logs for non-admins).

---

## 6. Desktop Notifications
**Goal:** Alert users when long-running scans complete, even if the tab is backgrounded.

**Technical Implementation:**
- **Frontend (React):**
  - Request `Notification.requestPermission()` on login/app load.
  - Use `new Notification("Scan Complete", { body: "Project X scan finished with N findings." })`.
- **Real-time Trigger:**
  - Leverage existing WebSocket / Polling mechanism.
  - When scan status transitions to `COMPLETED` or `FAILED`, trigger the notification.
- **Service Worker (Optional):** If background notifications (tab closed) are needed, implement a Service Worker + Web Push API (requires VAPID keys). *MVP:* Stick to open-tab notifications first.
