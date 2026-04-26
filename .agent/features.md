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

## [COMPLETED] 2. Easy Installation Script
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

## [COMPLETED] 3. Onboarding / Setup Wizard
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

## 4. **Admin Configuration Dashboard**:
    - **System Configuration**: Manage core system settings, including:
        - **CORS Configuration**: Enable/disable Cross-Origin Resource Sharing and configure allowed origins (optional, disabled by default).
        - **Debug Mode**: Toggle system-wide debug logging (enabled during setup, disabled by default after).
    - **LLM Configuration**: Manage LLM providers, models, and API keys.
    - **Agent Management**: View and configure available agents.
    - **Framework Management**: Manage security frameworks.
    - **Prompt Management**: customized prompts for different stages.
    - **RAG Management**: Manage RAG knowledge base.
    - **System Logs**: View system logs.
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

---

## 7. Deterministic SAST pre-pass — follow-ups

**Goal:** Extend the Bandit-only pre-pass shipped 2026-04-26 (`/sccap sast-prescan`) with the rest of recommendation §3.1.

**Backlog (ordered roughly by ROI):**
- **Semgrep CE integration.** Add `semgrep` to runtime deps, ship a bundled rule pack (start with `p/security-audit`) at `/app/scanners/configs/semgrep/`, and add a `semgrep_runner.py` mirroring `bandit_runner`. Pin `--config` explicitly so user-tree `.semgrepignore` cannot redirect behavior.
- **Gitleaks integration.** Download the binary in the worker Dockerfile (verify SHA), bundle a `.gitleaks.toml` at `/app/scanners/configs/gitleaks.toml`, add `gitleaks_runner.py` with secret redaction (`<REDACTED:length=N>`) before findings hit `WorkerState.findings`.
- **Critical-secret short-circuit.** Add a conditional edge from `deterministic_prescan` → terminal `BLOCKED_PRE_LLM` status when Gitleaks reports a Critical finding, so the LLM never sees the secret. Routes around `estimate_cost_node` rather than calling `interrupt()`.
- **Verified-findings prompt prefix.** Inject scanner findings into `generic_specialized_agent` prompts as a "do not duplicate" prefix so agents skip re-flagging instead of relying on `correlate_findings_node` dedup. Update agent structured-output schema + golden tests in lockstep.
- **SHA-pin GitHub Actions.** `gitleaks/gitleaks-action@v2` (added by `/sccap-bootstrap`) currently uses a tag pin; switch to a SHA digest after verifying upstream.
- **Backfill `findings.source` for historical scans.** Admin script that infers `source = NULL → "agent"` (or leaves NULL, since pre-prescan rows are entirely LLM-attributable).
- **Per-scanner concurrency tuning.** Today `CONCURRENT_SCANNER_LIMIT = 5` is shared across scanners; if Semgrep wall-clock pressure shows up, split per-scanner caps.
- **Admin UI surface.** Add a `source` filter to the findings list and a per-source counter on the scan results page.
- **F1 (security-review Low) — NUL-byte input handling.** `staging._safe_relative_path` should `try/except (ValueError, OSError)` around `Path(rel_path).parts` so a NUL-bearing path is converted to the `unnamed` slug instead of aborting the entire scan via `error_message`.
- **F2 (security-review Low) — Bandit binary discovery UX.** `bandit_runner.BANDIT_BINARY` is hard-coded to `/app/.venv/bin/bandit`. A `os.environ.get("BANDIT_BINARY") or shutil.which("bandit") or "/app/.venv/bin/bandit"` fallback would let local dev outside Docker iterate without silent FileNotFoundError suppression.
- **F3 (security-review Low) — prescan-fail policy.** Today `_route_after_prescan` aborts the whole scan if the prescan node hits an unexpected exception (disk-full, etc.). Consider downgrading prescan failures to a logged warning + empty findings list so the LLM analysis still runs.
- **F4 (security-review Info) — `ix_findings_source` cardinality.** Single-column non-unique index on a 3-cardinality VARCHAR(32). Either drop the index or make it `WHERE source IS NOT NULL` to skip the legacy NULL rows.
- **F5 (security-review Info) — SHA-pin sweep.** `.pre-commit-config.yaml` pins by tag (`gitleaks/gitleaks@v8.21.2`, `astral-sh/ruff-pre-commit@v0.11.11`, `psf/black@25.1.0`, `pre-commit/pre-commit-hooks@v4.6.0`). Bundle these into the same `gitleaks/gitleaks-action@v2` SHA-pinning follow-up.
