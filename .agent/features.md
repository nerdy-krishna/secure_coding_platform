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

## [COMPLETED] 4. Admin Configuration Dashboard

**Shipped:** routers under `src/app/api/v1/routers/admin_*.py` + `llm_config.py`; UI under `secure-code-ui/src/pages/admin/` (SystemConfigTab, AgentManagementPage, FrameworkManagementPage, PromptManagementPage, UserManagement) plus `features/admin-settings/components/LLMSettingsPage.tsx`; runtime cache invalidation in `admin_config.py:91-103` keeps `SystemConfigCache` in sync after PUTs.

**Original spec for reference below:**

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

## [COMPLETED] 5. User Management & RBAC

**Shipped:** `admin_users.py` CRUD + `fastapi-users` `current_active_user` (rejects `is_active=False`) + `current_superuser` route guard (`infrastructure/auth/core.py:23-24`); UI at `pages/admin/UserManagement.tsx` with role-aware route guards in `App.tsx`. The H.3 design simplified roles to a single `is_superuser` boolean (admin/user) rather than the spec's `enum: ADMIN, USER`; semantically equivalent.

**Original spec for reference below:**

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

## [COMPLETED] 6. Desktop Notifications

**Shipped:** `useNotificationPermission` hook (`secure-code-ui/src/shared/hooks/useNotificationPermission.ts`) + TopNav opt-in button (visible only when `supported && permission === "default" && !dismissed`) + `ScanRunningPage` terminal-status `useEffect` firing `new Notification("SCCAP — Scan finished", { body, tag: scan_id })` once per scan (deduped via `notifiedRef`). Generic body per privacy review (no findings count, no severity, no file paths). Service Worker / Web Push API deferred per spec MVP.

**Security-review follow-ups (Low; UX residue, not security):**
- **F1 (close-features-4-6)** — clear `notifications_dismissed` localStorage flag when `permission` transitions back to `"granted"`; today the flag stays stale across browser-level re-enables.
- **F2 (close-features-4-6)** — `notifiedRef` is per-page-instance; navigating away from `ScanRunningPage` and back to a terminal scan re-fires the notification once. `tag` dedupe at the browser level prevents stacking; persist notified-set in `sessionStorage` if observed in practice.
- **F3 (close-features-4-6)** — by-design: granting permission while the fallback toast already fired means no desktop notification for that one scan (toast only). Next scan notifies normally.

**Original spec for reference below:**

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

## 10. OWASP LLM Top-10 + Agentic Top-10 frameworks (§3.11)

**Status:** ✅ COMPLETE as of `llm-agentic-rag-content` run (2026-04-27).

**What shipped (seed + selective mapping; commit `97d8388`):**
- Two new frameworks seeded in `default_seed_service.FRAMEWORKS_DATA`: `llm_top10` (OWASP Top 10 for LLM Applications, 2025) and `agentic_top10` (OWASP Top 10 for Agentic AI Applications, 2026).
- Two new agents in `AGENT_DEFINITIONS`: `LLMSecurityAgent` and `AgenticSecurityAgent` covering all 10 entries of each Top-10.
- **Selective framework→agent mapping**: each agent declares an optional `applicable_frameworks` field. Legacy AppSec agents (no field set) attach to the three OWASP AppSec frameworks; the new AI agents attach only to their respective AI framework. Selecting `asvs` no longer pulls LLM-prompt-injection RAG context into a server-side scan and vice versa. Pinned by a regression test.
- `SubmitPage` framework selector dynamically fetches from the backend, so the new frameworks appear automatically in the UI with no frontend changes.

**What shipped (RAG content + ingest UI; commit `<this run>`):**
- Starter content authored under `data/owasp/{llm_top10_2025,agentic_top10_2026}.json` — 10 entries per framework with vulnerability-pattern + secure-pattern descriptions and a Python vulnerable/secure code example each. Each entry's CWE references are included. Operators can refine the content against the canonical OWASP source before relying on it for compliance reporting.
- New `SecurityStandardsService.ingest_owasp_top10_json` shared method handles both Top-10s — validates the upload's `framework` and `control_family` fields against the slot, formats each entry into the doc-text shape the agent's RAG-context extractor expects (`**Vulnerability Pattern (..):**`, `[[PYTHON PATTERNS]]` blocks with `Vulnerable: ` / `Secure: ` code fences), and writes documents tagged with `framework_name`, `control_family`, `scan_ready=True` so the agents' `metadata_filter` retrieves only the right framework's entries during a scan.
- Two new `standard_type` slugs on `POST /admin/rag/ingest/standards/{type}`: `llm-top10` and `agentic-top10`, both accepting a JSON file upload.
- Compliance page (`CompliancePage.tsx`) gets two new hidden file inputs (`hidden-llm-top10-input`, `hidden-agentic-top10-input`) and dispatches Ingest / Edit clicks for the AI frameworks to those inputs via a new `triggerIngestForFramework` helper. Two new ragService methods (`ingestLLMTop10`, `ingestAgenticTop10`) wrap the API calls.
- `data/` directory is now mounted into the `app` container (read-only) so the ingest tests can validate the canonical starter-content files.
- 7 new tests pin: doc-text formatting matches the agent's regex anchors (silent-failure trap), wrong-framework JSON is rejected with HTTP 400, wrong-control-family is rejected, non-JSON upload is rejected, empty entries is rejected, and the canonical `data/owasp/*.json` files ingest cleanly end-to-end.

---

## 8. OSV-Scanner dependency scan + CycloneDX BOM (ADR-009)

**Status:** ✅ COMPLETE as of `prescan-approval-osv` run (2026-04-26).

**What shipped:**
- `src/app/infrastructure/scanners/osv_runner.py` — fourth deterministic scanner. Runs OSV-Scanner v2.x as a subprocess against the staged dependency tree; produces `VulnerabilityFinding` rows (`source="osv"`) and a CycloneDX 1.5 BOM dict. BOM is hard-capped at 5 MB (truncation sentinel written at overflow); WARN logged at 2 MB.
- `Scan.bom_cyclonedx` JSONB column — persisted eagerly in `deterministic_prescan_node` before the prescan-approval interrupt so it survives regardless of operator decision.
- Alembic migration `add_scan_bom_cyclonedx` — reversible; also adds the `findings.cve_id` column.
- `SourceFilter` in `admin_findings.py` extended to include `"osv"`.
- BOM safe-render on scan results page: `safeUrl.ts:isSafeHttpUrl` filters `references` URLs before use as `<a href>`.

---

## 9. Prescan-approval gate (ADR-009)

**Status:** ✅ COMPLETE as of `prescan-approval-osv` run (2026-04-26).

**What shipped:**
- Replaces the pre-ADR-009 Critical-Gitleaks auto-block with a human-in-the-loop gate. When the deterministic pre-pass produces any findings, the graph pauses at the new `pending_prescan_approval` node (`interrupt()`, status `PENDING_PRESCAN_APPROVAL`) so the operator can review before any LLM spend.
- `GET /scans/{id}/prescan-findings` endpoint — serves the deterministic findings for the prescan-approval card.
- `POST /scans/{id}/approve` extended with `kind` discriminator — `"prescan_approval"` resumes the prescan gate; `"cost_approval"` resumes the existing cost gate. Body is backward-compatible (missing body defaults to cost approval).
- Post-resume routing (`_route_after_prescan_approval`): `approved=False` → `user_decline` terminal node → `STATUS_BLOCKED_USER_DECLINE`; `approved=True` with unacknowledged Critical Gitleaks → `blocked_pre_llm` → `STATUS_BLOCKED_PRE_LLM`; otherwise → `estimate_cost`.
- `prescan_approval_sweeper.py` — auto-declines scans parked at `PENDING_PRESCAN_APPROVAL` for >24 h; writes `PRESCAN_AUTO_DECLINED` scan event; deletes checkpointer thread.
- LangGraph checkpointer-thread cleanup on every terminal status (completed, failed, declined, blocked) via `_maybe_cleanup_checkpointer_thread` in `consumer.py`.
- Frontend: `PrescanReviewCard.tsx` + `CriticalSecretOverrideModal.tsx` in `secure-code-ui/src/features/prescan-approval/`. Override modal explicitly names the credential rule and the three downstream destinations (LLM provider, Langfuse, Loki); requires the operator to type "OVERRIDE" before the danger-styled Continue button enables.

---

## 7. Deterministic SAST pre-pass

**Status:** ✅ COMPLETE as of `/sccap sast-prescan-followups` (2026-04-26). The recommendation §3.1 backlog is empty.

**Shipped commits:**
- `f93f580` — Bandit-only initial slice (`/sccap sast-prescan`).
- Semgrep + Gitleaks runners + Critical-secret short-circuit (`BLOCKED_PRE_LLM` terminal node).
- Verified-findings `<UNTRUSTED_SCANNER_FINDINGS>` prompt prefix in every LLM agent.
- F1–F3 UX cleanup (NUL-byte path handling, `_resolve_binary` env-var/PATH/fallback discovery, prescan-fail-continues policy).
- C1+F5 SHA-pin sweep across `.pre-commit-config.yaml` and `.github/workflows/ci.yml`.
- F4 partial `ix_findings_source` index `WHERE source IS NOT NULL` + `findings.source = 'agent'` backfill admin script (idempotent + batched).
- D1 admin findings list endpoint (`GET /api/v1/admin/findings`) with source filter + cursor pagination, doubly scoped by `current_superuser` + `visible_user_ids`.
- D2 per-source counter row on the scan results page.

**Closed in `feature7-cleanup` run (2026-04-27):**
- ✅ **F1** — `datetime.utcnow()` → `datetime.now(timezone.utc)` in `admin_findings.py`.
- ✅ **F2** — `_resolve_binary` is now `@functools.cache`d + accessed via `_<scanner>_binary()` lazy functions; `*_BINARY` env-vars set in `.env` (loaded after module import by `dotenv`) are now honored.
- ✅ **F3** — `ScanRepository.count_findings_by_source` accepts a defensive `visible_user_ids` kwarg.
- ✅ **F4** — Semgrep rule-pack SHA-pin bump procedure documented in `.agent/devsecops_playbook.md` § "Operational runbooks".
- ✅ **B1** — LLM-emitted findings now stamp `source="agent"` at write time in `generic_specialized_agent._build_finding_object`.
- ✅ **B2** — `.github/renovate.json` adds custom-managers regex coverage for Dockerfile-pinned scanner binaries (Bandit / Semgrep / Gitleaks / OSV-Scanner). Complements the existing `dependabot.yml` (which already handles pip / npm / github-actions).
- ✅ **B3** — `findings_source_sweeper` runs hourly on the API container as a defense-in-depth catch for any `findings.source IS NULL` rows that land after the initial backfill. No-op in steady state.

**Filed forward (NOT in §3.1 scope; deferred to dedicated runs):**
- Custom Semgrep rule packs beyond `p/security-audit` — needs DB schema + admin UI + worker integration.
- Per-tenant `.gitleaksignore` allow-list table — needs DB schema + admin UI + worker integration.
- Wall-clock benchmarking to justify per-scanner concurrency split — research task.

---

## 11. DeepSeek + xAI Grok provider support

**Status:** ✅ COMPLETE as of `/sccap add-deepseek-grok-llm-support` (2026-04-27).

- `LLMConfigurationBase.provider` and `LLMConfigurationUpdate.provider` are now `Literal["openai","anthropic","google","deepseek","xai"]` — unknown providers are rejected with HTTP 422 at the schema layer (mitigation #1 from the threat model).
- `cost_estimation._PROVIDER_PREFIX` extended with `"deepseek": "deepseek"` and `"xai": "xai"`. LiteLLM's bundled `model_cost` map already keys both providers under those prefixes (e.g. `deepseek/deepseek-chat`, `xai/grok-2-latest`); no network calls are introduced.
- Frontend: `LLM_PROVIDERS` in `LLMSettingsPage.tsx` and the `LLMConfiguration.provider` TS type (`shared/types/api.ts`) widened to the same allowlist.
- API keys remain Fernet-encrypted via `EncryptedSecret`; no `.env.example` placeholders are added (CLAUDE.md H.0.2 — guarded by `tests/test_env_example_no_new_provider_keys.py`).

**Eval-gap (operator-facing caveat):** the Promptfoo eval suite and the deferred OWASP LLM/Agentic redteam pack do not yet exercise DeepSeek or Grok. Their RLHF profiles differ from the incumbent providers; an attacker-controlled file embedding indirect-prompt-injection content could behave differently on these models. Treat both as *experimental* until the redteam pack ships.

**Operator note:** restricted-egress deployments must allowlist `api.deepseek.com` and `api.x.ai` (TCP 443) before scans against those configs can complete.
