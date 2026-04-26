# Security Review (Cycle 2) — `add-deepseek-grok-llm-support`

## Scope

- Threat model: `.agent/work/add-deepseek-grok-llm-support-threat-model.md`
- Plan: `.agent/work/add-deepseek-grok-llm-support-plan.md`
- Cycle-1 verdict: BLOCK with 1 Critical (`_build_model` factory gap) + 2 High (setup-form `gemini` regression, legacy-row read-back).
- Cycle-2 diff: working tree vs `main` HEAD (uncommitted). 7 modified source files + 1 new Alembic migration + 3 new tests.

## Threat-model mitigation status (cycle 2)

| # | Mitigation | Status | Evidence |
|---|---|---|---|
| 1 | `Literal` allowlist on `provider` (Create + Update) | ✓ verified | `src/app/api/v1/models.py:37` (Base) and `src/app/api/v1/models.py:101-106` (Update). Test `tests/test_llm_config_provider_allowlist.py:21-33,57-64` pins `literal_error` rejection. |
| 2 | `.env.example` regression test | ✓ verified | `tests/test_env_example_no_new_provider_keys.py` present; manual grep on `.env.example` confirms neither `DEEPSEEK_API_KEY` nor `XAI_API_KEY` appear. |
| 3 | `_PROVIDER_PREFIX` extension | ✓ verified | `src/app/shared/lib/cost_estimation.py:46-48` adds `"deepseek": "deepseek"` and `"xai": "xai"`. `tests/test_cost_estimation.py` extended with prefix-resolution test. |
| 4 | Frontend allowlist parity | ✓ verified | `secure-code-ui/src/shared/types/api.ts:55` widens to the 5-string union. `secure-code-ui/src/features/admin-settings/components/LLMSettingsPage.tsx:20-26` extends `LLM_PROVIDERS`. `SetupPage.tsx:341-343` ships `value="google"` (replacing the broken `"gemini"`) plus `"deepseek"` and `"xai"`. |
| 5 | Eval-gap caution comment | ✓ verified | `src/app/shared/lib/cost_estimation.py:39-42` carries the inline note. |
| 6 | Operator egress note | ✓ verified | `.agent/features.md` records the new egress destinations. |

All six declared mitigations land in cycle 2.

## Cycle-1 blocker re-verification

| Cycle-1 finding | Severity | Status | Evidence |
|---|---|---|---|
| `_build_model` missing branches for deepseek/xai | Critical | ✓ FIXED | `src/app/infrastructure/llm_client.py:100-129`. New class-level `_OPENAI_COMPATIBLE_BASE_URLS = {"deepseek": "https://api.deepseek.com/v1", "xai": "https://api.x.ai/v1"}` mapping; the factory falls through to `OpenAIModel(model_name, provider=OpenAIProvider(api_key=..., base_url=base_url))` for any provider in that dict. Hardcoded literals — **not user-controllable**; admins set only `provider` (gated by `Literal`) and `model_name`. The base_url comes from this class-level dict, never from request input. Test `tests/test_llm_client_provider_factory.py:37-57` parametrises all 5 providers and asserts the right model class. The unknown-provider branch raises `ValueError` (defence-in-depth at `llm_client.py:130`). |
| Setup form posts `value="gemini"` (now 422 under new Literal) | High #1 | ✓ FIXED | UI: `secure-code-ui/src/pages/setup/SetupPage.tsx:341-343` — `<option value="google">Google Gemini</option>` plus DeepSeek + xAI options; legacy `value="gemini"` is gone. Backend: `src/app/api/v1/schemas/setup.py:14` tightens `SetupRequest.llm_provider` to the same `Literal["openai","anthropic","google","deepseek","xai"]`, so any future drift between UI and backend gets caught at FastAPI's request-validation layer (HTTP 422) before the broad `except Exception` at `setup.py:84` can swallow it as a 500. Manual grep confirms no other call site posts to `/api/v1/setup/` with a non-allowlisted provider value. |
| Legacy `provider="gemini"` rows break `LLMConfigurationRead` | High #2 | ✓ FIXED | Two-layer fix landed as recommended: (1) `src/app/api/v1/models.py:129-138` — `LLMConfigurationRead` redeclares `provider: str  # type: ignore[assignment]` with a comment citing Alembic `c0f39ef37367`. Pydantic v2 child-class field redeclaration overrides the parent annotation cleanly — Create/Update validation remains tight because `LLMConfigurationCreate` inherits the parent's `Literal` and `LLMConfigurationUpdate` declares its own `Literal` directly (it doesn't inherit from Base). (2) `alembic/versions/2026_04_26_2141_normalize_legacy_provider_gemini_to_.py` (revision `c0f39ef37367`, `down_revision="6b06a5036276"`) runs `UPDATE llm_configurations SET provider = 'google' WHERE provider = 'gemini'` with a symmetrical `downgrade()`. Both `op.execute()` calls wrap hardcoded string literals in `sa.text()`; **no f-string interpolation, no user input** — SQL-safe. Read-back regression pinned by `tests/test_llm_config_provider_allowlist.py:78-102`. |

## Codebase-wide legacy-provider grep

Searched for hardcoded provider literals not in the allowlist (`gemini`, `vertex`, `bedrock`, `azure`, `cohere`, `mistral`, `fireworks`, `together`, `groq`, `perplexity`):

- `src/app/shared/lib/cost_estimation.py:46` — `"google": "gemini"` is the SCCAP→LiteLLM **prefix** mapping (LiteLLM's bundled cost map keys Google models under `gemini/...`). Not a stored provider value; correct as-is.
- `src/app/api/v1/routers/setup.py:64,70` and `src/app/api/v1/schemas/setup.py:28` — both reference `'anthropic'` only, in operator-facing description strings. Not stored values.
- `secure-code-ui/src/widgets/Tweaks/Tweaks.tsx:30` — `azure` is a UI **theme color name** (`#2563eb`), not a provider identifier. Unrelated.
- No other call site stores a provider string. `gemini` is the only legacy spelling in the wild (it shipped from the old setup form), and the migration covers it.

The migration is therefore complete — no other legacy values need normalising.

## Project-aware findings (cycle 2)

| Severity | Finding | Location | Status |
|---|---|---|---|
| Medium | Rate limiter still absent for DeepSeek and xAI. `provider_rate_limiters` is initialised only for `openai/google/anthropic` (`llm_client_rate_limiter.py:27-46`); `get_rate_limiter_for_provider("deepseek"/"xai")` returns `None`, and `LLMClient.generate_structured_output` skips acquisition on a falsy limiter. DeepSeek and Grok scans currently run with no client-side rate limiting; upstream 429s and unbounded burst spend are the operator's problem until the cost-approval interrupt absorbs the per-scan ceiling. | `src/app/infrastructure/llm_client_rate_limiter.py:15-48` | Carried forward — confirm tracked in plan "Out of scope". |
| Low | Discovery-phase undermapping note from cycle 1 (the call chain from `provider` string → factory function spans three modules). | `.agent/work/add-deepseek-grok-llm-support-discovery.md` | Process note; not a code finding. |

No new findings were introduced by the cycle-2 fixes themselves:

- **Hardcoded base_url path is not user-controllable.** `_OPENAI_COMPATIBLE_BASE_URLS` is a class-level dict literal in `llm_client.py:100-103`; the request flow never writes to it. Admin requests carry only `provider` (allowlisted by `Literal`) and `model_name` (free-text but only used as the model identifier, not as a URL). No SSRF surface.
- **`# type: ignore[assignment]` on `LLMConfigurationRead.provider` does not weaken Create/Update validation.** Pydantic v2 child-class field redeclaration overrides the parent annotation only on the subclass. `LLMConfigurationCreate` inherits the parent's `Literal` (verified at `models.py:93`); `LLMConfigurationUpdate` has its own independent `Literal` at `models.py:101`. The relaxation applies exclusively to read-back validation, exactly as intended.
- **Alembic migration uses parameterised SQL via `sa.text()`** with hardcoded string literals only (`alembic/versions/2026_04_26_2141_*.py:40-54`). No f-string interpolation, no attacker-controllable data. Reversible.

## Project-aware checklist (cycle 2)

- New list endpoints scoped — N/A (no new endpoints).
- Secrets encrypted via `EncryptedSecret` Fernet path — PASS (provider-agnostic; reused unchanged).
- Admin routes mounted under `/admin/*` — N/A (no new routes).
- Worker-graph `interrupt()`/resume preserved — PASS (no graph changes).
- `.env.example` clean — PASS (verified, regression test in place).
- LLM calls cost-accounted via LiteLLM — PASS (`_PROVIDER_PREFIX` extension; new prefix-resolution test).
- Migrations reversible — PASS (`c0f39ef37367` carries a symmetrical `downgrade()`).
- CORS via `SystemConfigCache` — N/A.
- Logging hygiene — PASS (provider name + model name only; never the API key).
- SQL safety — PASS (`sa.text()` wraps hardcoded literals in the new migration; no interpolation).
- Frontend / backend allowlist parity — PASS (5 entries each, end-to-end).

## Generic security-review skill output (summary)

Standard SAST sweep on the cycle-2 diff: no SQL injection, no `text()` interpolation of dynamic data, no hardcoded secrets, no plaintext API-key persistence, no PII in log lines, no new HTTP endpoints, no change to `EncryptedSecret`/Fernet path, no change to authn/authz, no change to CORS / `SystemConfigCache`. The new `_OPENAI_COMPATIBLE_BASE_URLS` constants are class-attribute literals, not user-controllable. The Alembic migration uses parameter-free hardcoded SQL.

## Verdict

**APPROVE** — no Critical or High findings remaining.

- Blocking: 0 Critical, 0 High.
- Follow-ups to file (carry into plan's "Out of scope"):
  - **Medium** — Add `DEEPSEEK_REQUESTS_PER_MINUTE` / `DEEPSEEK_TOKENS_PER_MINUTE` and `XAI_*` settings, then register limiters in `initialize_rate_limiters()` (`llm_client_rate_limiter.py`). Default to a conservative 60 RPM / 100k TPM until production traffic informs tuning.
  - **Low** — Process note: when the next provider is added, discovery should grep every callsite that reads `LLMConfiguration.provider` (`grep -rn "config\.provider\|llm_config\.provider\|provider_name"`), not just the admin router, to surface factory-style integration points like `_build_model`.

Cycle-1 blockers all reverified as fixed; the threat-model mitigations and the cycle-1 remediation guidance landed in full.
