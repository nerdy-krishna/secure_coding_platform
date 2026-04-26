# Threat Model — `add-deepseek-grok-llm-support`

## Change context

- **Goal:** Add DeepSeek and xAI Grok to SCCAP's supported LLM providers, configured via the existing admin `/api/v1/llm-configs/*` surface and routed through LiteLLM + Pydantic AI.
- **Files in scope:** 5 backend + 1 frontend type module: `src/app/shared/lib/cost_estimation.py`, `src/app/api/v1/models.py`, `src/app/api/v1/routers/admin.py`, `src/app/infrastructure/database/models.py` (no schema change), `src/app/infrastructure/database/repositories/llm_config_repo.py` (no logic change), `secure-code-ui/src/shared/types/api.ts` plus the frontend select component (planner to locate).
- **Trust boundaries crossed:** worker → new external LLM endpoints (`api.deepseek.com`, `api.x.ai`). No new user→API boundaries; the admin surface already exists and is unchanged.
- **Auth surfaces touched:** admin-only `/api/v1/llm-configs/*` (existing `Depends(current_superuser)` on POST/PATCH/DELETE in `admin.py:14-55`). No change to dependency wiring.
- **Data sensitivity:** Fernet-encrypted API keys at rest in `llm_configurations.encrypted_api_key`; scanned source code transits to two new third-party endpoints whose RLHF profiles differ from incumbent providers.

## STRIDE-lite

| Category | Status | Notes / Mitigation |
|---|---|---|
| **S**poofing | PASS | No new auth surface. `llm_router` POST/PATCH/DELETE already gated on `current_superuser` (`admin.py:18,36,49`); GET on `current_active_user`. Change is data-only. |
| **T**ampering | FLAG | `LLMConfigurationBase.provider` is unvalidated `str` (`models.py:37`). With more accepted vendors and no allowlist, an admin (or hijacked admin session) can persist arbitrary `provider` strings; coerced silently to `_PROVIDER_PREFIX.get(...)→None` and the `len/4` token-estimate fallback (`cost_estimation.py:48,119`). **Mitigation:** add a `Literal["openai","anthropic","google","deepseek","xai"]` validator on `LLMConfigurationBase.provider` and `LLMConfigurationUpdate.provider`. |
| **R**epudiation | PASS | Existing admin-action logging path is unchanged; `X-Correlation-ID` middleware already attaches the request id to logs. No new mutation type. |
| **I**nfo disclosure | FLAG | Scanned source code is sent to two new third-party LLM providers with different alignment profiles. An attacker who controls a scanned file (poisoned dependency, hostile sample) could embed indirect-prompt-injection payloads tuned for less-aligned models — e.g. instruct Grok to echo the system prompt back into `parsed_output`, persisted into `llm_interactions.parsed_output` and surfaced in the UI. Existing prompts were tuned against OpenAI/Anthropic/Google; eval coverage is functional only. **Mitigation:** documentation-only — add a caution note. Redteam eval pack is a separately-tracked follow-up. |
| **D**oS | PASS | New providers ride the existing `Semaphore(CONCURRENT_LLM_LIMIT=5)`. Cost estimate fallback (`len/4`) on an unrecognised provider could under-estimate spend, but the cost-approval interrupt still requires explicit operator approval. |
| **E**levation | PASS | `llm_router` superuser-gated; no regular-user route. Provider bound through SQLAlchemy ORM, no SQL-string interpolation. |

## Project-specific gates

| Gate | Applies? | Notes |
|---|---|---|
| New list endpoint takes `visible_user_ids = Depends(get_visible_user_ids)` | N/A | No new endpoint; `llm_router` is admin-only and not user-scoped. |
| Secrets / API keys Fernet-encrypted | Y — PASS | DeepSeek + xAI keys land in existing `encrypted_api_key: Text` via `AdminService.create_config`. Provider-agnostic Fernet path. |
| New superuser routes mounted under `/admin/*` | N/A | No new routes; reusing `llm_router`. |
| New worker-graph nodes preserve interrupt/resume | N/A | No graph changes. `LLMClient.generate_structured_output` model-agnostic via Pydantic AI/LiteLLM. |
| `.env.example` does **not** add plaintext API key placeholders | Y — required test | CLAUDE.md H.0.2. **Required test:** assertion that `.env.example` contains neither `DEEPSEEK_API_KEY` nor `XAI_API_KEY`. |
| New LLM calls go through `litellm` for cost accounting | Y — PASS | Cost path is `_compute_cost` → `litellm.cost_per_token` (`cost_estimation.py:140`). Extending `_PROVIDER_PREFIX` keeps both providers on this path; bundled `litellm.model_cost` already contains DeepSeek + xAI entries (planner must verify canonical prefix). |
| New DB migrations are reversible | N/A | No migration — `provider: String(50)` accommodates `"deepseek"` (8) and `"xai"` (3). |

Operational note: adding `api.deepseek.com` and `api.x.ai` extends worker egress for restricted-egress deployments. Operators must update firewall rules — flag in plan operator notes; not a code-level mitigation.

## Verdict

**PROCEED-WITH-MITIGATIONS.**

DeepSeek and Grok ride entirely existing trust boundaries: same admin auth, same Fernet encryption, same LiteLLM cost path, same Pydantic-AI structured-output guarantee, no schema migration, no new user-scope surface. The change is essentially extending two strings in `_PROVIDER_PREFIX` and one allowlist.

### Required mitigations (carry into plan's verification matrix)

1. **`Literal` allowlist on provider field.** Add `Literal["openai","anthropic","google","deepseek","xai"]` validator to `LLMConfigurationBase.provider` (`api/v1/models.py:37`) and `LLMConfigurationUpdate.provider` (~line 100). Unit test: POST `/api/v1/llm-configs/` with `provider="bogus"` returns HTTP 422.
2. **`.env.example` regression test.** Assert the file contains neither `DEEPSEEK_API_KEY` nor `XAI_API_KEY`.
3. **Extend `_PROVIDER_PREFIX`** in `cost_estimation.py:39` with `"deepseek"` and `"xai"` mapping to LiteLLM's canonical prefixes (planner verifies against `litellm.model_cost` keys). Unit test: `_first_working_model_key` returns a known-good key for one DeepSeek and one xAI model present in the bundled cost map.
4. **Frontend allowlist parity:** add the two providers to the LLM-config form's `<Select>` options and update `secure-code-ui/src/shared/types/api.ts` `LLMConfiguration.provider` to a string-union mirroring the backend `Literal`.
5. **Document the eval gap.** One-line note near the `_PROVIDER_PREFIX` extension and a sentence in `.agent/features.md` (or equivalent docs) stating DeepSeek and Grok have not been redteam-evaluated against SCCAP's prompt templates.
6. **Operator note (not code):** plan's release notes call out new egress destinations `api.deepseek.com` and `api.x.ai`.

## Open

- LiteLLM's canonical prefixes for DeepSeek and xAI must be verified by the planner (run `python -c "import litellm; print([k for k in litellm.model_cost if 'deepseek' in k or 'grok' in k or 'xai' in k])"` or read the LiteLLM model map directly). Allowlist `Literal` values must match LiteLLM's, not invented strings.
- Pre-existing zero-override cost-bypass surface (admin can set `input_cost_per_million=0`) is orthogonal — flagged but not in scope for this change.
