# Change Plan — `add-deepseek-grok-llm-support`

> No ADR — this is a config-only change. No new service boundaries, no new auth surface, no new deps, no migration. Threat model cleared as PROCEED-WITH-MITIGATIONS; all six mitigations are carried into the phases below.

## Goal

Add DeepSeek and xAI Grok to SCCAP's supported LLM providers. Operators configure them through the existing `/api/v1/llm-configs/*` admin surface; calls route through LiteLLM + Pydantic AI which already support both natively. Success = an admin can POST `provider="deepseek"` or `provider="xai"`; a scan referencing that config token-counts and prices via LiteLLM's bundled cost map without falling back to `len/4`; the frontend form lets the operator pick either; and a malformed `provider="bogus"` is rejected with HTTP 422.

## Inputs

- Discovery report: `.agent/work/add-deepseek-grok-llm-support-discovery.md`
- Threat model: `.agent/work/add-deepseek-grok-llm-support-threat-model.md`

## Risk posture

- **Risk tolerance:** low (data-only change touching admin auth surface; new third-party egress destinations; unevaluated prompt-alignment profiles).
- **STRIDE flags carried over:** **T**ampering (unvalidated `provider` string → `Literal` allowlist); **I**nfo disclosure (new third-party endpoints + indirect prompt-injection risk on less-aligned models → documentation-only caution).
- **Architectural impact:** no — no ADR.

## LiteLLM canonical-prefix verification

| Provider string (SCCAP) | LiteLLM prefix | Sample key in `litellm.model_cost` |
|---|---|---|
| `deepseek` | `deepseek` | `deepseek/deepseek-chat`, `deepseek/deepseek-coder` |
| `xai` | `xai` | `xai/grok-2-latest`, `xai/grok-beta` |

The `Literal[...]` values in `LLMConfigurationBase.provider` and `_PROVIDER_PREFIX` keys MUST match the SCCAP-side strings in column 1. Phase 3's cost-prefix test (`_first_working_model_key` returns a key from `litellm.model_cost`) is the drift-catcher if LiteLLM ever renames either prefix.

---

## Phase 1 — Backend allowlist + cost-prefix

**Goal:** validation + cost routing land in one self-contained patch. After this phase, a backend POST with `provider="bogus"` returns 422 (T mitigation), and a known DeepSeek/Grok model resolves through `_first_working_model_key` rather than the `len/4` fallback.

- [ ] Add `Literal["openai", "anthropic", "google", "deepseek", "xai"]` annotation to `LLMConfigurationBase.provider` at `src/app/api/v1/models.py:37`. Update the description to include the new options.
- [ ] Mirror the same `Literal[...]` (wrapped in `Optional[...]`) on `LLMConfigurationUpdate.provider` at `src/app/api/v1/models.py:100`. The `Literal` import is already present at `models.py:6`.
- [ ] Extend `_PROVIDER_PREFIX` at `src/app/shared/lib/cost_estimation.py:39` with two entries: `"deepseek": "deepseek"`, `"xai": "xai"`.
- [ ] Add a one-line eval-gap caution comment immediately above `_PROVIDER_PREFIX` (mitigation #5).

**Mitigations:** #1 (Literal allowlist), #3 (cost-prefix extension), #5 (eval-gap caution comment).

## Phase 2 — Frontend parity

**Goal:** the LLM-config form and the type façade match the new backend allowlist.

- [ ] Update `LLMConfiguration.provider` at `secure-code-ui/src/shared/types/api.ts:55` from `provider: string;` to `provider: "openai" | "anthropic" | "google" | "deepseek" | "xai";`.
- [ ] Extend `LLM_PROVIDERS` at `secure-code-ui/src/features/admin-settings/components/LLMSettingsPage.tsx:20` from `["openai", "google", "anthropic"] as const` to `["openai", "google", "anthropic", "deepseek", "xai"] as const`. Both the create-form `<select>` (~line 247) and the filter `<select>` (~line 379) iterate this const, so a single edit covers both.

**Mitigations:** #4 (frontend parity).

## Phase 3 — Tests

- [ ] New file `tests/test_llm_config_admin_router.py`:
  - `test_create_llm_config_rejects_unknown_provider` — POST with `provider="bogus"` → 422 with `literal_error`.
  - `test_create_llm_config_accepts_deepseek` — POST with `provider="deepseek"`, `model_name="deepseek-chat"` → 201.
  - `test_create_llm_config_accepts_xai` — POST with `provider="xai"`, `model_name="grok-2-latest"` → 201.
- [ ] Extend `tests/test_cost_estimation.py`:
  - `test_first_working_model_key_resolves_new_providers` — `_config("deepseek", "deepseek-chat")` and `_config("xai", "grok-2-latest")` each resolve to a key present in `litellm.model_cost`.
- [ ] New file `tests/test_env_example_no_new_provider_keys.py` — assert `.env.example` contains neither `DEEPSEEK_API_KEY` nor `XAI_API_KEY`.

**Mitigations:** #1, #2, #3.

## Phase 4 — Docs

- [ ] Append to `.agent/features.md`: one bullet noting DeepSeek + xAI added 2026-04-27 with the eval-gap caveat.
- [ ] Confirm `.agent/scanning_flow.md` requires no change (worker graph is model-agnostic).
- [ ] Confirm `.agent/project_structure.md` requires no change (no new modules; tests/ additions are conventional).

**Mitigations:** #5.

## Operator notes (release-notes copy)

- **New egress destinations.** `api.deepseek.com` (TCP 443) and `api.x.ai` (TCP 443). Restricted-egress deployments must allowlist these.
- **Eval coverage gap.** Promptfoo eval suite + the OWASP LLM/Agentic redteam pack do not yet exercise DeepSeek or Grok. Treat both as experimental until the redteam pack ships.
- **No `.env.example` changes.** Per CLAUDE.md H.0.2, no new `*_API_KEY` placeholders. Keys are configured via the admin UI and stored Fernet-encrypted.
- **No migration.** `provider` is `String(50)`; both new strings fit.

## File-touched table

| File | Change | Lines (approx) |
|---|---|---|
| `src/app/api/v1/models.py` | add `Literal[...]` on `provider` (Base + Update) | ~37, ~100 |
| `src/app/shared/lib/cost_estimation.py` | extend `_PROVIDER_PREFIX` + eval-gap comment | ~38–43 |
| `secure-code-ui/src/shared/types/api.ts` | tighten `LLMConfiguration.provider` to a string-union | ~55 |
| `secure-code-ui/src/features/admin-settings/components/LLMSettingsPage.tsx` | extend `LLM_PROVIDERS` tuple | ~20 |
| `tests/test_llm_config_admin_router.py` | new — 422 + happy-path tests for deepseek/xai | new file |
| `tests/test_cost_estimation.py` | new test: prefix resolution for DeepSeek + xAI | append |
| `tests/test_env_example_no_new_provider_keys.py` | new — regression: file omits the two key names | new file |
| `.agent/features.md` | one-line eval-gap caveat | end of file |

## Verification matrix

| Gate | Required? | Command | Expected |
|---|---|---|---|
| `ruff` | Y | `python3 -m ruff check src` | clean |
| `black` | Y | `python3 -m black --check src` | clean |
| `mypy` | Y | `python3 -m mypy src` | clean (or stable diff vs main) |
| pytest (focused) | Y | `docker compose exec app pytest tests/test_llm_config_admin_router.py tests/test_cost_estimation.py tests/test_env_example_no_new_provider_keys.py -v` | all pass |
| pytest (full suite) | Y | `docker compose exec app pytest` | green; no regressions |
| frontend lint | Y | `cd secure-code-ui && npm run lint` | clean |
| frontend build | Y | `cd secure-code-ui && npm run build` | `tsc -b` clean, vite build succeeds |
| `.env.example` regression | Y | `! grep -E '^(DEEPSEEK\|XAI)_API_KEY=' .env.example` | exit 1 (no match) |

## Out of scope (deferred follow-ups)

- Promptfoo eval coverage for DeepSeek and Grok — deferred to redteam pack.
- Provider-specific prompt-tuning if outputs are noisier than incumbents.
- Pre-existing zero-cost-override surface (orthogonal).
- Per-tenant Langfuse projects.
- **Medium (filed during security review cycle 1):** rate-limiter coverage for `deepseek` and `xai` in `src/app/infrastructure/llm_client_rate_limiter.py`. `provider_rate_limiters` is initialised only for `openai`/`google`/`anthropic`; `get_rate_limiter_for_provider("deepseek")` returns `None` and `llm_client.py:151-157` silently skips acquisition. Add `DEEPSEEK_REQUESTS_PER_MINUTE` / `_TOKENS_PER_MINUTE` and `XAI_*` settings; register both limiters. Default 60 RPM / 100k TPM until production traffic informs tuning.
- **Low (process note):** discovery for provider-allowlist changes should grep every consumer of the `LLMConfiguration.provider` field (`grep -rn "config\.provider\|llm_config\.provider\|provider_name"`), not only the admin router. The cycle-1 review caught three integration gaps the discovery missed because it didn't trace the field through `llm_client.py`, `setup.py`, or `LLMConfigurationRead`.

## ADR draft

Not needed — config/allowlist extension. No service boundary change, no auth-model change, no graph-topology change, no new external dependency category (LiteLLM and Pydantic AI already span both providers), no public API contract change beyond *tightening* an existing field's accepted values.
