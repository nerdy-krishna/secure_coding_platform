# Discovery: add-deepseek-grok-llm-support

## Files in scope

- `src/app/infrastructure/database/models.py` — `LLMConfiguration` ORM model with `provider: String(50)` and `model_name: String(100)` fields, no enum validation.
- `src/app/api/v1/models.py` — `LLMConfigurationBase` Pydantic schema with `provider: str` Field (no validation; examples mention openai / google / anthropic).
- `src/app/api/v1/routers/admin.py` (or `admin_config.py` / `llm_config.py`) — `llm_router` with POST/GET/PATCH/DELETE endpoints; accepts `LLMConfigurationCreate` and `LLMConfigurationUpdate`. (Path to be confirmed by orchestrator.)
- `src/app/infrastructure/database/repositories/llm_config_repo.py` — `create()` persists provider string unchanged; no validation.
- `src/app/shared/lib/cost_estimation.py` — `_PROVIDER_PREFIX` dict maps hardcoded providers ("openai", "anthropic", "google") to LiteLLM prefixes; this is the deterministic provider→prefix routing.
- `secure-code-ui/src/shared/types/api.ts` — `LLMConfiguration` interface with `provider: string` (no enum).
- `evals/providers/mock.js` — Promptfoo mock provider; sandboxed, does not enumerate or validate providers.
- `.env.example` — must NOT include DeepSeek / xAI API-key placeholders (CLAUDE.md H.0.2).
- `src/app/core/services/default_seed_service.py` — does not define provider list (frameworks + agents only).

## Reuse candidates

- `_PROVIDER_PREFIX` in `src/app/shared/lib/cost_estimation.py` — extend with `"deepseek"` and `"xai"` (or whatever LiteLLM's canonical prefix is) and cost lookup works automatically via the bundled `litellm.model_cost` map.
- `LLMConfigurationBase.provider` — unvalidated `str` today. Can optionally add a soft `Literal[...]` enum for known providers; backward-compat-friendly to keep open if we want future flexibility.
- Pydantic AI structured-output retry — model-agnostic, routes through LiteLLM, so Grok/DeepSeek work without client code changes.

## Blast radius

- **API:** `/api/v1/llm-configs/*` accepts a `provider` string; new providers ride the same path.
- **Services:** `AdminService` create/update persists provider unchanged; no business logic changes.
- **Repos:** generic on provider string; no changes.
- **Worker graph:** model-agnostic via `LLMClient.generate_structured_output` → Pydantic AI → LiteLLM.
- **Frontend:** any provider `<Select>` dropdown must include the new options.
- **Migrations:** none — `provider` is `String(50)`, both new strings fit.
- **CI / evals:** mock provider is sandboxed; no changes needed.
- **Docs:** `.agent/project_structure.md` / `.agent/features.md` may need a one-liner if we add a hard allowlist; otherwise skip.

## Inherited constraints

- `.env.example` MUST NOT carry DeepSeek / xAI API-key placeholders (CLAUDE.md H.0.2).
- API keys remain Fernet-encrypted via `EncryptedSecret`.
- Per-`LLMConfiguration` `input_cost_per_million` / `output_cost_per_million` overrides take precedence over LiteLLM's `model_cost` map.
- `LITELLM_LOCAL_MODEL_COST_MAP=True` keeps cost lookups offline; DeepSeek + xAI Grok are already present in the bundled LiteLLM cost map (verify in plan phase).
- No new Python or NPM dependencies — LiteLLM and Pydantic AI both already support these providers.
- No `Co-Authored-By: Claude` trailer on the commit.

## Open questions for the planner

1. **Validation:** add `Literal[...]` allowlist enforcement on `provider`, or keep it open?
2. **Frontend dropdown:** single canonical select component, or fragmented across pages?
3. **Cost-map fallback:** reject unknown model strings at create-time, or allow and warn at cost-estimation time?
4. **Provider-prefix mapping:** confirm LiteLLM's canonical prefix for each (`deepseek/...` and `xai/...` are likely; planner should verify against `litellm.model_cost`).
