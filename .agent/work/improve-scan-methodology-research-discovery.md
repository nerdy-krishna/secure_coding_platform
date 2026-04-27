# Discovery: improve-scan-methodology-research

> Pipeline audit by Explore agent (very thorough). 2,500+ LOC read across worker_graph, agents, nodes, scanners, templates, schemas, cost estimation. Verbatim file:line citations throughout.

## A. Worker graph topology

`src/app/infrastructure/workflows/worker_graph.py:126-275`

Nodes (registration order):
1. `retrieve_and_prepare_data` (L128) — entry
2. `deterministic_prescan` (L129) — Bandit + Semgrep + Gitleaks + OSV in parallel under `Semaphore(CONCURRENT_SCANNER_LIMIT=5)` (`prescan.py:53,122-159`)
3. `pending_prescan_approval` (L130) — `interrupt()` if findings non-empty
4. `blocked_pre_llm` (L131) — terminal: operator declined Critical-Gitleaks override
5. `user_decline` (L132) — terminal: Stop pressed or 24-h auto-decline
6. `estimate_cost` (L133) — token-counts via LiteLLM, then `interrupt()` for cost approval
7. `analyze_files_parallel` (L134) — single-pass, all agents × all files, bounded by `Semaphore(CONCURRENT_LLM_LIMIT=5)` (`analyze.py:35,82`); emits `FILE_ANALYZED` SSE per file (`analyze.py:217-226`)
8. `correlate_findings` (L135) — dedupes by `(file_path, cwe, line_number)` (`correlate.py:26`); populates `corroborating_agents`
9. `consolidate_and_patch` (L136) — REMEDIATE-only; sequential per-file conflict resolution via `_run_merge_agent` (`consolidate.py:75-190,300-428`)
10. `verify_patches` (L137) — REMEDIATE-only; re-runs Semgrep over patched files (`verify.py:59-158`)
11. `save_results` (L138)
12. `save_final_report` (L139) — risk_score + summary JSON
13. `handle_error` (L140) — terminal

**Audit vs Remediate is implicit, not branched** — `consolidate_and_patch_node` and `verify_patches_node` self-short-circuit via `scan_type != "REMEDIATE"` checks (`consolidate.py:316`, `verify.py:74`).

Concurrency: Semaphores per node, sequential merge in consolidate.

## B. Per-file agent dispatch

`src/app/infrastructure/agents/generic_specialized_agent.py:424-653`

Single unified `analysis_node` for all 18 agents:
1. Reads agent name + domain_query from `config["configurable"]` (L430-432)
2. Picks `QUICK_AUDIT` or `DETAILED_REMEDIATION` template (L447-449)
3. `_build_rag_context(agent_name, domain_query, filename)` (L271-293) → `(vulnerability_patterns_str, secure_patterns_str)`
4. `PromptTemplateRepository.get_template_by_name_and_type(agent_name, template_type, variant=...)` — variant = `"anthropic"` if `SystemConfigCache.is_anthropic_optimized()` else `"generic"` (L464); fallback to `"generic"` then no-variant
5. `_split_template_around_code_bundle` (L101-104) splits on `{code_bundle}` to isolate cacheable system prefix
6. Filters `<UNTRUSTED_SCANNER_FINDINGS>` for the file (L36-73, 485-487) and prepends to system prompt
7. `llm_client.generate_structured_output(user_prompt, InitialAnalysisResponse, system_prompt)` (L511-515)
8. Logs `LLMInteraction` row (L526-542)
9. Per finding: `_get_cwe_from_description` (L183-241) — RAG distance < 0.25 direct, else top-3 + LLM picker (L228-234); `_build_finding_object` stamps `source="agent"` (L418); REMEDIATE: `_verify_and_correct_snippet` 4-attempt retry loop (L593-644)

Routing to files: `resolve_agents_for_file(file_path, all_relevant_agents)` (extension-based) lives in `analyze.py:130-230`, not in agent code.

## C. Prompt templates

Storage: `default_seed_service.py:430-473`, files in `src/app/core/services/seed_prompts/audit.md`, `remediation.md`, `chat.md`. Loaded via importlib at module import.

DB schema: `PromptTemplate` rows; per agent we get TWO rows (`QUICK_AUDIT` + `DETAILED_REMEDIATION`). Variant column gates anthropic vs generic.

Variant fallback: `prompt_template_repo.py:44-89` — try variant → `generic` → no-variant.

**Format: plain `str.format()`** — three placeholders (`{vulnerability_patterns}`, `{secure_patterns}`, `{code_bundle}`). No jinja2.

**All 18 agents use the same audit.md / remediation.md text. No per-language variant. No per-agent variant.** Domain specificity = RAG keywords + metadata filter + a fixed domain-scoping instruction (`generic_specialized_agent.py:476`).

## D. Deterministic scanners (prescan)

Routing: `scanners/registry.py:78-94` — extension-based.
- Python → Bandit + Semgrep
- Web/Java/Go/Ruby/PHP/C/C++ → Semgrep
- Config/text/markdown → Gitleaks (additionally on every above)

`prescan.py:59-194`:
- File staging via `stage_files(eligible)` (L126) — sandboxed temp dir, sanitised basenames (M1/M2/M3 mitigations).
- Per-file caps: 1 MiB normal / 256 KiB minified (L90-108, `is_minified` in `registry.py:68-75`).
- Single semaphore (5) over Bandit + Semgrep + Gitleaks + OSV subprocess calls (L122-159).
- Per-scanner timeout: 120s.
- Per-scanner failure non-fatal (N15) — one crash continues with the rest (L142-152).
- BOM persisted eagerly to `Scan.bom_cyclonedx` JSONB before any interrupt (L183-192).

Findings are NOT injected verbatim into LLM prompts — they go into `WorkerState.findings`, then are filtered to per-file and wrapped in `<UNTRUSTED_SCANNER_FINDINGS>` data block (`analyze.py:154-159`, `generic_specialized_agent.py:485-487`). Deduplicated against agent-emitted findings later in `correlate_findings_node` by signature.

## E. Correlation + consolidation

`correlate.py:15-76` — group by `f"{file_path}|{cwe}|{line_number}"`. On 2+ agents agreeing: highest-severity wins, `confidence="High"`, `corroborating_agents=sorted([all_agents])`.

`consolidate.py:300-428` (REMEDIATE-only):
- Group fixes by file (L333-338)
- Pre-compute `cwe_id → owasp_rank` map (L341-349)
- Per-file `_resolve_file_fix_conflicts` — sort by line, detect overlaps, pass-through non-overlaps, send overlaps to `_run_merge_agent` (`consolidate.py:75-190`)
- Merge agent: **single-shot, no retry** (L131-133) — produces `MergedFixResponse` with snippet + replacement; tree-sitter syntax-checked; on failure → fallback to highest-priority fix
- Single-pass replace against original (no iteration)

`verify.py:59-158` — re-run Semgrep over `patched_files` content; match on `(file_path, cwe)` (line-shifted-tolerant); set `fix_verified=True/False`. **Bandit/Gitleaks/OSV/agent fixes remain `fix_verified=NULL`.**

## F. Output schemas

`src/app/core/schemas.py:44-148`:
- `VulnerabilityFinding` — cwe, title, description, remediation, severity, confidence, line_number, file_path, cvss_vector, cvss_score, source ("bandit"/"semgrep"/"gitleaks"/"osv"/"agent"), agent_name, corroborating_agents, fixes, is_applied_in_remediation, fix_verified.
- `FixSuggestion` — description, original_snippet, code.
- `LLMInteraction` — full per-call telemetry (tokens, cost, raw, parsed).

SSE `FILE_ANALYZED` event: `{stage_name, details: {file_path, findings_count, fixes_count}}` per file (`analyze.py:217-226`).

## G. Cost / tokens

`shared/lib/cost_estimation.py:61-140` — covered in earlier discovery, recap: token count via `litellm.token_counter`; price via `cost_per_token` with admin override taking precedence; cost is **dry-run** at `estimate_cost_node` (sums tokens across every agent × file × chunk before interrupt; `cost.py:85-109`). Actual usage may differ.

No per-agent or per-file cost cap; one global cost estimate.

## H. Evals + tests

`evals/` — Promptfoo, deterministic JS mock provider by default; live opt-in. CI on `evals/**`, seed prompts, agent code; **warn-only**.

`scripts/extract_eval_prompts.py` keeps eval prompts in sync with seed strings (`--check` in CI).

**Coverage:** functional regressions only. **No prompt-injection / jailbreak coverage** — deferred to redteam pack (CLAUDE.md).

## I. RAG content

`src/app/infrastructure/rag/`:
- Collections: `security_guidelines_v1` (ASVS / Proactive Controls / Cheatsheets / LLM Top-10 / Agentic Top-10) + `cwe_collection`.
- Filter `scan_ready=True` so chat-only docs don't leak into scan agents (`generic_specialized_agent.py:280`).
- `_build_rag_context` (L337-383) — query Qdrant, regex-extract `**Vulnerability Pattern (..):**` blocks, prefer language-specific `[[<LANG> PATTERNS]]` (L318-330).
- `_get_cwe_from_description` (L183-241) — top-3 + LLM picker if distance ≥ 0.25.

**RAG is queried unconditionally per agent call.** Empty RAG → empty patterns → agent error path (L457-459).

## J. Tooling integrations the LLM does NOT have

The agent today is **deterministic single-path**: RAG → LLM structured call → Pydantic validation (transparent retry) → CWE RAG → snippet verification (4-attempt LLM loop). No agent-controlled branching, no multi-step tool orchestration.

Cannot:
- Re-run a scanner mid-analysis
- Ask follow-up questions
- Read prior findings on the same file (per-file isolation; only cross-file `build_dep_summary` from `repository_map`)
- Access external APIs / git / package managers
- Self-modify the prompt based on observations

Skills would imply parameterised tool calls + optional retry + runtime backend routing — none of which exist today.

## K. Open / known issues

Filed-forward (`.agent/features.md`):
- Custom Semgrep rule packs beyond `p/security-audit` — needs DB schema + admin UI
- Per-tenant `.gitleaksignore` — needs DB schema + admin UI
- Wall-clock benchmarking for per-scanner concurrency — research
- DeepSeek/Grok eval coverage gap

No `TODO/FIXME/XXX` comments in workflows code (verified clean).

## L. Gaps the audit surfaced (most important section)

1. **Prompt templates are global, not per-language or per-agent** — all 18 agents run the same audit.md / remediation.md regardless of Python vs Go vs Java; specificity is delegated to RAG keywords + a fixed domain-scoping line.
2. **Same prompt template per scan type, no per-finding-type customisation** — authorization-checks, crypto, data-protection all share one base template structure.
3. **Prescan findings treated as immutable ground truth, not hypotheses** — agents are told to *avoid duplicating* scanner flags, not asked to *validate or refute* them.
4. **Merge agent single-shot, no retry/negotiation** (`consolidate.py:131-133`) — conflicting fixes → one LLM call → fallback to highest priority.
5. **Fix verification only for Semgrep findings** — Bandit/Gitleaks/OSV/LLM fixes stay `fix_verified=NULL`; can't tell if an LLM refactor closes an OSV advisory.
6. **No retry on agent LLM call failures** — Pydantic AI handles schema retries; network/timeout errors lose the finding.
7. **Cost estimate dry-run only, not granular** — global token sum; no per-agent caps; actual run may diverge if context shifts.
8. **Agents don't adapt behaviour based on prescan findings** — agents could focus on gaps Bandit missed or deep-dive on high-confidence flags; today the prescan block is purely informational.
9. **RAG context unconditionally injected, silently degrades** — empty RAG → empty patterns → error path; no fallback policy.
10. **Deterministic scanners are not framework-filtered** — Semgrep covers 12+ languages; rules out of scope for the selected SCCAP framework still execute.
11. **Audit-vs-remediate split is implicit (node self-short-circuit), not graph-level** — debugging traces don't show the branch clearly.
12. **No per-agent SLA / wall-clock timeout** — one slow agent can hold its semaphore slot indefinitely.

These 12 gaps are the foundation for the recommendations doc.
