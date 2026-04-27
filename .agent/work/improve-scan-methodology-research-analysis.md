# SCCAP Scan Methodology — Recommendations & Strategic Decision

**Run:** `improve-scan-methodology-research`
**Date:** 2026-04-27
**Author:** SCCAP DevSecOps harness (Opus 4.7 orchestrator)
**Evidence base:** `.agent/work/improve-scan-methodology-research-discovery.md` (full pipeline audit, 2,500 LOC read)

---

## 1. Executive summary

**TL;DR.** The current SCCAP scan pipeline is a single-pass, RAG-augmented, prompt-templated multi-agent system with two human gates (prescan, cost) and a deterministic SAST pre-pass. The audit surfaced **12 concrete gaps** (discovery §L) that fall cleanly onto three axes: *template engineering*, *skill scaffolding*, and *workflow guardrails*.

The strategic question — "templates vs skills vs hybrid" — has a clear answer: **hybrid (skills-augmented templates)**. SCCAP's cost-approval gate (`estimate_cost_node`) and structured-output contract (Pydantic AI → `VulnerabilityFinding`) are load-bearing constraints that pure-skills designs break. Templates preserve them; selectively-invoked skills extend the agent's capability where the templated path is insufficient.

**Top-5 prioritised improvements (P0 — this quarter):**

1. **Per-agent / per-language prompt-template variants** (closes gaps 1, 2). Replaces the one-template-fits-all `audit.md` and `remediation.md`.
2. **Agent-level retry with exponential backoff** on transient LLM failures (gap 6). Pure workflow change; no schema impact.
3. **Per-agent cost caps + granular token tracking** (gap 7). Extends `cost_estimation.py`'s dry-run with per-agent ceilings.
4. **Prescan-validation skill** — agent invokes a callable to confirm/refute scanner findings (gap 3, 8). The first true "skill" in SCCAP.
5. **Extended fix verification** beyond Semgrep — re-run Bandit + OSV post-fix where applicable (gap 5).

The remainder (gaps 4, 9, 10, 11, 12) become P1/P2; sequenced as four follow-up `/sccap` runs (Phases A–D in §5).

---

## 2. Current state

### Pipeline shape

```
                    ┌─────────────────────────────┐
                    │ retrieve_and_prepare_data   │
                    └──────────────┬──────────────┘
                                   ▼
            ┌──────── deterministic_prescan ────────┐
            │  Bandit + Semgrep + Gitleaks + OSV    │  Semaphore(5), per-scanner 120s timeout
            │  (parallel, non-fatal on per-scanner  │  → findings[source=<scanner>]
            │   crash, BOM persisted eagerly)       │
            └──────────────┬───────────────────────┘
                           │ findings non-empty?
                           ▼
                  ╔════════════════════╗
                  ║ pending_prescan_   ║ ← interrupt() — operator gate
                  ║   approval         ║   (24h auto-decline sweeper)
                  ╚════════════╤═══════╝
                               ▼
                       ┌───────────────┐
                       │ estimate_cost │ ← interrupt() — cost gate
                       └───────┬───────┘   (LiteLLM dry-run; sums all agent×file×chunk)
                               ▼
        ┌─────── analyze_files_parallel ─────────┐
        │  Semaphore(5) over agents × files       │  Single-pass; no topo ordering
        │  Each agent: RAG → LLM(structured)      │  <UNTRUSTED_SCANNER_FINDINGS> data block
        │   → CWE-RAG → snippet-verify (4-retry)  │  → findings[source=agent]
        └──────────────┬──────────────────────────┘
                       ▼
              ┌────────────────────┐
              │ correlate_findings │  Dedupe by (file, cwe, line); corroborating_agents
              └─────────┬──────────┘
                        ▼
        ┌───── consolidate_and_patch ──────┐  REMEDIATE-only (else no-op)
        │  Per-file conflict resolution    │  Single-shot merge agent on overlaps
        │  Tree-sitter syntax check        │  Sequential per-file
        │  Single-pass replace             │
        └──────────────┬───────────────────┘
                       ▼
              ┌────────────────┐
              │ verify_patches │  REMEDIATE-only; re-runs Semgrep on patched_files
              └────────┬───────┘  → fix_verified True/False (only Semgrep findings)
                       ▼
                ┌──────────────────┐
                │ save_results +   │
                │ save_final_report│
                └──────────────────┘
```

### Twelve gaps mapped to axes

The full list is in `discovery §L`. Mapped onto three intervention axes:

| # | Gap | Template | Skill | Workflow |
|---|---|---|---|---|
| 1 | Same template per language (Python, Go, Java, etc.) | **Y** | | |
| 2 | Same template per agent / per finding-type domain | **Y** | | |
| 3 | Prescan findings = ground truth, not hypotheses | | **Y** | |
| 4 | Merge agent single-shot, no negotiation (`consolidate.py:131`) | partial | partial | **Y** |
| 5 | Fix-verification only for Semgrep findings | | partial | **Y** |
| 6 | No agent retry on transient LLM failures | | | **Y** |
| 7 | Cost estimate dry-run only, no per-agent caps | | | **Y** |
| 8 | Agents don't adapt behaviour based on prescan flags | | **Y** | |
| 9 | RAG silently degrades on empty / outage | | partial | **Y** |
| 10 | Semgrep rules not framework-filtered (irrelevant rules execute) | | | **Y** |
| 11 | Audit/remediate split is implicit (node self-short-circuit) | | | **Y** |
| 12 | No per-agent wall-clock SLA | | | **Y** |

That distribution is the empirical answer to the strategic question: most gaps are workflow plumbing or template content — neither is a skill question. A genuine subset (3, 8, partially 5) wants real skills.

---

## 3. Strategic decision — templates, skills, or hybrid?

### 3.1 Definitions in SCCAP context

This question gets confused when people import abstract definitions from elsewhere (Claude Code's skill system, AutoGPT-style agents, ReAct loops). The right question is: *what does each term mean in SCCAP's existing pipeline?*

- **Prompt template** in SCCAP = a row in `prompt_templates` (one `QUICK_AUDIT` + one `DETAILED_REMEDIATION` per agent), loaded by `prompt_template_repo.get_template_by_name_and_type` (`prompt_template_repo.py:44-89`), rendered via `str.format()` with three placeholders (`{vulnerability_patterns}`, `{secure_patterns}`, `{code_bundle}`). The variant column gates anthropic-tuned vs generic. Today's path. Cost-predictable, dry-runnable, fully covered by Promptfoo.
- **Agent skill** in SCCAP would be = a parameterised, server-side callable the LLM can invoke during its turn. The most useful candidates surfaced by the audit:
  - `validate_prescan_finding(finding_id) → {confirms, refutes, refines}`
  - `query_dependency_tree(file_path, depth=N) → list[Symbol]`
  - `run_targeted_scan(file_path, ruleset) → list[VulnerabilityFinding]`
  - `re_query_rag(keywords, framework_filter) → list[Pattern]`
  - `fetch_cve_advisory(cve_id) → AdvisoryDoc`
  Each skill has a Pydantic input schema, a typed return, and a token/latency cap. The agent loop becomes `template → maybe-skill-call → maybe-skill-call → final-structured-output`.
- **Hybrid** = templated baseline (deterministic per-call structure, dry-runnable cost estimate, Promptfoo-covered) + a small registry of skills the agent invokes only when the templated path is insufficient. The skill registry is *enumerated and gated* — not a free-form tool palette.

### 3.2 Decision matrix

| Dimension | Templates only (today) | Skills only | **Hybrid (skills-augmented)** |
|---|---|---|---|
| Determinism | High — fixed control flow | Low — agent decides loop length | Medium — skills bounded by registry |
| Token cost | Predictable (dry-runnable) | Variable, can spiral | Tiered: baseline known, skills budgeted per-call |
| Cost-approval gate (`estimate_cost_node`) | Aligned | **Breaks dry-run** — agent decides skill calls at runtime | Preserved with per-skill token caps + a skill-call ceiling per scan |
| Failure modes | Misclassification, false negatives | Tool-orchestration runaway, prompt-injection-via-skill-args, infinite loops | Same as templates baseline + bounded skill failures (budget exhausts → fallback to template-only path) |
| Promptfoo eval coverage | Covered | Hard — combinatorial explosion of skill-call traces | Covered for baseline; per-skill mocks extend the suite |
| Implementation complexity | Lowest (touched today) | Highest (new tool-call infra, new schemas, new safety gates) | Medium (build the registry incrementally, one skill at a time) |
| Backward-compat with existing `PromptTemplate` rows | N/A | Migration risk | Compatible — templates remain canonical; skills are additive |
| Risk of prompt injection via attacker-controlled file content | Already mitigated by `<UNTRUSTED_SCANNER_FINDINGS>` data block | Higher — skill arguments may be derived from attacker text; need argument validation | Same as templates if skill arguments are constrained to typed enums / IDs / hashes; do NOT pass free-form attacker text into skill arguments |
| Fit for `LITELLM_LOCAL_MODEL_COST_MAP=True` | Yes | Yes | Yes |
| Fit for the prescan-cost-approval cadence (operator approves once, then runs) | Native | Misaligned (skills add round-trips operator didn't approve) | Native if total skill-budget is part of the cost estimate |
| Compatibility with Pydantic AI structured output | Native | Native (Pydantic AI supports tools) | Native (skills are tools with typed Pydantic schemas) |
| Fit for the eval-coverage-gap concern (DeepSeek/Grok unevaluated) | Existing problem | Worse (more surface) | Same as templates baseline; per-skill prompts get their own eval rows |

### 3.3 Recommendation: hybrid

**Go hybrid, but build it conservatively.** The recommendation rests on three load-bearing observations:

1. **The cost-approval gate is non-negotiable.** SCCAP's value proposition includes "no LLM spend before operator review." A pure-skills design where the agent decides at runtime how many tool calls to make breaks the dry-run estimate — every scan becomes a probabilistic spend, not a quoted one. Hybrid preserves the gate by:
   - Including a **skill budget** (e.g. `skill_token_ceiling_per_scan = 50_000`, `skill_call_count_per_scan = 20`) in the cost estimate.
   - Treating skills as *opt-in* per-agent: an agent's prompt template declares whether it can call skills, and the cost estimate runs the dry-run *with* the skill budget pre-allocated.
   - When the budget exhausts mid-scan, the agent falls back to the template-only path; spend is bounded by the operator's pre-approval.

2. **The 12 gaps split cleanly.** Most don't want skills. Per-language templates (gap 1) is a content change. Agent retry (gap 6) is a workflow guardrail. Per-agent cost caps (gap 7) is a cost-estimator extension. Genuine skill candidates are: prescan-validation (gaps 3, 8), targeted re-scanning (gap 5 and partly extended verification), dependency-tree query (a future cross-file fix coordinator). That's three to five skills, not a bazaar.

3. **The Pydantic AI + LiteLLM stack already supports tool calling natively.** Implementing a skill is implementing a Pydantic input model, a server-side function, and registering it on the `Agent`. We don't need new infrastructure — we need a *registry pattern* and a *budget enforcer*. (Concretely: a `SkillRegistry` keyed by skill name with `{schema: Type[BaseModel], handler: Callable, token_ceiling: int, call_ceiling: int}` per entry; injected into `LLMClient.generate_structured_output` as an optional `tools=[...]` argument.)

**Risks of the hybrid path:**

- **Prompt injection via skill arguments.** If a skill takes a `keyword: str` argument and the agent derives it from attacker-controlled scanned text, the skill could be hijacked into making malicious external requests. **Mitigation:** every skill schema MUST use typed enums / UUIDs / hashes, NOT free-form strings. `validate_prescan_finding(finding_id: UUID)` is safe; `re_query_rag(keywords: str)` is not. Where free text is unavoidable, run it through `infrastructure/observability/mask.py` first (the redactor already used for Langfuse).
- **Eval coverage gap widens.** Promptfoo today covers prompt → structured output. Skills add `prompt → skill_call → skill_response → final_output`. Each skill needs its own eval row mocking the handler. **Mitigation:** for every new skill, ship a Promptfoo test row in the same PR. Make this a verifier gate.
- **Token cost overrun.** Skill round-trips are real LLM calls. Even with caps, complex agents could blow through budgets. **Mitigation:** the per-scan skill budget is part of the cost estimate; budget exhaustion ⇒ degrade to template-only path with a `WARN` in the LLMInteraction trace.
- **Operational complexity.** Skills are a new failure surface (timeouts, network errors, type mismatches). **Mitigation:** every skill handler runs under a `try/except` with a structured fallback; skill failures emit a warning finding rather than failing the agent.

**What hybrid does NOT mean:**
- It does not mean ripping out the template system. Templates remain the canonical contract. Skills are additive.
- It does not mean a free-form ReAct loop. The agent is constrained to the registered skills with hard call/token ceilings.
- It does not mean abandoning Promptfoo. The eval suite extends to cover skill-augmented prompts.
- It does not mean breaking backward-compat. Existing `PromptTemplate` rows remain valid and load as-is.

---

## 4. Prioritised improvements

Severity scale: **High** = directly impacts scan quality or cost predictability; **Medium** = improves UX or covers an edge case; **Low** = hygiene. Effort scale: **S** = ≤1 PR, **M** = 2–3 PRs, **L** = 4+ PRs or needs an ADR.

### 4.1 P0 — this quarter (highest leverage, lowest risk)

| # | Gap | Severity × Effort | Why now |
|---|---|---|---|
| **1** | **Per-agent + per-language prompt templates** (gaps 1, 2) | High × M | Today every agent runs the same `audit.md` regardless of agent domain or file language. RAG patterns provide some specificity, but the prompt structure is rigid. Splitting into per-agent templates (with a small set of `[language]` blocks within each) addresses the single most impactful quality gap. Fully template-axis; no skill infra needed. |
| **2** | **Agent-level retry with exponential backoff** (gap 6) | High × S | Pydantic AI handles schema retries (transparent). Network/timeout errors today silently lose findings. Add 2-attempt retry with 1s/4s backoff in `LLMClient.generate_structured_output`. ~30 LOC + a test. |
| **3** | **Per-agent cost caps + granular token tracking** (gap 7) | High × M | The cost estimate today is a single global number. If one agent over-runs (e.g. due to a long file or chatty model), there's no early-warning signal. Extend `estimate_cost_for_prompt` to emit a per-agent breakdown; add a `Scan.per_agent_cost_ceiling` column; abort the agent run if exceeded. Sets the foundation for the skill-budget extension in P1. |

These three together close roughly 40% of the quality gap surfaced by the audit, all without introducing skills.

### 4.2 P1 — next quarter (skills land here)

| # | Gap | Severity × Effort | Why this sequence |
|---|---|---|---|
| **4** | **Prescan-validation skill** (gaps 3, 8) | High × L | This is the first real skill in SCCAP. The agent receives a `<UNTRUSTED_SCANNER_FINDINGS>` block and can call `validate_prescan_finding(finding_id) → {confirms, refutes_with_reason, refines_with_extra_context}`. Closes the "ground truth vs hypothesis" gap (3) and gives the agent a way to focus its analysis (8). Requires the cost-cap infra from P0. Needs an ADR. |
| **5** | **Multi-turn merge agent** (gap 4) | Medium × M | Today `_run_merge_agent` is single-shot (`consolidate.py:131-133`). On failure → fallback to highest-priority fix. Extend to 2-attempt retry where the retry includes the syntax-check failure or spec violation as feedback. ~80 LOC change, contained to `consolidate.py`. |
| **6** | **Extended fix verification** (gap 5) | Medium × M | Today `verify_patches_node` re-runs Semgrep only. Extend to re-run Bandit (cheap; already in the prescan path) and OSV (only if dependency files changed) over `patched_files`. Sets `fix_verified` for findings beyond Semgrep. Closes the most-asked operator question: "did the LLM's refactor actually close my OSV advisory?" |

By the end of P1, SCCAP has its first skill, retry semantics are first-class, and verification covers three of four scanner sources.

### 4.3 P2 — backlog (file as `/sccap`-able units)

| # | Gap | Severity × Effort | Note |
|---|---|---|---|
| 7 | RAG fallback policy (gap 9) | Medium × S | One admin config flag (`rag_fallback_mode: fail|degrade|warn`) + a propagation through `_build_rag_context`. |
| 8 | Framework-filtered Semgrep (gap 10) | Medium × M | Match Semgrep rule packs to the active framework set (e.g. only run `p/owasp-llm-top10` rules when the LLM Top-10 framework is selected). Needs DB schema for rule-pack ↔ framework mapping. |
| 9 | Explicit audit/remediate graph branching (gap 11) | Low × S | Cosmetic — split the implicit no-op into explicit edges. Improves Langfuse trace clarity. |
| 10 | Per-agent wall-clock SLA (gap 12) | Medium × S | `asyncio.wait_for(agent_call, timeout=PER_AGENT_TIMEOUT_SECONDS)` with circuit-breaker. ~40 LOC. |

### 4.4 Out of scope (not on the roadmap)

- **A Claude-Code-style "skills" subsystem with arbitrary user-defined skills.** SCCAP's skills are a curated registry, not user-extensible. User-extensibility belongs in a future product surface, not the scan agent.
- **A ReAct loop with arbitrary tool selection.** The hybrid recommendation explicitly forbids this.
- **Replacing Pydantic AI with a different agent framework.** The audit found no functional gap that motivates a framework change. Pydantic AI's structured-output retry is exactly the contract we want.
- **Custom Semgrep rule pack authoring (already filed in `.agent/features.md`).**
- **Per-tenant `.gitleaksignore` (already filed).**

---

## 5. Implementation roadmap

Each phase below should be one or more `/sccap` runs. Phase A unblocks Phase B (the skill registry needs cost caps); B unblocks C; D is independent and can be picked up in parallel.

### Phase A — Template + workflow foundation (P0, 3 `/sccap` runs)

- **Run A1** — Per-agent / per-language prompt templates. New `PromptTemplate.language_filter` column + Alembic migration; `prompt_template_repo.get_template_by_name_and_type` extended with optional `language` arg; per-agent audit.md / remediation.md broken out into `seed_prompts/<agent>/audit.md` etc.; backfill for existing rows. ADR justified (template-resolution semantics change).
- **Run A2** — Agent retry with backoff. Pure `LLMClient` change; one test.
- **Run A3** — Per-agent cost caps. New `Scan.per_agent_cost_ceiling: float` column; cost estimator emits per-agent breakdown; abort logic in `analysis_node`.

### Phase B — Skill registry (P1 lead, 1–2 runs + ADR)

- **Run B1** — Skill registry primitive. ADR: "Skill registry — bounded tool-calling for SCCAP agents." Implements `SkillRegistry`, the budget enforcer, the Pydantic schema convention, the Promptfoo extension, and one minimal-viable skill: `validate_prescan_finding`. Per-skill eval row required at PR time.
- **Run B2** — Multi-turn merge agent (gap 4). Extends `_run_merge_agent` with retry-on-failure and structured feedback into the retry prompt.

### Phase C — Verification expansion (P1 tail, 2 runs)

- **Run C1** — Bandit re-run in `verify_patches_node` for Bandit-derived applied fixes.
- **Run C2** — OSV re-run conditional on dependency file changes; `fix_verified` for OSV findings.

### Phase D — Hardening (P2 — picked up opportunistically)

- **Run D1** — RAG fallback policy.
- **Run D2** — Framework-filtered Semgrep + rule-pack ↔ framework mapping.
- **Run D3** — Explicit audit/remediate graph edges.
- **Run D4** — Per-agent wall-clock SLA + circuit-breaker.

### Sequencing guard-rail

Do not start Phase B until Phase A's per-agent cost caps land. Do not start Phase C until at least one skill (B1) is in production for a sprint, since skill telemetry will inform what verification skills look like.

---

## 6. Risks and open questions

1. **Eval-suite extension is a prerequisite, not an afterthought.** Promptfoo today covers functional regressions only (`evals/README.md` "Coverage gap, explicit"). Phases A and B both expand the prompt surface; the verifier gate should fail any PR in those phases that doesn't ship matching eval rows. **Action item:** before starting Run A1, file a sub-run that *strengthens the eval gate* to block on missing prompt coverage.

2. **Backward-compat with existing `PromptTemplate` rows.** Adding `language_filter` is additive and reversible, but the seed migration (per-agent audit.md → `seed_prompts/<agent>/audit.md`) is a content reshuffle. Operators with custom-edited `prompt_templates` rows in production must be flagged. **Action item:** Run A1's plan must include an admin-UI export-then-merge tool, and an Alembic data-migration that preserves operator overrides.

3. **Token cost of hybrid is real.** Each skill round-trip is a real LLM call. A pessimistic estimate: 5 skill calls × 2k tokens = 10k extra tokens per agent; with 18 agents × 10 files = 1.8M extra tokens per scan, materially shifting cost. **Mitigation:** the per-skill ceilings + per-scan skill budget make this bounded; the cost estimate transparently includes them; operators see the inflated number at the cost-approval gate and approve/decline accordingly.

4. **OWASP LLM Top-10 / Agentic Top-10 redteam pack is a separate, unbudgeted track.** Skills introduce new prompt-injection surfaces (skill argument coercion, skill-response prompt injection, skill-loop infinite-call attacks). The redteam pack is currently deferred (CLAUDE.md). **Action item:** before Run B1 ships, schedule the redteam pack as a parallel `/sccap` run; do not ship any skill into production until at least the L01-injection and A05-tool-misuse cases are covered.

5. **Operator ergonomics.** Today the cost-approval card shows a single "estimated cost" number. Per-agent cost caps + skill budget add complexity. **Mitigation:** the UI changes lag the backend by one phase — Phase A's cost-cap rollout can land with a flat single-number UX; the per-agent breakdown lands in Phase D when telemetry justifies it.

6. **DeepSeek / Grok eval gap (already noted).** New providers add to the prompt-template variant matrix. Until those models are in the eval suite, the per-language template work in Run A1 is generic-only — no Anthropic-tuned variants for DeepSeek/Grok.

7. **The "agent skills" name will collide with the `Skill` tool in the Claude Code harness.** This doc uses "skill" to mean SCCAP's runtime tool-callables; readers from the harness side may confuse it with the slash-command-style skills. **Action item:** when Run B1 lands, name the registry artifact `AgentTool` or `AgentCallable`, NOT `Skill`. Keep "skill" as an informal term in user-facing docs only.

---

## 7. Appendices

### A. Evidence cross-reference

| Section | Evidence |
|---|---|
| Pipeline shape | `worker_graph.py:126-275`; `analyze.py:35-230`; `consolidate.py:300-428`; `verify.py:59-158` |
| Prompt templates | `default_seed_service.py:430-473`; `prompt_template_repo.py:44-89`; `seed_prompts/{audit,remediation,chat}.md`; `generic_specialized_agent.py:101-104,464-487` |
| Scanners | `registry.py:78-94`; `prescan.py:59-194`; per-runner files `bandit_runner.py`, `semgrep_runner.py`, `gitleaks_runner.py`, `osv_runner.py` |
| Correlate / consolidate / verify | `correlate.py:15-76`; `consolidate.py:75-190,300-428`; `verify.py:59-158` |
| Cost estimate | `cost_estimation.py:61-140`; `cost.py:40-136` |
| RAG | `infrastructure/rag/{base.py,rag_client.py,qdrant_store.py,embedder.py}`; `generic_specialized_agent.py:183-241,271-383` |
| Eval suite | `evals/promptfooconfig.shared.yaml`; `scripts/extract_eval_prompts.py`; `.github/workflows/evals.yml`; `evals/README.md` |
| Auth/visibility (constraints) | `dependencies.py:get_visible_user_ids`; `shared/lib/scan_scope.py` |

### B. Sketch — what a skill looks like in code

```python
# src/app/infrastructure/agents/skills/registry.py
class AgentTool(BaseModel):
    name: str
    schema: Type[BaseModel]      # Pydantic input model
    handler: Callable[[BaseModel, ToolContext], Awaitable[BaseModel]]
    token_ceiling: int           # Per-call max output tokens
    call_ceiling_per_scan: int   # Hard cap per scan_id

class SkillRegistry:
    _tools: Dict[str, AgentTool] = {}

    @classmethod
    def register(cls, tool: AgentTool) -> None: ...

    @classmethod
    def for_agent(cls, agent_name: str) -> List[AgentTool]:
        # Per-agent allowlist comes from PromptTemplate.skills_allowlist (new column)
        ...

# src/app/infrastructure/agents/skills/validate_prescan_finding.py
class ValidatePrescanFindingInput(BaseModel):
    finding_id: UUID  # NOT free-form text — typed ID

class ValidatePrescanFindingOutput(BaseModel):
    verdict: Literal["confirms", "refutes", "refines"]
    reason: str  # Free-form, but redacted by mask.py before logging

async def handler(
    input: ValidatePrescanFindingInput, ctx: ToolContext
) -> ValidatePrescanFindingOutput:
    finding = await ctx.scan_repo.get_finding(input.finding_id)
    if finding.scan_id != ctx.scan_id:
        raise PermissionError("Cross-scan finding lookup")
    # ... LLM call to a smaller reasoning model with the finding + file context
    ...

SkillRegistry.register(AgentTool(
    name="validate_prescan_finding",
    schema=ValidatePrescanFindingInput,
    handler=handler,
    token_ceiling=2_000,
    call_ceiling_per_scan=20,
))
```

Note: `ctx.scan_id` is enforced cross-scan; argument types are typed UUIDs not free-form strings; the handler asserts ownership before dispatching the LLM call. These are the patterns every skill must follow.

### C. ADRs to file (during P1)

- **ADR — Skill registry: bounded tool-calling for SCCAP agents.** Documents the registry pattern, the budget enforcer, the prompt-injection mitigations, and the eval-extension contract.
- **ADR — Per-agent prompt template variants.** Documents the new `PromptTemplate.language_filter` column, the resolution order (`(agent, language, variant) → (agent, language, generic) → (agent, generic) → legacy`), and the operator-override preservation strategy.

---

**End of analysis.** This doc is the input artifact for the four follow-up `/sccap` runs in §5. Each will frame its own goal from this list; this doc does not prescribe their threat models or plans — those phases run when the individual `/sccap` runs invoke them.
