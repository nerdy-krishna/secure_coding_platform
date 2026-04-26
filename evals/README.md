# SCCAP eval harness (Promptfoo)

This directory holds the Promptfoo-based regression suite for SCCAP's prompt templates. Every PR that touches an agent's prompt — directly or via the canonical seed in `src/app/core/services/default_seed_service.py` — runs these evals in CI to catch behavioural regressions before merge.

> **CI gate is warn-only.** The workflow uploads a results artifact and surfaces the diff but **does not block merges**. Once we have ~2 weeks of stable baselines, we'll flip to hard-block in a follow-up run.

## Coverage today

| Agent | Cases | What's exercised |
|---|---|---|
| `generic_specialized_agent` (worker analyzer) | 4 | SQL injection, XSS, auth-bypass, clean-code negative |
| `chat_agent` (advisor) | 3 | OWASP A03 explanation, false-positive triage, citation-required |

The other 12 specialized agents (CryptoAgent, AccessControlAgent, etc.) are added incrementally — see "Adding a new agent" below.

## Local run (mock, free)

```bash
cd evals
npm ci
npm test                    # both agent suites
npm run test:gs             # generic_specialized only
npm run test:chat           # chat only
```

The default provider is a deterministic JS mock at `providers/mock.js` — no LLM calls, no network, no cost. Mock-mode is what runs on every PR.

## Live run (real LLM, costs ~1¢)

The same eval suites can be run against a real model. **This is opt-in only — never auto-runs on a PR.**

In CI: open the **Actions → SCCAP Evals** workflow, click **Run workflow**, set `mode: live`. Requires the `OPENAI_API_KEY` secret in the repo settings (separate from anything in `.env` or `system_config` — the eval framework never touches SCCAP's runtime LLM keys).

Locally:

```bash
OPENAI_API_KEY=sk-... npx promptfoo eval \
  -c agents/generic_specialized/promptfooconfig.yaml \
  --provider openai:gpt-4o-mini
```

A typical full run costs ~1–2¢ on `gpt-4o-mini`. Cost scales linearly with case count and per-case prompt size.

## Adding a new agent

1. Edit `scripts/extract_eval_prompts.py` to materialise the agent's prompt from the seed.
2. Run `python scripts/extract_eval_prompts.py --write` to regenerate.
3. Create `agents/<agent_name>/promptfooconfig.yaml` mirroring the existing two.
4. Add `cases/*.yaml` files. **Synthetic data only — see G8 below.**
5. Run `npm test` locally; commit the new files.

## Adding a new case

Each case is a YAML file under `agents/<agent>/cases/`:

```yaml
description: One-line description of what this case pins
vars:
  agent_name: ValidationAgent
  language: python
  vulnerability_patterns: |
    Pattern: ... (the RAG-side context the runtime feeds in)
  secure_patterns: |
    ...
  code_bundle: |
    # the synthetic code snippet under analysis
assert:
  - type: javascript
    value: "(function(){ const out=JSON.parse(output); return /* boolean expression */; })()"
```

JS asserts MUST be a single-line expression that evaluates to a boolean. Multi-line YAML literal blocks (`|`) break Promptfoo's expression parser — wrap in an IIFE on one line.

## Rules (these are gate criteria; CI enforces)

### G7 — Mock provider sandbox

`providers/mock.js` MUST NOT use `process.env`, `fetch`, `http`, `https`, `child_process`, or `fs.write*`. The CI workflow greps for these tokens; introducing one fails the build. Rationale: a fork PR that tampers with the mock provider should not be able to exfiltrate secrets, write to disk, or open network sockets — even though the live eval keys are gated to `workflow_dispatch` only.

The grep is a baseline, not a sandbox. Determined obfuscation (e.g. `globalThis['proc'+'ess']['env']`, `Function('return process')()`, dynamic `require()` via a string-built name) bypasses it. Every diff to `mock.js` therefore requires reviewer approval — the grep catches accidental drift, the human catches intent.

### G8 — Synthetic data only

Eval `vars:` blocks MUST contain synthetic / public-domain examples only. Never paste real customer code, API keys, internal URLs, or any production data. The eval results land in CI artifacts; treat them as public.

### G9 — Redteam coverage gap

This eval suite catches **functional regressions** — does the prompt still produce the expected JSON shape and detect the obvious vulnerability? It does **not** cover OWASP LLM Top-10 / Agentic Top-10 prompt-injection or jailbreak attacks. The redteam pack is filed as a separate `/sccap` run and will live in a sibling `redteam/` directory when shipped. **"We have evals" ≠ "we have injection coverage."**

## Files

```
evals/
├── package.json                  # promptfoo pinned ~0.121.x
├── package-lock.json             # committed; CI uses `npm ci`
├── promptfooconfig.shared.yaml   # documentation-only shared fragment
├── providers/
│   ├── mock.js                   # sandboxed deterministic mock
│   └── live.config.yaml          # documentation for the live `openai:` builtin
├── agents/
│   ├── generic_specialized/
│   │   ├── promptfooconfig.yaml
│   │   ├── prompts/
│   │   │   ├── quick_audit.txt           # extracted from seed; do not hand-edit
│   │   │   └── detailed_remediation.txt  # extracted from seed; do not hand-edit
│   │   └── cases/
│   │       ├── python_sqli.yaml
│   │       ├── python_xss.yaml
│   │       ├── auth_bypass.yaml
│   │       └── clean_code.yaml
│   └── chat/
│       ├── promptfooconfig.yaml
│       ├── prompts/
│       │   └── chat.txt                  # extracted from seed; do not hand-edit
│       └── cases/
│           ├── owasp_a03.yaml
│           ├── false_positive_appeal.yaml
│           └── citation_required.yaml
└── README.md                     # this file
```

The CI workflow is at [`.github/workflows/evals.yml`](../.github/workflows/evals.yml). The prompt-extraction script that sources the canonical templates is at [`scripts/extract_eval_prompts.py`](../scripts/extract_eval_prompts.py).
