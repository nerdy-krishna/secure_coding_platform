"""Canonical agent prompt templates.

The three text files in this package (`audit.md`, `remediation.md`,
`chat.md`) are the source of truth for the prompt strings the worker
runs. `default_seed_service.py` loads them at module load via
`importlib.resources` so the seed code stays small and the prompts
can be diffed in isolation.

The eval extractor at `scripts/extract_eval_prompts.py` re-imports
the loaded constants (`_AUDIT_TEMPLATE`, `_REMEDIATION_TEMPLATE`,
`_CHAT_TEMPLATE`) from `default_seed_service` so it stays unaffected
by the file move.
"""
