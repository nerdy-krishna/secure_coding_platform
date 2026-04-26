"""Deterministic SAST scanner wrappers invoked by the worker LangGraph
`deterministic_prescan` node before LLM agents run. Each wrapper:

- Receives a sandboxed file tree (`stage_files`); never touches paths
  supplied directly by the user.
- Invokes its scanner via `subprocess.run([...], shell=False, timeout=...)`
  with all arguments as a list and an explicit `--` separator before
  any user-derived value (M1).
- Pins its config to a bundled file so a malicious user-tree
  `.semgrepignore` / `.gitleaks.toml` cannot redirect behavior (M3).
- Truncates and HTML-escapes user-controlled scanner-message text
  before it lands in any `VulnerabilityFinding.description` so the
  downstream LLM agents see only sanitized data (M7).
"""
