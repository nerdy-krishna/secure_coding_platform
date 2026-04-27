# Security review — close-disk-fill-class

**Scope:** Independent review of the disk-fill closure change set on `main` (unstaged + new untracked files). Verifies the 9 mitigations from `close-disk-fill-class-threat-model.md` actually shipped, plus a project-aware pass.

**Time budget:** 240 s. Hit ~150 s.

---

## 1. Threat-model mitigation verification

| ID | Mitigation | Landed? | Citation |
|---|---|---|---|
| P1-R1 | Reroute `db` and `ui` stdout through `driver: fluentd` so security-relevant events land in Loki under retention | YES | `docker-compose.yml:71-79` (db, `tag: docker.db.{{.Name}}`), `docker-compose.yml:466-475` (ui, `tag: docker.ui.{{.Name}}`). Both use `fluentd-async: "true"` + bounded `fluentd-max-retries: "30"`. `depends_on.fluentd: service_healthy` set on both (db at L63-65; ui at L460-465 converted from list-form per plan). |
| P2-E1 | `setup.sh` JSON-merges via `python3` heredoc, never `>` overwrites; writes `.bak.sccap-<ts>`; uses `install -m 0644 -o root -g root` | YES | `setup.sh:243-281` (`_sccap_render_daemon_json` heredoc reads `DAEMON_EXISTING` env, validates JSON, only adds keys if absent — never clobbers operator's existing `log-driver`); `setup.sh:325-332` (`.bak.sccap-$(date +%s)` via `cp -a` before mutation); `setup.sh:333-334` (`install -m 0644 -o root -g root` atomic replace). The python heredoc is **single-quoted** (`<<'PY'`) so no shell-side variable interpolation; the file content rides via env (`DAEMON_EXISTING="$existing"`), not via shell substitution into the heredoc body. |
| P2-E2 | EUID==0 vs sudo-available vs neither; `type YES` confirmation acknowledging daemon-restart blast radius | YES | `setup.sh:228-241` (`_sccap_with_root` three-branch detection — direct argv, then `sudo "$@"` argv, then prints commands and `return 1`); `setup.sh:289-297` (interactive prompt mentions "restarts the Docker daemon and will recreate ALL containers on this host (not just SCCAP)" + `read -p "    Apply now? (type YES to confirm, anything else skips): "`). |
| P3-R1 | `drop_oldest_chunk` surfaces `BUFFER_OVERFLOW` event in Loki via `<label @ERROR>` + `record_transformer` regex match | YES | `fluentd/fluentd.conf:1-5` (`<system> log_level info`); `fluentd/fluentd.conf:60-65` (`<buffer>` block: `total_limit_size 2GB`, `overflow_action drop_oldest_chunk`, `retry_max_times 600`, `retry_type periodic`); `fluentd/fluentd.conf:75-90` (`<label @ERROR>` with `record_transformer enable_ruby` + regex `BufferOverflowError|drop_oldest_chunk|chunk bytes limit exceeds` → tags `service_name=fluentd-internal level=ERROR event=BUFFER_OVERFLOW` + routes to `@type stdout`). |
| P4-R1 | `LOKI_RETENTION_DAYS` operator-tunable; `.env.example` documents PCI/HIPAA trade-off | YES | `loki/loki-config.yaml:55` (`retention_period: ${LOKI_RETENTION_DAYS:-30d}`); `docker-compose.yml:212-215` (`-config.expand-env=true` flag + `environment: [LOKI_RETENTION_DAYS=${LOKI_RETENTION_DAYS:-30d}]`); `.env.example:67-76` (compliance comment + `LOKI_RETENTION_DAYS=30d`). |
| P5-T1 | Sidecar locally-built (not public-image), `read_only: true`, `cap_drop: [ALL]`, `/:/host:ro`, mountpoint allowlist enforced in `emit.sh` | YES | `tools/df-emitter/Dockerfile:7` (`FROM busybox:1.37` local build, runs as `USER 65534:65534`, ENTRYPOINT to script); `docker-compose.yml:482-509` (`build: ./tools/df-emitter`, `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `user: "65534:65534"`, `volumes: [/:/host:ro]`); `tools/df-emitter/emit.sh:27,35-38` (allowlist via `DF_MOUNTPOINTS` default `/host /host/var/lib/docker`, non-allowlisted are silently skipped via `for mp in $MOUNTS; do … if [ ! -d "$mp" ]; then continue; fi`). |
| P5-I1 | Interval ≥ 30 s default, refuses < 10 s; `service_name=disk-monitor` tag; runbook recommends `GF_AUTH_ANONYMOUS_ENABLED=false` | YES | `tools/df-emitter/emit.sh:21-25` (`INTERVAL=${DF_INTERVAL_SECONDS:-30}` with hard `[ "$INTERVAL" -lt 10 ]` → `exit 2`); `tools/df-emitter/emit.sh:56` (`"service_name":"disk-monitor"` in JSON payload); `.agent/runbooks/disk-fill.md:165-174` (§8 "Production-hardening reminder" recommends flipping the env var). |
| R8 | `.agent/project_structure.md` gains "Logging architecture" section | YES | `.agent/project_structure.md:200-239` — new section covers per-service driver matrix, fluentd buffer caps + BUFFER_OVERFLOW signal, Loki retention with `LOKI_RETENTION_DAYS`, host-disk visibility, daemon-wide fallback (setup.sh §2.7), RabbitMQ overflow, runbook pointer. |
| R9 | Operator runbook with HOST/CONTAINER demarcation, Loki outage recovery, first-compactor I/O spike, retention trade-off, daemon.json rollback, recent incident replay, anonymous-viewer recommendation | YES | `.agent/runbooks/disk-fill.md` (184 lines): §1 triage, §2 quick reclaim, §3 Loki outage, §4 compactor cycle, §5 retention compliance, §6 daemon.json rollback, §7 April-2026 incident replay, §8 GF_AUTH_ANONYMOUS_ENABLED=false. Banner convention "every command is prefixed by either `# === HOST ===` or `# === CONTAINER ===`" enforced throughout. |

**All 9 required mitigations landed.**

---

## 2. SCCAP-specific gates

| Gate | Status | Notes |
|---|---|---|
| `get_visible_user_ids` on new list endpoints | N/A | No API endpoints touched. |
| Secrets handling (Fernet) | PASS | No secret fields introduced. Confirmed `rabbitmq/definitions.json` carries empty `users: []` / `permissions: []` arrays — only a policy rule. `rabbitmq/rabbitmq.conf` carries only `load_definitions = /etc/rabbitmq/definitions.json`. No plaintext credentials. |
| Worker-graph interrupt/resume | N/A | `infrastructure/workflows/worker_graph.py` untouched. |
| `.env.example` clean | PASS | Sole addition is `LOKI_RETENTION_DAYS=30d` (non-secret, parallel to existing `LANGFUSE_TRACE_RETENTION_DAYS`). No new `OPENAI_API_KEY` / `GOOGLE_API_KEY` placeholders. |
| LiteLLM routing | N/A | No LLM calls. |
| Migrations reversible | N/A | No alembic migrations. |
| CORS via `SystemConfigCache` | N/A | `main.py` untouched. |
| Conventional commit + no Claude trailer | NOTE for orchestrator | Plan and threat-model both already call this out. Nothing committed yet. |

---

## 3. Special-focus deep dives

### 3.1 `setup.sh` python-merge injection vector

**Verdict: SAFE.**

- Heredoc is `<<'PY'` (single-quoted) — shell does not perform variable substitution inside, so no metacharacter from `$existing` reaches the python source.
- Existing-file content is passed via `DAEMON_EXISTING="$existing" python3 - "$out_path" <<'PY'` — i.e. as an environment variable, not interpolated into the script body. Python reads it through `os.environ.get("DAEMON_EXISTING", "{}")` and parses with `json.loads()`. Worst case: malformed JSON → `JSONDecodeError` → exit 2 → caller skips with "render failed" message. No code execution path.
- The output filename arrives via `sys.argv[1]` which is the shell-quoted `"/tmp/sccap-daemon.json.$$"` — bash substitutes `$$` (PID) safely.
- All `_sccap_with_root` calls are argv-style (`_sccap_with_root cat /etc/docker/daemon.json`, `_sccap_with_root install -m 0644 …`, `_sccap_with_root systemctl restart docker`, `_sccap_with_root cp -a …`, `_sccap_with_root test -f …`). No string concatenation of operator input into a `sudo` command line.
- `cat /etc/docker/daemon.json` requires root or readable perms; on a hardened host where `daemon.json` is `0600 root:root`, the cat call may itself need `_sccap_with_root cat`. **The code already handles this**: `existing=$(_sccap_with_root cat /etc/docker/daemon.json)` (`setup.sh:251`). Good.

### 3.2 `tools/df-emitter/emit.sh` injection / parser robustness

**Verdict: SAFE WITH ONE LOW-SEVERITY OBSERVATION.**

- `DF_MOUNTPOINTS` is iterated via `for mp in $MOUNTS` — word-split by whitespace. Shell metacharacters in the env (`;`, `&`, backticks) would split into additional tokens but each token is then **only used as `df -P "$mp"` (quoted argv) and `[ ! -d "$mp" ]` (quoted)**. No `eval`, no command substitution on the value. **Not exploitable.**
- `cut -d, -f1` parses `awk` output that's already been normalised to `pct,used,avail` form via `gsub("%","",$5); print $5","$3","$4`. If `df` output is malformed `awk NR==2` returns empty → `[ -z "$line" ] && continue` skips emit. Safe.
- The `printf … | nc -w 1 "$HOST" "$PORT" || true` — values come from `df` (numeric) and `mp` (env). Mountpoint with shell metacharacters would land literally inside the JSON quotes. `printf '%s'` would be safer than the embedded-`%s`-in-format-string pattern (LOW: a mountpoint containing `%` would corrupt the printf format). In practice `DF_MOUNTPOINTS` is operator-controlled and limited to filesystem paths from `df` output, so risk is theoretical.

**Finding:** `tools/df-emitter/emit.sh:56` — `printf` uses `%s` for `host_mp` inside a single format string. A pathological mountpoint containing `%` characters could mis-format the JSON. **Not exploitable** (operator controls input, df output is numeric for the other fields). LOW severity, follow-up.

### 3.3 fluentd `<label @ERROR>` regex ReDoS

**Verdict: SAFE.**

`record["message"].to_s.match?(/BufferOverflowError|drop_oldest_chunk|chunk bytes limit exceeds/)` — pure literal alternation, no nested quantifiers, no `(a+)+`-style backtracking. Ruby's `match?` returns boolean without populating `MatchData`, optimal cost. Input is bounded by fluentd's own internal-error message size. Catastrophic backtracking impossible by construction.

### 3.4 docker-compose `disk-monitor` privilege envelope

**Verdict: SAFE.**

- `read_only: true` + `cap_drop: [ALL]` + `security_opt: [no-new-privileges:true]` + `user: "65534:65534"` + `/:/host:ro` (read-only bind). Container cannot write the host. Even with a busybox CVE, an attacker would need to (a) escape the container despite no caps and no-new-privileges, (b) gain write access despite the read-only mount.
- Information disclosure surface: `df` reports the *mountpoint path strings* (`/`, `/var/lib/docker`) plus the numeric fields. Mountpoint allowlist is enforced in `emit.sh` so paths like `/host/proc`, `/host/etc/shadow`, etc. are NOT enumerated. The two default paths (`/`, `/var/lib/docker`) are themselves not sensitive — they're just well-known directory names.
- **Operator caveat (already in runbook §8):** Grafana ships with `GF_AUTH_ANONYMOUS_ENABLED=true` in the dev compose default (`docker-compose.yml:237`). Anyone with viewer access to Grafana sees the disk-usage panels. The runbook documents the production-hardening flip. Not a code defect.

### 3.5 fluentd port exposure (24224)

**Verdict: PRE-EXISTING, OUT OF SCOPE.**

`docker-compose.yml:185-186` exposes fluentd's forward port on the host (`"24224:24224"` + UDP). All four `driver: fluentd` services use `fluentd-address: localhost:24224` (host-side address, since the Docker daemon performs the actual forward). The port is bound on `0.0.0.0` by Docker's default (no host IP prefix). On a host directly reachable from the internet, an attacker could inject forged log lines into Loki — already true before this PR. Out of scope; would require a separate ADR to bind `127.0.0.1:24224:24224`.

### 3.6 Loki `allow_structured_metadata` deviation from plan

**Verdict: BENIGN.**

Plan said `allow_structured_metadata: true`; landed as `false` (`loki/loki-config.yaml:58`) with an explanatory comment ("boltdb-shipper does not support structured metadata; tsdb does"). Verifier already accepted this; not a security issue.

### 3.7 RabbitMQ definitions credential check

**Verdict: SAFE.**

`rabbitmq/definitions.json` carries `"users": []` and `"permissions": []` (empty arrays). Only a single policy rule. No usernames, passwords, hashes, or secrets in the file. `rabbitmq/rabbitmq.conf` is just `load_definitions = /etc/rabbitmq/definitions.json`. Both mounted `:ro`. Clean.

### 3.8 `runbook_url: file:///workspace/.agent/runbooks/disk-fill.md`

**Verdict: COSMETIC DEFICIENCY (not a security finding).**

`grafana/provisioning/alerting/disk-alert.yaml:79,141,206` — `file://` URL is a placeholder; Grafana renders it as an unclickable annotation. No security risk, but the operator clicking the alert won't navigate. Already known. LOW severity, doc follow-up.

---

## 4. Generic security-review skill output (summary)

Internal SAST-style sweep over the diff:
- No injection sinks (`eval`, `exec`, dynamic SQL, `os.system` w/ user input).
- No hardcoded secrets / credentials added (verified against `.env.example` diff and `rabbitmq/definitions.json`).
- No weak crypto / deprecated TLS / disabled cert verification introduced.
- No new network listeners except the privileged read-only sidecar (already analysed in 3.4).
- Shell scripts (`setup.sh`, `emit.sh`) use quoted variable expansion, argv-form sudo, and bounded loops. The python heredoc uses single-quoted `<<'PY'` correctly.
- Container postures (read_only, cap_drop ALL, no-new-privileges, non-root UID) are textbook.

---

## 5. Findings table

| ID | Severity | Finding | Mitigation |
|---|---|---|---|
| F-1 | LOW | `tools/df-emitter/emit.sh:56` `printf` uses `%s` substitution where `mp`/`host_mp` is interpolated into the format string — theoretically a `%`-bearing mountpoint could mis-format. Not exploitable in practice (operator controls allowlist; df output for `/` and `/var/lib/docker` is numeric). | Follow-up: switch the `printf` to `printf '%s\n' "$json_payload"` or sanitise `host_mp` for `%` characters. |
| F-2 | LOW | `grafana/provisioning/alerting/disk-alert.yaml:79,141,206` — `runbook_url: file:///workspace/.agent/runbooks/disk-fill.md` is a placeholder; not navigable from Grafana UI. | Follow-up: replace with the production https URL once the runbook is published, or drop the field. |
| F-3 | INFO | `docker-compose.yml:185-186` fluentd port `24224` exposed on `0.0.0.0` — pre-existing, not introduced by this PR. Hosts directly internet-reachable could receive forged log injections. | Out of scope; separate ADR. |

No Critical, High, or Medium findings.

---

## Verdict

**APPROVE**

- Blocking findings: 0 Critical, 0 High, 0 Medium
- Follow-ups to file: 0 Medium, 2 Low (F-1, F-2). F-3 is pre-existing/out-of-scope.

All 9 mitigations from the threat model landed in the diff with verifiable code citations. Threat-model verdict ("APPROVE WITH MITIGATIONS") is fully discharged.

### Suggested append to plan's "Out of scope" section

- `tools/df-emitter/emit.sh` — switch the JSON-line `printf` to a `'%s\n'` form (or `awk`-printed JSON) so a mountpoint containing `%` cannot mis-format the output. (LOW)
- `grafana/provisioning/alerting/disk-alert.yaml` — replace placeholder `file:///workspace/.agent/runbooks/disk-fill.md` `runbook_url` with the production https URL once published. (LOW, doc)
- `docker-compose.yml:185-186` — bind fluentd forward port to `127.0.0.1:24224:24224` instead of `0.0.0.0` to prevent log injection from the public network. (Pre-existing; new ADR.)
