# Threat model — close-disk-fill-class

## Change context

- **Goal:** Close the disk-fill failure class across the SCCAP stack (P1 compose `logging:` caps, P2 host `daemon.json` write + Docker restart, P3 fluentd bounded retries + buffer cap + `drop_oldest_chunk`, P4 Loki 30 d retention, P5 host-disk Grafana alert via `df` sidecar) plus three architectural extras: RabbitMQ overflow policy, Docker-volume size monitoring, operator runbook.
- **Files in scope:** `docker-compose.yml`, `setup.sh`, `fluentd/fluentd.conf`, NEW `loki/loki-config.yaml`, NEW `grafana/provisioning/alerting/disk-alert.yaml`, `.env.example`, `.agent/project_structure.md`, optional `tools/df-emitter/Dockerfile`, NEW operator runbook.
- **Trust boundaries:** Operator → Docker host root (P2). Container → fluentd → Loki → Grafana (existing pipeline, modified semantics). NEW `df` sidecar → fluentd.
- **Auth surfaces touched:** Host root via `sudo` in setup.sh (new). No application-plane auth changes.

## STRIDE-lite

| Category | Status | Notes / Mitigation |
|---|---|---|
| Spoofing | PASS | No new identity surfaces. fluentd `<source>` already on `scpnetwork`; `df` sidecar publishes via existing forward protocol on the same private bridge. |
| Tampering | FLAG | (a) `df` sidecar image substitution → SHA-pin or local build (`busybox`/`alpine`). (b) Naive `>` overwrite of `/etc/docker/daemon.json` deletes operator's pre-existing keys (registry mirrors, custom data-root). Mitigation: JSON-merge via `python3 -c 'import json…'`, write `.bak` first, atomic replace. |
| Repudiation | FLAG | (a) **P3 `drop_oldest_chunk` deliberately discards chunks under sustained backpressure** — intentional audit gap. Mitigation: emit `BUFFER_OVERFLOW` line on overflow, alert in Grafana, document recovery via `docker compose logs fluentd`. (b) **P4 30 d Loki retention deletes >30 d data on first compactor cycle** — irreversible. Mitigation: `LOKI_RETENTION_DAYS` operator-tunable in `.env`; runbook calls out compliance trade-offs (PCI/HIPAA). (c) **P1 50 m × 5 = 250 MB cap on non-fluentd services enables rotate-out-evidence on `db`, `ui`** (security-relevant stdout). Mitigation: route `db` and `ui` through `driver: fluentd` so events land in Loki under 30 d retention, OR document forensic fallback (Postgres CSVlog from `postgres_data`). |
| Info-disclosure | FLAG | (a) `df` sidecar emits mountpoint paths into Loki; Grafana anonymous viewer is enabled today (compose line 192–193). Mitigation: allowlist mountpoints (`/`, `/var/lib/docker`), tag `service_name=disk-monitor`, recommend `GF_AUTH_ANONYMOUS_ENABLED=false` in runbook. (b) `daemon.json.bak` cleanup mirrors existing `.env.bak` cleanup pattern. |
| DoS | FLAG | (a) Whole change set is a DoS *mitigation*, but rotate-out window (R-c) lets attacker flood non-fluentd stdout to mask earlier events — same mitigation. (b) Bounded `retry_max_times 600 × 5s flush = ~50 min` retry window; Loki outages longer than that drop all subsequent logs. Mitigation: Grafana panel/alert for fluentd buffer fill % (or `BUFFER_OVERFLOW` count). (c) First compactor cycle on >30 d existing Loki data could spike I/O. Mitigation: runbook step "schedule upgrade in low-traffic window; monitor `docker stats sccap_loki`." (d) `df` sidecar must sleep ≥ 30 s between emits. |
| Elevation | FLAG | (a) **setup.sh adopts `sudo`** for the first time (P2). Existing `read -p` prompts (lines 111, 132, 147, 176) feed `sed` substitutions; with `sudo` in scope, shell-metacharacter injection becomes dangerous. Mitigation: (i) any `sudo` invocation uses fixed argv / heredoc, never interpolated operator input; (ii) detect `EUID==0` and skip `sudo`; (iii) if neither root nor `sudo`, print exact commands and exit non-zero — never silent-pass. (b) `daemon.json` ownership `root:root 0644` (default of `tee`). (c) Docker restart recreates **all** host containers including non-SCCAP — interactive `"type YES"` confirmation. (d) `df` sidecar mounts host root `/host:ro`, `cap_drop: [ALL]`. |

## Project-specific gates

| Gate | Status | Notes |
|---|---|---|
| New list endpoint takes `visible_user_ids = Depends(get_visible_user_ids)` | N/A | No API endpoints touched. |
| New secrets are Fernet-encrypted via `EncryptedSecret` | N/A | No secret fields. `daemon.json`, `loki-config.yaml`, fluentd buffer config are non-secret. |
| Worker-graph nodes preserve interrupt/resume contract | N/A | `infrastructure/workflows/worker_graph.py` untouched. |
| `.env.example` does NOT add LLM-key placeholders | PASS | `LOKI_RETENTION_DAYS` is non-secret (parallel to existing `LANGFUSE_TRACE_RETENTION_DAYS`, `NEXTAUTH_SESSION_MAXAGE`). |
| New LLM calls go through litellm | N/A | None. |
| Async alembic migrations | N/A | No migrations. |
| Doc-sync (`scanning_flow.md` + `project_structure.md`) | FLAG | `scanning_flow.md` unaffected. `project_structure.md` MUST gain a "Logging architecture" subsection (per-service driver matrix, fluentd buffer/drop semantics, Loki retention, runbook pointer). |
| Docker-only backend commands | FLAG (expected) | P2 `systemctl restart docker` and `tee /etc/docker/daemon.json` are host-side by definition. Operator runbook must demarcate HOST vs CONTAINER commands. |
| Conventional commit + no Claude co-author trailer | NOTE | Commit subject suggestion: `feat(observability): close disk-fill failure class` or `chore(ops): bound log volume across stack`. No `Co-Authored-By: Claude` trailer per memory note. |

## Abuse cases

1. **Rotate-out-evidence on a non-fluentd service.** Attacker triggers ~250 MB of benign Postgres failed-auth output (or a noisy SQL error replayed in a loop) within minutes. With P1 caps, the *first* probes that initiated reconnaissance are rotated out of `docker logs sccap_db` before triage. **Prevention:** route `db` and `ui` through `driver: fluentd`, OR document forensic fallback (Postgres CSVlog inside `postgres_data` volume) in the runbook. Files: `docker-compose.yml` `db:` (50–69), `ui:` (361–382).
2. **Buffer-overflow blackout during incident.** Attacker times an exploit to coincide with a Loki outage. Bounded retry exhausts after ~50 min; subsequent chunks dropped. **Prevention:** emit `BUFFER_OVERFLOW` log line on each drop, Grafana alert on the count, runbook step `docker compose logs fluentd > /tmp/fluentd-buffer.log` for in-process recovery. Files: `fluentd/fluentd.conf:53-60`, NEW `grafana/provisioning/alerting/disk-alert.yaml`.
3. **`/etc/docker/daemon.json` clobber on shared host.** Operator runs setup.sh on a host with a pre-existing `daemon.json` (registry mirror, custom data-root). Naive overwrite breaks other workloads after daemon restart. **Prevention:** detect-existing → JSON-merge via `python3` (already required, line 19) → `.bak` first → atomic replace. File: new block in `setup.sh` between lines 92–94, paralleling the existing `.env.bak` pattern at line 216.

## Verdict

**APPROVE WITH MITIGATIONS**

### Required mitigations (carry into plan)

1. **(P3-R1)** When `drop_oldest_chunk` fires, fluentd emits a `BUFFER_OVERFLOW` line to its own stdout. Grafana alert on the count.
2. **(P4-R1)** `LOKI_RETENTION_DAYS` is operator-tunable via `.env` (default `30d`); `.env.example` carries a comment about the compliance trade-off.
3. **(P2-E1)** `daemon.json` write JSON-merges with any pre-existing file via `python3`, writes `.bak`, atomic replaces, cleans up `.bak` on success. Use `sudo tee` heredoc / fixed argv — never string-interpolate operator input into a `sudo` command.
4. **(P2-E2)** setup.sh detects `EUID==0` vs `sudo` vs neither; if neither, prints exact commands to run as root and exits non-zero. If `sudo` is available, print interactive `type YES` confirmation acknowledging daemon restart bounces ALL host containers.
5. **(P5-T1)** SHA-pin the `df`-sidecar image OR build locally from `tools/df-emitter/` with alpine/busybox base. Sidecar runs `read_only: true`, `cap_drop: [ALL]`, mounts host root `/host:ro`, emits only allowlisted mountpoints (`/`, `/var/lib/docker`).
6. **(P5-I1)** Sidecar emits with `service_name=disk-monitor` tag and interval ≥ 30 s. Runbook recommends `GF_AUTH_ANONYMOUS_ENABLED=false` for production.
7. **(P1-R1)** Either route `db` and `ui` stdout through `driver: fluentd` so security events land in Loki under 30 d retention, OR document the rotate-out window in the runbook with forensic fallback to Postgres CSVlog. Planner picks; recommend the former.
8. **(Doc)** `.agent/project_structure.md` gains "Logging architecture" subsection. `.agent/scanning_flow.md` unchanged.
9. **(Runbook)** New operator runbook (`docs/runbooks/disk-fill.md`) explicitly demarcates HOST vs CONTAINER commands and covers: Loki outage recovery, first-compactor I/O spike, compliance retention trade-off, daemon.json merge + `.bak` rollback.

### Files cited (absolute)

- `/Users/overlord/Projects/secure_coding_platform/docker-compose.yml` (38–46, 50–69, 140–147, 173–182, 184–200, 192–193, 361–382, 384–393)
- `/Users/overlord/Projects/secure_coding_platform/setup.sh` (14–22, 46–59, 70–91, 197–216, 224–249)
- `/Users/overlord/Projects/secure_coding_platform/fluentd/fluentd.conf` (53–60)
- `/Users/overlord/Projects/secure_coding_platform/.agent/work/close-disk-fill-class-discovery.md` (input)

### Files to be created

- `loki/loki-config.yaml`
- `grafana/provisioning/alerting/disk-alert.yaml`
- `tools/df-emitter/` (if local-build route chosen)
- `docs/runbooks/disk-fill.md`
