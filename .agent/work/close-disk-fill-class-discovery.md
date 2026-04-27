# Discovery — close-disk-fill-class

## Files in scope

- **`docker-compose.yml`** (1–399) — services block defining all containers. P1: add `logging:` blocks (json-file, max-size 50m, max-file 5) to every service that does not already use the fluentd driver: `db`, `rabbitmq`, `qdrant`, `ui`, `fluentd`, `loki`, `grafana`, and the langfuse-* services. `app` and `worker` already use `driver: fluentd` (lines 38–46, 140–147) and are insulated from json-file growth. `loki` (lines 173–182) and `ui` (lines 361–382) currently have no logging block. P4 will also add a `volumes:` mount for the new `loki/loki-config.yaml`. P5 may add a `df` sidecar service.
- **`setup.sh`** (1–284) — interactive setup script. P2: add an idempotent block that writes `/etc/docker/daemon.json` with `{"log-driver":"json-file","log-opts":{"max-size":"50m","max-file":"5"}}` and restarts the docker daemon (or warns if no sudo). P4: optionally template `LOKI_RETENTION_DAYS` into the new config.
- **`fluentd/fluent.conf`** — fluentd routing config. P3: edit the existing `<buffer>` block (around line 56 per CLAUDE.md analysis): add `total_limit_size 2GB`, `overflow_action drop_oldest_chunk`, replace `retry_forever true` with bounded retries (`retry_max_times 600`).
- **`loki/loki-config.yaml`** (NEW) — currently the loki container uses the image's bundled `/etc/loki/local-config.yaml` (compose line 178). P4: create a custom config with `compactor.retention_enabled: true`, `compactor.retention_period: 30d` (or operator-tunable), `limits_config.retention_period: 30d`, and mount it via compose `volumes:`. The compose `command:` arg already points at `/etc/loki/local-config.yaml`, so the mount target is fixed.
- **`grafana/provisioning/`** — already mounted (compose line 196). P5: add `grafana/provisioning/alerting/disk-alert.yaml` (or .json) for a host root-fs alert at >75%. May need a `node_exporter` sidecar OR Loki-based metric to source the data.
- **`.env.example`** (1–67) — P4: document `LOKI_RETENTION_DAYS` (default 30) if we make retention operator-tunable.
- **`.agent/project_structure.md`** — doc-sync target. Logging architecture (json-file caps, fluentd buffer, Loki retention, Grafana alerting) is a structural addition worth documenting.

## Reuse candidates

- **setup.sh sed/.env edit pattern (lines 46–59)** — atomic `.bak`-backed edit with OS detection. Reusable for daemon.json modification (`sed -i.bak '...' /etc/docker/daemon.json` with sudo).
- **`docker compose exec` pattern (line 249)** — already used for alembic; can be reused to verify post-restart container health.
- **Existing `grafana/provisioning/` mount** — operators already understand this; add the alert file under it rather than introducing a new mechanism.
- **Existing fluentd build context** (`./fluentd`) — no Dockerfile changes required; P3 is config-only.
- **Compose `${VAR}` interpolation** — already used for ports/passwords; reuse for `${LOKI_RETENTION_DAYS:-30d}` if templating is desired.

## Blast radius

- **Docker daemon (HIGH).** P2 writes `/etc/docker/daemon.json` and `systemctl restart docker` — recreates **every** container on the host (not just SCCAP). Risk medium for shared hosts; the user accepted "high risk tolerance" so we proceed.
- **Every container's logging behavior (HIGH).** P1's `logging:` blocks rotate and cap container stdout. After the change, only the most recent `max-size × max-file` bytes are retained per container. Operators relying on raw `docker logs` for old debug data will lose it.
- **fluentd (MEDIUM).** P3 replaces `retry_forever` with bounded retries plus a 2 GB buffer cap and `drop_oldest_chunk`. Under sustained Loki outage, **chunks will be dropped silently** (intended trade-off, but must be documented).
- **Loki on-disk format (MEDIUM).** P4 enables the compactor with retention. Existing data older than 30 d will be deleted on the first compactor cycle. Re-indexes; no schema migration. Backward compatible at the index level but lossy for >30 d historical logs.
- **Grafana (LOW).** P5 alert is additive. No existing dashboard or alert removed.
- **Host filesystem (MEDIUM).** Daemon log defaults applied host-wide.
- **CI / build / app code (NONE).** No application or migration changes.

## Inherited constraints

- **No `Co-Authored-By: Claude` trailer** on the commit (memory note + CLAUDE.md repo conventions).
- **Backend commands run inside Docker** — but P2's `systemctl` is **host-level** by definition. setup.sh already runs on the host shell, so this is consistent.
- **`.agent/project_structure.md`** must be re-synced if logging architecture is structurally documented; **`.agent/scanning_flow.md`** is unaffected (no worker-graph node changes).
- **No new secrets** — daemon.json and Loki config contain no Fernet-protected fields. `.env` additions (e.g., `LOKI_RETENTION_DAYS`) are non-secret.
- **`.env.example` must NOT include `OPENAI_API_KEY` / `GOOGLE_API_KEY`** — irrelevant here, no LLM key fields touched.
- **Async alembic** — irrelevant, no DB migrations.
- **All conventional-commit format** — `chore(ops): close disk-fill failure class` or `feat(observability): bound log volume across stack` — both fit; planner picks.

## Open questions

1. **Sudo affordance in setup.sh.** Currently does not invoke `sudo`. Should P2 wrap daemon.json edits in `sudo`, or print a clearly delimited "PASTE THESE COMMANDS AS ROOT" block? Recommend: detect root vs non-root, attempt `sudo` if available, fall through to print-instructions otherwise. **Planner decides.**
2. **Loki config baseline.** The bundled `local-config.yaml` is reasonable; question is whether to *replace* or *layer*. Recommend: write a full custom file (replacing) so operators have one source of truth. **Planner decides.**
3. **`LOKI_RETENTION_DAYS` configurability.** Recommend: operator-tunable via `.env` with default `30d`, since enterprises will want longer; document in `.env.example`. **Planner decides format (`30d` vs `30`).**
4. **Whitelist for P1 logging blocks.** Recommend: every service WITHOUT a `driver: fluentd` block. Today: `db`, `rabbitmq`, `qdrant`, `ui`, `fluentd`, `loki`, `grafana`, plus all langfuse-* if Langfuse is enabled. **Planner enumerates exact list from current compose.**
5. **P5 alert metric source.** Two options:
   - (a) Add `node_exporter` + Prometheus + Grafana datasource (heavyweight — prometheus added to stack).
   - (b) A tiny `df`-emitter sidecar that ships to fluentd → Loki, then a Loki-based alert in Grafana (lighter, fits existing pipeline).
   Recommend **(b)**. **Planner decides and threat-modeler reviews.**
6. **Architectural extras** (since user said "everything and more"): the threat-modeler / planner should consider:
   - **Postgres `pg_stat_statements` and WAL retention** — not currently a disk-fill vector but worth checking `pg_settings.archive_mode`.
   - **RabbitMQ queue length cap / overflow policy** — if a queue grows unbounded, the `rabbitmq` data dir grows.
   - **Docker volume size monitoring** — `loki-data`, `langfuse-postgres-data`, `qdrant-data` are all volumes that can balloon independently of container logs.
   - **Operations runbook** — a `docs/runbooks/disk-fill.md` (or `.agent/runbooks/`) documenting the cleanup steps used in the recent incident, so operators can replay them without ad-hoc SSH archaeology.

## Summary

Five primary work streams (P1–P5) crossing orchestration, init script, log pipeline config, and observability. Blast radius high (daemon restart, container recreate, retention deletion of >30 d Loki data). Six open design questions for the planner. Three architectural extras worth bolting on given the "everything and more" scope: rabbitmq overflow policy, volume-level disk monitoring, and a host-disk-fill runbook.
