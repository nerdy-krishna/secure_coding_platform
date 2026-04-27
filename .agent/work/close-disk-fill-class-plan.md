# Change Plan — close-disk-fill-class

## Goal

Eliminate the disk-fill failure class across the SCCAP stack by bounding every uncapped log/data sink: per-service compose `logging:` blocks (with `db`+`ui` rerouted through fluentd), a host-wide Docker daemon log default written by `setup.sh`, a bounded fluentd file-buffer with `drop_oldest_chunk` overflow + bounded retries + a grep-able `BUFFER_OVERFLOW` signal, a custom `loki/loki-config.yaml` enabling the compactor with operator-tunable 30-day retention, a host-disk Grafana alert fed by a locally-built `df`-emitter sidecar, plus three architectural extras (RabbitMQ overflow policy, operator runbook, project-structure doc-sync). Single squashed commit.

## Inputs

- Discovery: `.agent/work/close-disk-fill-class-discovery.md`
- Threat model: `.agent/work/close-disk-fill-class-threat-model.md` (verdict: APPROVE WITH MITIGATIONS, 9 required mitigations)
- ADR: `.agent/work/close-disk-fill-class-adr.md`

## Risk posture

- **Risk tolerance:** high
- **STRIDE flags carried over:** Tampering (P2 daemon.json clobber, df-sidecar image), Repudiation (P3 drop_oldest_chunk; P4 30-day deletion; P1 rotate-out on db/ui — addressed by routing both through fluentd), Info-disclosure (df mountpoint allowlist; Grafana anon viewer), DoS (rotate-out window; bounded retry exhaustion; first-compactor I/O spike; df-sidecar interval ≥30 s), Elevation (sudo introduced; daemon restart bounces all host containers; df sidecar caps).
- **Architectural impact:** **yes** — committing to a per-service log-driver matrix, a 30-day Loki retention contract, and a new sidecar service category.

## Committed design decisions

1. **`df`-emitter sidecar — local build from `tools/df-emitter/`.** Smaller surface (busybox + 25-line shell), no external dep, easier audit, no SHA-pin churn.
2. **`setup.sh` sudo strategy — three-branch detection function** `_sccap_with_root <cmd...>`: (a) `EUID==0` runs directly; (b) `sudo` available → `sudo "$@"` fixed argv; (c) neither → print exact root commands and `exit 1`. Daemon.json write uses `python3` JSON-merge → temp file → `install -m 0644 -o root -g root` (no shell interpolation). Original preserved at `/etc/docker/daemon.json.bak.sccap-<timestamp>`.
3. **`db` and `ui` log routing — `driver: fluentd`** per threat-model P1-R1.
4. **`LOKI_RETENTION_DAYS` format — `30d`** (string with suffix; Loki accepts `30d`/`4w`/`720h`).
5. **`fluentd` `BUFFER_OVERFLOW` signal mechanism** — `<system> log_level info` + `<label @ERROR>` sink + `record_transformer` filter promoting drop events into a structured `service_name=fluentd-internal level=ERROR event=BUFFER_OVERFLOW` Loki line.

## Phased steps

- [x] **Step 1 — Bounded `logging:` blocks for all non-fluentd-driver services in `docker-compose.yml`.**
  - Files: `docker-compose.yml` (edit)
  - Apply identical `logging: {driver: json-file, options: {max-size: "50m", max-file: "5"}}` to: `rabbitmq`, `qdrant`, `fluentd` itself, `loki`, `grafana`, `langfuse-postgres`, `langfuse-clickhouse`, `langfuse-redis`, `langfuse-minio`, `langfuse-web`, `langfuse-worker`.
  - Reuse: existing `logging:` shape from `app` (`docker-compose.yml:38-46`).
  - Mitigation: P1.
  - Verifies via: `docker compose config -q`.

- [x] **Step 2 — Reroute `db` and `ui` stdout through fluentd (P1-R1).**
  - Files: `docker-compose.yml` (edit)
  - Same fluentd `logging:` options block as `app`/`worker`, with `tag: docker.db.{{.Name}}` / `docker.ui.{{.Name}}`. Add `depends_on: {fluentd: {condition: service_healthy}}` to both. Convert `ui`'s legacy list-form `depends_on: [app]` to map form to combine.
  - Mitigations: P1-R1, Repudiation R-c.
  - Verifies via: `docker compose config -q`; manual Loki label query for `service_name=db` / `service_name=ui`.

- [x] **Step 3 — Bound the fluentd buffer + add `BUFFER_OVERFLOW` signal in `fluentd/fluentd.conf`.**
  - Files: `fluentd/fluentd.conf` (edit)
  - In `<buffer>`: add `total_limit_size 2GB`, `overflow_action drop_oldest_chunk`; replace `retry_forever true` with `retry_max_times 600`. Add `<system>\n  log_level info\n</system>`. Add `<label @ERROR>` block with `<match **> @type stdout </match>` so dropped-chunk events appear in fluentd's own stdout. Add `<filter docker.fluentd.**>` `record_transformer` tagging `event "BUFFER_OVERFLOW"` when message matches `BufferOverflowError|drop_oldest_chunk`.
  - Reuse: existing `<filter docker.**>` shape, `<match docker.**>` Loki sink.
  - Mitigations: P3, P3-R1.
  - Verifies via: `docker run --rm -v "$PWD/fluentd:/fluentd/etc" fluent/fluentd:v1.17-1 fluentd -c /fluentd/etc/fluentd.conf --dry-run`.

- [x] **Step 4 — Create `loki/loki-config.yaml` with compactor + retention.**
  - Files: `loki/loki-config.yaml` (create); `docker-compose.yml` (edit `loki:` service)
  - Full custom config: `auth_enabled: false`; `server.http_listen_port: 3100`; `common: {path_prefix: /loki, replication_factor: 1, ring: {kvstore: {store: inmemory}}}`; `schema_config` boltdb-shipper from `2024-01-01`; `storage_config` filesystem; `compactor: {working_directory: /loki/compactor, retention_enabled: true, retention_delete_delay: 2h, retention_delete_worker_count: 150, delete_request_store: filesystem}`; `limits_config: {retention_period: ${LOKI_RETENTION_DAYS:-30d}, allow_structured_metadata: true}`.
  - Compose mount: `- ./loki/loki-config.yaml:/etc/loki/local-config.yaml:ro`. Change `command:` to add `-config.expand-env=true`. Add `environment: [LOKI_RETENTION_DAYS=${LOKI_RETENTION_DAYS:-30d}]`.
  - Mitigations: P4, P4-R1.
  - Verifies via: `docker run --rm -v "$PWD/loki:/etc/loki" -e LOKI_RETENTION_DAYS=30d grafana/loki:3.4.2 -verify-config -config.file=/etc/loki/local-config.yaml -config.expand-env=true`.

- [x] **Step 5 — Document `LOKI_RETENTION_DAYS` in `.env.example`.**
  - Files: `.env.example` (edit)
  - Add near `LANGFUSE_TRACE_RETENTION_DAYS`: comment block + `LOKI_RETENTION_DAYS=30d`.
  - Mitigation: P4-R1.

- [x] **Step 6 — Add daemon-wide log-rotation in `setup.sh`.**
  - Files: `setup.sh` (edit)
  - New section between line 217 (end of `.env` save) and line 224 (compose build). Define `_sccap_with_root` helper, `_sccap_render_daemon_json` function (python3 JSON-merge that respects pre-set `log-driver`), interactive `type YES` prompt, `.bak.sccap-<ts>` backup, `install -m 0644 -o root -g root` atomic replace, `systemctl restart docker` (Linux) or print "Manually restart Docker Desktop now" (macOS).
  - Reuse: `.env.bak`/sed pattern (lines 46-59, 197-216); `read -p` shape (lines 111, 132, 147, 176).
  - Mitigations: P2-E1, P2-E2, Tampering.
  - Verifies via: `bash -n setup.sh`; manual Linux-VM smoke (no daemon.json / pre-existing `data-root` / non-root no-sudo).

- [x] **Step 7 — Build the local `df`-emitter sidecar context.**
  - Files: `tools/df-emitter/Dockerfile` (create), `tools/df-emitter/emit.sh` (create), `tools/df-emitter/README.md` (create)
  - `Dockerfile`: `FROM busybox:1.37`, `COPY emit.sh /emit.sh`, `chmod 0555`, `USER 65534:65534`, `ENTRYPOINT ["/emit.sh"]`.
  - `emit.sh`: env-driven loop. `DF_MOUNTPOINTS` (default `/host /host/var/lib/docker`), `DF_INTERVAL_SECONDS` (default 30, refuse <10), `FLUENTD_HOST`, `FLUENTD_PORT`. For each allowlisted mountpoint, emits one JSON line `{"mountpoint":"...","used_pct":N,"service_name":"disk-monitor","level":"INFO"}` to fluentd via `nc`. Non-allowlisted mountpoints dropped silently after one startup log line.
  - `README.md`: documents env vars, allowlist semantics, security posture.
  - Mitigations: P5-T1, P5-I1.
  - Verifies via: `docker build -t sccap-df-emitter:dev tools/df-emitter`.

- [x] **Step 8 — Wire `disk-monitor` sidecar into `docker-compose.yml`.**
  - Files: `docker-compose.yml` (edit)
  - New service `disk-monitor:` — `build: ./tools/df-emitter`, `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `volumes: [/:/host:ro]`, `environment: {...}`, `depends_on: {fluentd: {condition: service_healthy}}`, `logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}`, `networks: [scpnetwork]`, `restart: unless-stopped`.
  - Mitigations: P5-T1, P5-I1.
  - Verifies via: `docker compose config -q`; manual smoke after up.

- [x] **Step 9 — Grafana alerting rules: host-disk + buffer-overflow.**
  - Files: `grafana/provisioning/alerting/disk-alert.yaml` (create)
  - Two `groups` in a single `apiVersion: 1` provisioning file:
    1. `host-disk-fill`: `quantile_over_time(0.95, {service_name="disk-monitor"} | json | unwrap used_pct [5m])` > 75 → warning, > 90 → critical, `for: 10m`. Annotations link the runbook.
    2. `fluentd-buffer-overflow`: `sum(count_over_time({service_name="fluentd-internal", event="BUFFER_OVERFLOW"}[5m]))` > 0 → critical, `for: 0m`.
  - Mitigations: P5, A3, P3-R1.
  - Verifies via: `docker compose config -q`; manual `curl -u admin:admin /api/v1/provisioning/alert-rules`.

- [x] **Step 10 — RabbitMQ overflow policy (architectural extra A1).**
  - Files: `docker-compose.yml` (edit), `rabbitmq/definitions.json` (create)
  - `definitions.json`: `policies` entry pinning `^code_submission_queue$|^analysis_approved_queue$|^remediation_queue$` to `{"max-length": 100000, "overflow": "drop-head"}`. Mount `:ro`. Add `RABBITMQ_LOAD_DEFINITIONS=/etc/rabbitmq/definitions.json` env (3.13+) OR a `rabbitmq.conf` `load_definitions` line for 3.12.
  - Queue names sourced from `config/config.py` per CLAUDE.md.
  - Mitigation: A1.
  - Verifies via: `docker compose config -q`; manual `rabbitmqctl list_policies`.

- [x] **Step 11 — Doc-sync `.agent/project_structure.md` (R8).**
  - Files: `.agent/project_structure.md` (edit)
  - New "Logging architecture" section: per-service driver matrix, fluentd buffer caps + `BUFFER_OVERFLOW` signal, Loki retention with `LOKI_RETENTION_DAYS`, Grafana alerts, runbook pointer.
  - Mitigation: R8.

- [x] **Step 12 — Author `docs/runbooks/disk-fill.md` (R9, A2).**
  - Files: `docs/runbooks/disk-fill.md` (create)
  - Sections: Symptoms, HOST commands (banner), CONTAINER commands (banner), Loki outage recovery, First-compactor I/O spike, Compliance retention trade-off (PCI/HIPAA), `daemon.json` rollback, Recent incident replay (placeholder), `GF_AUTH_ANONYMOUS_ENABLED=false` recommendation.
  - Mitigation: R9.

## File-touched table

| Path | Action | Mitigations |
|---|---|---|
| `docker-compose.yml` | edit | P1 (Step 1), P1-R1 (Step 2), P4 mount (Step 4), P5-T1 sidecar (Step 8), A1 (Step 10) |
| `fluentd/fluentd.conf` | edit | P3, P3-R1 (Step 3) |
| `loki/loki-config.yaml` | create | P4, P4-R1 (Step 4) |
| `.env.example` | edit | P4-R1 (Step 5) |
| `setup.sh` | edit | P2-E1, P2-E2, Tampering (Step 6) |
| `tools/df-emitter/Dockerfile` | create | P5-T1 (Step 7) |
| `tools/df-emitter/emit.sh` | create | P5-T1, P5-I1 (Step 7) |
| `tools/df-emitter/README.md` | create | audit trail (Step 7) |
| `grafana/provisioning/alerting/disk-alert.yaml` | create | P5, P3-R1, A3 (Step 9) |
| `rabbitmq/definitions.json` | create | A1 (Step 10) |
| `.agent/project_structure.md` | edit (doc-sync) | R8 (Step 11) |
| `docs/runbooks/disk-fill.md` | create | R9, A2 (Step 12) |

## Verification matrix

| Gate | Required | Command | Reason |
|---|---|---|---|
| ruff | Y | `python3 -m ruff check src` | always-on; expected pass-through |
| black | Y | `python3 -m black --check src` | always-on; expected pass-through |
| mypy | Y | `python3 -m mypy src` | always-on; expected pass-through |
| pytest | Y | `docker compose exec app pytest` | always-on; expected pass-through |
| Compose syntax | Y | `docker compose config -q` | load-bearing for this change |
| Fluentd dry-run | Y | `docker run --rm -v "$PWD/fluentd:/fluentd/etc" fluent/fluentd:v1.17-1 fluentd -c /fluentd/etc/fluentd.conf --dry-run` | catches `<buffer>`/`<label>` typos |
| Loki verify | Y | `docker run --rm -v "$PWD/loki:/etc/loki" -e LOKI_RETENTION_DAYS=30d grafana/loki:3.4.2 -verify-config -config.file=/etc/loki/local-config.yaml -config.expand-env=true` | catches retention/compactor schema typos |
| setup.sh shell | Y | `bash -n setup.sh` | catches new heredoc / fn shape |
| df-emitter build | Y | `docker build -t sccap-df-emitter:dev tools/df-emitter` | proves new build context self-contained |
| gitleaks (if bootstrapped) | Y | `gitleaks detect --no-banner --source .` | rabbitmq definitions / daemon.json templates leakage check |

### Manual smoke (automation-resistant)

1. `docker compose up -d --build` on fresh checkout — all 13 services healthy.
2. `df` sidecar emit — `docker compose logs disk-monitor` shows ≥ 2 emits within 90 s; queryable in Grafana Explore as `service_name=disk-monitor`.
3. fluentd buffer signal — stop loki briefly; verify retry/recover; sustained outage → confirm `BUFFER_OVERFLOW` lines in Loki on recovery.
4. Loki compactor cycle — `docker compose logs loki | grep compactor` within ~1 h of startup; `loki-data` volume size plateaus.
5. setup.sh daemon.json branch — Linux VM: no daemon.json (creates), pre-existing `{"data-root":"/srv/docker"}` (merges), non-root no-sudo (prints commands & exits 1).
6. Grafana host-disk alert — `fallocate` `/host` to >75%; alert fires within 10 m and resolves on cleanup.
7. RabbitMQ policy — `rabbitmqctl list_policies` shows `max-length=100000, overflow=drop-head`.

## Out of scope (deferred follow-ups)

- **Docker-volume size monitoring panel** in Grafana — second sidecar emitting `docker system df`.
- **Postgres `archive_mode` / WAL retention audit**.
- **Per-tenant Langfuse projects** (already filed in CLAUDE.md).
- **SHA-pin `busybox:1.37`** in `tools/df-emitter/Dockerfile` (defer until local-build context stable).
- **`GF_AUTH_ANONYMOUS_ENABLED=false`** as compose default (UX change for dev users).
- **Promote evals warn-only gate to hard-block** (orthogonal).
- **F-1 (security-review LOW)** — `tools/df-emitter/emit.sh:56` `printf` with literal format string and `%s` arguments. Reviewer flagged as a stylistic nit; the format string is single-quoted and the mountpoint is an argument (not interpolated into the format), so there is no injection vector. Optional refactor to pre-build the JSON string and `printf '%s\n' "$json"` for readability.
- **F-2 (security-review LOW)** — `grafana/provisioning/alerting/disk-alert.yaml` `runbook_url: file:///workspace/.agent/runbooks/disk-fill.md` is a placeholder. Replace with a production https URL once the docs site publishes the runbook.
- **F-3 (security-review informational, pre-existing)** — fluentd `<source>` listens on `0.0.0.0:24224` and the host port `24224:24224` is published. Inside `scpnetwork` only (no external attack surface in default deploys), but worth a separate ADR if hardening this further (e.g., bind to `127.0.0.1` host-side, or remove the host port mapping entirely since fluentd is only addressed by other compose services).
