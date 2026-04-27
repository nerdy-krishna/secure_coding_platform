# ADR-010: Bounded log volume across the SCCAP stack

- **Status:** Proposed
- **Date:** 2026-04-28
- **Driver:** `/sccap` run `close-disk-fill-class` / Krishna Lal
- **Deciders:** SCCAP maintainers

## Context

A production SCCAP host filled its root filesystem in late April 2026, taking the stack offline. Postmortem identified four uncapped sinks:

1. Container stdout for non-fluentd services (`db`, `rabbitmq`, `qdrant`, `ui`, `loki`, `grafana`, langfuse-*) writes to the host-default json-file driver, which has no per-container size cap until a daemon-wide setting is applied. A single misbehaving container can fill `/var/lib/docker` with hundreds of GB of logs in under a day.
2. The fluentd `<buffer>` block (lines 53–60 of `fluentd/fluentd.conf`) used `retry_forever true` with no `total_limit_size`. On a Loki outage, fluentd would buffer indefinitely to disk, eventually filling the bind mount.
3. Loki ran on the bundled `local-config.yaml` with no compactor / retention configured. Once a chunk was written it lived forever.
4. No host-level alerting existed; the on-call engineer learned about the fill from `pg_isready` failures, not a disk alarm.

The deploy posture is operator-self-hosted (often single-host VMs). Operators are not full-time SREs; "obvious" disk hygiene cannot be assumed. CLAUDE.md commits us to "Docker-only backend commands" but `setup.sh` runs on the host shell — daemon configuration belongs there.

## Decision

We will adopt a **per-service log-driver matrix** plus a **bounded retention contract** across the entire log pipeline:

1. **Compose log drivers split by intent.** Services whose stdout is security- or audit-relevant (`app`, `worker`, `db`, `ui`) route to `fluentd` so the events land in Loki under retention. All other services (infrastructure-only output: `rabbitmq`, `qdrant`, `loki`, `grafana`, `fluentd` itself, langfuse-*, `disk-monitor`) use `json-file` capped at `max-size: 50m, max-file: 5` (250 MB ceiling per container).
2. **Host daemon defaults match.** `setup.sh` (with operator consent and a documented merge into any pre-existing `/etc/docker/daemon.json`) sets host-wide json-file defaults, so any future container that forgets a `logging:` block still inherits the cap.
3. **fluentd buffer is bounded.** `total_limit_size 2GB`, `overflow_action drop_oldest_chunk`, `retry_max_times 600` (replacing `retry_forever true`). Drops surface as `event=BUFFER_OVERFLOW` log lines visible in Loki and alerted in Grafana.
4. **Loki keeps 30 days by default**, operator-tunable to longer via `LOKI_RETENTION_DAYS` (compactor + `limits_config.retention_period`). `.env.example` documents PCI/HIPAA implications.
5. **Host-disk visibility ships with the stack.** A locally-built `tools/df-emitter` busybox sidecar emits `df` metrics into the existing fluentd→Loki→Grafana pipeline at ≥30 s intervals. Grafana fires at 75% (warning) / 90% (critical).
6. **Bonus: RabbitMQ queue overflow is bounded** via a `drop-head` policy on the SCCAP work queues so the rabbitmq mnesia volume cannot balloon if a worker is wedged.

We deliberately accept silent log loss under sustained backpressure (item 3) and irreversible deletion of >30 d data on the first compactor cycle (item 4) as the cost of bounding disk usage. Both are surfaced operationally — the buffer-overflow Grafana alert and the `daemon.json.bak.sccap-*` rollback path keep operators in the loop.

## Alternatives considered

1. **"Just bigger disks."** Rejected. Treats the symptom; the next service to misbehave (or the next attacker who learns to inflate `db` stdout) hits the same wall. Doesn't address the rotate-out-evidence abuse case (threat model #1) or the audit-retention story.
2. **Promtail + Prometheus + Node Exporter for host metrics.** Rejected for *this* iteration: adds two new images, a new datasource type, and operator configuration burden. The df-sidecar uses the pipeline operators already understand. We can graduate to Prometheus when the platform genuinely needs metric-level granularity beyond log aggregations.
3. **SHA-pin a public `df-to-fluentd` image.** Rejected. The candidate public images are unmaintained. A locally-built 25-line busybox shell script has a smaller threat surface and zero external dependency.
4. **Daemon.json untouched; rely solely on per-compose `logging:` blocks.** Rejected. Misses any container an operator runs outside compose (e.g., a dev `docker run` against the same host) — those still fill the disk silently. A daemon-wide default is belt-and-suspenders.
5. **Loki retention via cron + `delete_request_store: filesystem` only.** Rejected. The 3.x compactor is the supported path; bypassing it leaves indexes pointing at deleted chunks.
6. **Drop logs older than 30 d with no operator override.** Rejected. PCI-DSS 10.5.3 and HIPAA 164.312(b) commonly require ≥1 year audit-log retention. `LOKI_RETENTION_DAYS` makes the constraint explicit and configurable.

## Consequences

- **Positive:**
  - Disk-fill failure class closed at four independent layers (per-container, daemon-wide, fluentd buffer, Loki retention).
  - Operators see fills coming via Grafana alerts before services degrade.
  - Security-relevant stdout from `db` and `ui` survives in Loki for 30 d (was previously rotate-out vulnerable).
  - The runbook gives non-SRE operators a deterministic recovery path.
- **Negative (intentional):**
  - **Silent log loss under sustained backpressure.** A Loki outage longer than ~50 minutes (600 retries × 5 s flush) drops every subsequent chunk until Loki returns. Surfaced as a `BUFFER_OVERFLOW` Grafana alert; not silently absorbed.
  - **Irreversible 30-day window on first compactor cycle.** Existing Loki data older than 30 d gets deleted. Operators with active incidents older than that window must capture forensics before deploying.
  - **Daemon-restart blast radius.** `systemctl restart docker` recreates **every** container on the host, not just SCCAP. Mitigated by interactive `type YES` confirmation in `setup.sh` and by the `/etc/docker/daemon.json.bak.sccap-<timestamp>` rollback path.
  - **First-compactor I/O spike** scales with the size of the existing `loki-data` volume. Runbook recommends scheduling the upgrade in a low-traffic window.
- **Migration:** existing Loki data is queryable under the new schema (single boltdb-shipper schema entry from `2024-01-01`). The 30-day deletion is a one-time event on first compactor cycle. No code or DB migration. Existing operators upgrading inherit the daemon log defaults only after running `setup.sh` again (or applying the `daemon.json` snippet manually per the runbook).
- **Reversal cost:** low. Removing the `logging:` blocks restores prior behavior. Restoring `daemon.json.bak.sccap-*` and `systemctl restart docker` reverses the host change. Removing the `loki-config.yaml` mount returns Loki to its bundled config (but historical data deleted by the compactor cannot be recovered). `df` sidecar removable by deleting one compose service. fluentd buffer settings revert via a one-block edit.

## References

- Code:
  - `docker-compose.yml`
  - `fluentd/fluentd.conf`
  - `setup.sh`
  - `loki/loki-config.yaml` (new)
  - `tools/df-emitter/` (new)
  - `grafana/provisioning/alerting/disk-alert.yaml` (new)
  - `docs/runbooks/disk-fill.md` (new)
- Related ADRs: ADR-008 (Qdrant migration); ADR-009 (prescan approval gate).
- External:
  - Docker logging-driver json-file: https://docs.docker.com/engine/logging/drivers/json-file/
  - fluentd buffer overflow_action: https://docs.fluentd.org/configuration/buffer-section#overflow_action
  - Loki compactor + retention: https://grafana.com/docs/loki/latest/operations/storage/retention/
  - PCI-DSS v4.0 §10.5.3 audit log retention; HIPAA Security Rule 45 CFR §164.312(b).
