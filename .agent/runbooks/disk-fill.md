# Runbook: Disk-fill on a SCCAP host

> Triggered by: Grafana alert `host-disk-fill` (warning ≥ 75%, critical ≥ 90%) or `fluentd-buffer-overflow`. Manual sign of the same: `pg_isready` failures, `docker compose ps` showing `(unhealthy)`, `df -h /` ≥ 90%.

ADR-010 closes the disk-fill class architecturally, but operators still need to act when an alert fires. This runbook is the deterministic recovery path.

> **Banner convention:** every command is prefixed by either `# === HOST ===` (run on the Docker host shell, often as root or with sudo) or `# === CONTAINER ===` (run via `docker compose exec ...` against an SCCAP container). **Never** mix the two.

---

## 1. Triage — figure out where the bytes went

```sh
# === HOST ===
df -h /
df -h /var/lib/docker
du -sh /var/lib/docker/containers/*/ | sort -h | tail -10
du -sh "$(docker volume inspect --format '{{.Mountpoint}}' loki-data)"
du -sh "$(docker volume inspect --format '{{.Mountpoint}}' rabbitmq_data)"
journalctl --disk-usage   # systemd-journald can be its own disk-fill vector
```

If any single container's `*-json.log` exceeds 1 GB, that's a service writing through the json-file cap (rare — investigate the `logging:` block in `docker-compose.yml`).

---

## 2. Reclaim quickly (least disruptive first)

```sh
# === HOST ===
# Truncating a Docker json-file *while the daemon is writing* is safe;
# Docker reopens the file on the next emit. Run for any container whose
# log dwarfs the rest. Adjust the path to the offender's container ID.
sudo truncate -s 0 /var/lib/docker/containers/<CID>/<CID>-json.log

# Reclaim the build cache (often 20 GB+ on long-lived hosts).
sudo docker builder prune -af

# Reclaim dangling images (containers in use stay).
sudo docker image prune -f

# Last resort: anonymous volumes from earlier deploys.
sudo docker volume ls -qf dangling=true | xargs -r sudo docker volume rm
```

---

## 3. Loki outage recovery (when `fluentd-buffer-overflow` fires)

When `service_name=fluentd-internal event=BUFFER_OVERFLOW` events are showing in Loki, fluentd's bounded retry exhausted (~50 minutes of Loki unavailability) and `drop_oldest_chunk` started discarding the oldest 2 GB worth of buffered chunks. **Those chunks are gone.**

Before restarting fluentd, capture what's still in its in-memory ring:

```sh
# === HOST ===
docker compose logs --no-color --since=1h fluentd > /tmp/sccap-fluentd-buffer-$(date +%s).log
```

Then clear the cause (Loki) and let fluentd drain:

```sh
# === HOST ===
docker compose ps loki
docker compose restart loki
sleep 30
docker compose logs --since=2m fluentd | grep -E 'flush|retry|BUFFER_OVERFLOW' | tail -50
```

If fluentd is wedged, restart it last (after Loki is verified healthy) — restarting fluentd while Loki is still down loses the in-memory ring entirely:

```sh
# === HOST ===
docker compose restart fluentd
```

---

## 4. Compactor cycle on first deploy

The first time Loki starts under `loki/loki-config.yaml`, the compactor will scan all chunks under `loki-data` and delete anything older than `LOKI_RETENTION_DAYS`. On a host with months of accumulated data this is a one-time I/O spike.

```sh
# === HOST ===
docker compose logs --since=5m loki | grep -i compactor
docker stats --no-stream sccap_loki   # watch CPU + IO for 5–10 min
du -sh "$(docker volume inspect --format '{{.Mountpoint}}' loki-data)"
```

Schedule this in a low-traffic window. Cycle duration scales with backlog size.

---

## 5. Compliance: extending retention beyond 30 days

PCI-DSS 10.5.3 and HIPAA Security Rule 164.312(b) typically require ≥1-year audit-log retention. SCCAP's default is 30 days. To extend:

```sh
# === HOST ===
# Stop loki cleanly, edit .env, restart.
echo "LOKI_RETENTION_DAYS=365d" >> .env   # or edit existing line
docker compose up -d --no-deps loki
```

Provision a larger `loki-data` volume **before** flipping the value — the compactor will keep more chunks, so disk usage scales linearly with retention (unless log volume drops).

If you need to *increase* retention on a host that's already been running with 30 d, all data older than the original 30 d window is already gone — you only get longer retention going forward, never retroactive.

---

## 6. `daemon.json` rollback (post-`setup.sh` §2.7)

`setup.sh` writes `/etc/docker/daemon.json.bak.sccap-<timestamp>` before any change. To revert:

```sh
# === HOST ===
ls -lt /etc/docker/daemon.json.bak.sccap-*
sudo install -m 0644 -o root -g root \
    /etc/docker/daemon.json.bak.sccap-<TIMESTAMP> /etc/docker/daemon.json
sudo systemctl restart docker
```

If no `.bak.sccap-*` exists the host had no `daemon.json` before; remove the file:

```sh
# === HOST ===
sudo rm /etc/docker/daemon.json
sudo systemctl restart docker
```

The compose `logging:` blocks still bound SCCAP services after rollback — only ad-hoc `docker run` containers lose their cap.

---

## 7. Recent incident replay (April 2026)

This incident is what motivated ADR-010. Symptom: 75 GB host at 100%, all containers in `(unhealthy)` state, `docker exec` failing with `no space left on device`.

Root cause: the `secure_coding_platform_fluentd` container's own Docker `json-file` log grew to 40 GB because the default driver had no cap and fluentd was emitting an error loop.

Recovery (in order):

```sh
# === HOST ===
# 1. Truncate the runaway log to free space immediately (~40 GB freed).
sudo truncate -s 0 /var/lib/docker/containers/<fluentd-CID>/<fluentd-CID>-json.log

# 2. Truncate the rest for tidiness (small wins).
sudo find /var/lib/docker/containers -name '*-json.log' -exec truncate -s 0 {} \;

# 3. Reclaim build cache (~25 GB).
sudo docker builder prune -af

# 4. (Optional) prune dangling images.
sudo docker image prune -f

# 5. Verify.
df -h /                       # expect ≥ 50% free
docker ps                     # services should drop (unhealthy) within ~60s
```

After recovery, ADR-010 prevents recurrence.

---

## 8. Production-hardening reminder

Grafana ships with `GF_AUTH_ANONYMOUS_ENABLED=true GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer` in the dev compose default. The `disk-monitor` sidecar emits mountpoint paths into Loki — anyone with Grafana viewer access can read them. For production:

```sh
# === HOST ===
# In .env or via your deployment pipeline:
echo "GF_AUTH_ANONYMOUS_ENABLED=false" >> .env
docker compose up -d --no-deps grafana
```

---

## See also

- `.agent/project_structure.md` — "Logging architecture" section (per-service driver matrix).
- `.agent/work/close-disk-fill-class-adr.md` — ADR-010 design rationale.
- `tools/df-emitter/README.md` — sidecar internals.
- `grafana/provisioning/alerting/disk-alert.yaml` — alert rule definitions.
