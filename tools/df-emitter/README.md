# df-emitter

Tiny busybox sidecar that emits host-disk-usage metrics into the
SCCAP fluentd → Loki → Grafana pipeline. Drives the host-disk
Grafana alert added by ADR-010.

## Why a local build instead of a public image

The candidate public `df-to-fluentd` images on Docker Hub are
unmaintained. The script is a 25-line shell loop; a SHA-pinned
public image would carry a much larger attack surface for the
same job. Once this build context is stable for a release cycle
we can SHA-pin the `busybox:1.37` base in `Dockerfile`.

## Container posture

Set in `docker-compose.yml`:

- `read_only: true`
- `cap_drop: [ALL]`
- `security_opt: [no-new-privileges:true]`
- `volumes: [/:/host:ro]` — host root is mounted read-only.
- `user: 65534:65534` (set in `Dockerfile`).

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `DF_MOUNTPOINTS` | `/host /host/var/lib/docker` | Space-separated allowlist. Anything outside is dropped silently. |
| `DF_INTERVAL_SECONDS` | `30` | Refuses any value < 10 to prevent fluentd flooding. |
| `FLUENTD_HOST` | `fluentd` | Forward target hostname (resolved on `scpnetwork`). |
| `FLUENTD_PORT` | `24224` | Forward TCP port. |

## Output shape

One JSON record per allowlisted mountpoint per cycle, sent to
fluentd's forward port with the tag `docker.disk-monitor.host`:

```json
{
  "mountpoint": "/",
  "used_pct": 21,
  "used_kb": 15728640,
  "avail_kb": 56623104,
  "service_name": "disk-monitor",
  "level": "INFO"
}
```

The `mountpoint` label has the `/host` prefix stripped so it shows
the host-side path. `service_name=disk-monitor` matches the Grafana
alert in `grafana/provisioning/alerting/disk-alert.yaml`.

## Verify locally

```sh
docker build -t sccap-df-emitter:dev tools/df-emitter
docker run --rm -e DF_INTERVAL_SECONDS=5 sccap-df-emitter:dev   # refuses
```
