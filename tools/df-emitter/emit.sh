#!/bin/sh
# df-emitter — emit host-disk usage to fluentd's forward port at a
# bounded interval (ADR-010 P5).
#
# Env vars (all optional with safe defaults):
#   DF_MOUNTPOINTS      space-separated list of mountpoints to emit.
#                       Defaults to "/host /host/var/lib/docker".
#                       Anything not in this allowlist is dropped.
#   DF_INTERVAL_SECONDS sleep between emits. Default 30. Refuses < 10
#                       so a runaway interval can't spam fluentd.
#   FLUENTD_HOST        fluentd hostname. Default "fluentd".
#   FLUENTD_PORT        fluentd forward TCP port. Default "24224".
#
# Output: one JSON line per allowlisted mountpoint per cycle, written
# via netcat in fluentd's json-tagged form. The tag prefix
# `docker.disk-monitor.host` matches fluentd's `<filter docker.**>`
# rules so the existing service_name extraction works.

set -eu

INTERVAL="${DF_INTERVAL_SECONDS:-30}"
if [ "$INTERVAL" -lt 10 ] 2>/dev/null; then
    echo "df-emitter: refusing DF_INTERVAL_SECONDS=$INTERVAL (< 10)" >&2
    exit 2
fi

MOUNTS="${DF_MOUNTPOINTS:-/host /host/var/lib/docker}"
HOST="${FLUENTD_HOST:-fluentd}"
PORT="${FLUENTD_PORT:-24224}"

echo "df-emitter: starting; mounts=[$MOUNTS] interval=${INTERVAL}s target=${HOST}:${PORT}" >&2

while :; do
    NOW=$(date +%s)
    for mp in $MOUNTS; do
        if [ ! -d "$mp" ]; then
            continue
        fi
        # df -P normalises to a single line per mount and POSIX columns:
        #   Filesystem  1024-blocks  Used  Available  Capacity  Mounted-on
        line=$(df -P "$mp" 2>/dev/null | awk 'NR==2 { gsub("%","",$5); print $5","$3","$4 }')
        if [ -z "$line" ]; then
            continue
        fi
        used_pct=$(echo "$line" | cut -d, -f1)
        used_kb=$(echo "$line" | cut -d, -f2)
        avail_kb=$(echo "$line" | cut -d, -f3)

        # Strip the /host prefix so Loki labels show the host-side path.
        host_mp=$(echo "$mp" | sed 's|^/host||')
        [ -z "$host_mp" ] && host_mp="/"

        # fluentd forward protocol accepts newline-delimited JSON when
        # we tag it via the in_forward "json" decode path. We write
        # one record per emit and let fluentd parse.
        printf '["docker.disk-monitor.host",%s,{"mountpoint":"%s","used_pct":%s,"used_kb":%s,"avail_kb":%s,"service_name":"disk-monitor","level":"INFO"}]\n' \
            "$NOW" "$host_mp" "$used_pct" "$used_kb" "$avail_kb" \
            | nc -w 1 "$HOST" "$PORT" || true
    done
    sleep "$INTERVAL"
done
