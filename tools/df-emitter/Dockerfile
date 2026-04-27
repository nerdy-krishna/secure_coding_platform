# df-emitter — minimal busybox sidecar that ships host-disk metrics
# into the existing fluentd → Loki → Grafana pipeline (ADR-010 P5).
#
# Local build (rather than a public image) keeps the threat surface
# tiny: 25-line shell script + busybox. SHA-pin the busybox base in
# a follow-up once the build context is stable for a release cycle.
FROM busybox:1.37

COPY emit.sh /emit.sh
RUN chmod 0555 /emit.sh

# Run as nobody (busybox UID/GID 65534) — the only thing this needs
# read access to is the host root mount (/host:ro) and outbound TCP
# to fluentd. cap_drop ALL is set in compose.
USER 65534:65534

ENTRYPOINT ["/emit.sh"]
