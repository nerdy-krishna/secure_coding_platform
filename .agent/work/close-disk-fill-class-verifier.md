# Verification Report — close-disk-fill-class

## Summary

| Gate | Status | Notes |
|---|---|---|
| ruff | PASS | clean |
| black | PASS | clean |
| mypy | FAIL | pre-existing errors (no Python touched in this change) |
| pytest | PASS | 197 passed, 1 skipped, 6.31 s |
| docker compose config | PASS | VITE_ALLOWED_HOSTS unset warning only (pre-existing) |
| bash syntax check (setup.sh) | PASS | no errors |
| Fluentd dry-run | PASS | config parses correctly with plugins |
| Loki -verify-config | FAIL | Loki 3.4.2 incompatibility in loki-config.yaml |
| df-emitter build | PASS | sccap-df-emitter:dev built successfully |
| gitleaks | SKIP | not installed on host; CI-only tool |
| bandit | SKIP | no Python touched; pre-existing CI toolchain |
| pip-audit | SKIP | no Python touched; pre-existing CI toolchain |
| npm lint/build | SKIP | frontend untouched |

## Detailed Findings

### mypy (pre-existing failures, not this change)

The mypy check shows pre-existing type-checking errors unrelated to this change (no Python files were modified). These are known issues in the codebase. Since the plan expected pass-through on mypy and no Python was touched, this is acceptable.

### Loki Configuration Failure

**Status: FAIL**

The `loki/loki-config.yaml` created in this change has a configuration incompatibility with Grafana Loki 3.4.2:

**Error:**
```
failed parsing config: /etc/loki/loki-config.yaml: yaml: unmarshal errors:
  line 42: field chunks_directory not found in type local.FSConfig
```

**Root cause:** Line 42 uses `chunks_directory` which is Loki 2.x syntax. Loki 3.4 requires `directory` instead.

**Additional issue:** Line 55 sets `allow_structured_metadata: true` which is incompatible with the `boltdb-shipper` storage backend in Loki 3.4. This combination requires the newer `tsdb` index type.

**Required fixes:**
1. Change line 42 from `chunks_directory: /loki/chunks` to `directory: /loki/chunks`
2. Change line 56 from `allow_structured_metadata: true` to `allow_structured_metadata: false`

### Fluentd Dry-Run (PASS)

The fluentd configuration passes validation when tested against the locally-built image (`sccap-fluentd:local`) which includes the necessary plugins (`fluent-plugin-multi-format-parser`, `fluent-plugin-grafana-loki`).

Output shows:
- All filters and matches parsed correctly
- Buffer settings (`total_limit_size 2GB`, `overflow_action drop_oldest_chunk`, `retry_max_times 600`) are valid
- ERROR label routing is properly configured

### Docker Compose Config (PASS)

`docker compose config -q` passed with only a benign unset warning (pre-existing) about `VITE_ALLOWED_HOSTS`.

### Setup.sh Syntax (PASS)

Bash syntax check (`bash -n setup.sh`) passed with no errors. The new daemon.json handling logic is syntactically valid.

### df-emitter Build (PASS)

The locally-built sidecar (`sccap-df-emitter:dev`) builds successfully from `tools/df-emitter/Dockerfile`, proving the context is self-contained.

## Test Results

**pytest:** 197 passed, 1 skipped in 6.31 seconds (expected pass-through since no Python was touched).

## Verification Summary

- **Infrastructure gates:** 4 of 5 load-bearing config gates pass; 1 **FAIL** (Loki config schema).
- **Code quality gates:** ruff/black pass (expected); mypy has pre-existing errors unrelated to this change; pytest passes.
- **Security gates:** gitleaks/bandit/pip-audit skipped (host environment limitation; CI-only); no Python files touched so these are lower priority for this ops-focused change.

## Recommendation

**OVERALL: FAIL — fix Loki config**

The `loki/loki-config.yaml` must be corrected before merge to ensure the Loki service can start with the new configuration. Two simple field renames are required (documented above).

All other gates pass. Once the Loki config is fixed, re-run the -verify-config test to confirm before merge.

---

## Re-verify after fix (orchestrator-applied)

Two field changes in `loki/loki-config.yaml`:

- `storage_config.filesystem.chunks_directory` → `directory` (Loki 3.x rename)
- `limits_config.allow_structured_metadata: true` → `false` (boltdb-shipper compatibility; tsdb upgrade deferred)

Re-ran the failing gate:

```
$ docker run --rm -v "$PWD/loki:/etc/loki" -e LOKI_RETENTION_DAYS=30d \
    grafana/loki:3.4.2 -verify-config \
    -config.file=/etc/loki/loki-config.yaml -config.expand-env=true
level=info caller=main.go:87 msg="config is valid"
```

`docker compose config -q` and `bash -n setup.sh` re-confirmed to ensure the fix didn't drift other configs.

**OVERALL after fix: PASS** (excluding pre-existing mypy errors unrelated to this change).
