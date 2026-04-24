# syntax=docker/dockerfile:1.7
#
# Unified multi-stage Dockerfile for the Python services (API + worker).
# Build a specific service with `docker build --target api` or `--target worker`.
# docker-compose.yml drives both targets from this one file.
#
# Stage layout:
#   base           → runtime OS, non-root user, minimal apt (libpq5, ca-certs)
#   poetry-base    → base + build-essential + poetry (shared by both builders)
#   api-builder    → poetry-base + `poetry install --without dev` (no worker
#                    group) → lean venv without tree-sitter (worker-only)
#   worker-builder → poetry-base + `poetry install --without dev --with worker`
#                    → adds the tree-sitter AST stack on top of the API deps
#   api            → base + api venv + source + git binary (GitPython)
#   worker         → base + worker venv + source (no git)
#
# The dep split keeps tree-sitter + tree-sitter-languages off the API
# image. Non-root (uid 1001) everywhere. BuildKit cache mounts on
# pip/poetry keep rebuilds fast.
#
# Historical note: an `ml-assets` stage used to pre-download
# `sentence-transformers/all-MiniLM-L6-v2`. Since Phase H.1.1 we use
# ChromaDB's bundled ONNX embedder instead (lazy-downloaded to
# /home/appuser/.cache/chroma on first use), and Phase I.3 dropped
# sentence-transformers + torch entirely — so the stage went away.

# ---------- base ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /bin/bash ${APP_USER}

WORKDIR /app
RUN mkdir -p /app/.venv /app/.cache \
    && chown -R ${APP_USER}:${APP_USER} /app

# ---------- poetry-base --------------------------------------------------
# Shared base for both builders. Has build-essential (for any wheels that
# need to compile) and poetry itself. The only thing both builders do is
# copy lock + pyproject and run a tailored `poetry install`.
FROM base AS poetry-base

ENV POETRY_VERSION=1.8.3 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_VIRTUALENVS_CREATE=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "poetry==${POETRY_VERSION}"

USER appuser
COPY --chown=appuser:appuser pyproject.toml poetry.lock ./

# ---------- api-builder --------------------------------------------------
# Installs only core runtime deps (no dev group, no optional worker group).
# The worker group is `optional = true` in pyproject.toml so plain
# `poetry install` skips it by default; `--without dev` just drops the
# dev tools.
FROM poetry-base AS api-builder

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev

# ---------- worker-builder -----------------------------------------------
# Installs core + the worker group (torch, sentence-transformers, tree-sitter).
FROM poetry-base AS worker-builder

RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev --with worker

# ---------- api ----------------------------------------------------------
FROM base AS api

# git is needed by GitPython for the repo-clone submission path in
# scan_service.create_scan_from_git.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
USER appuser

COPY --chown=appuser:appuser --from=api-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
COPY --chown=appuser:appuser ./alembic /app/alembic
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------- worker -------------------------------------------------------
FROM base AS worker

USER appuser

COPY --chown=appuser:appuser --from=worker-builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src

CMD ["python", "-m", "app.workers.consumer"]
