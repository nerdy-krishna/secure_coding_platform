# syntax=docker/dockerfile:1.7
#
# Unified multi-stage Dockerfile for the Python services (API + worker).
# Build a specific service with `docker build --target api` or `--target worker`.
# docker-compose.yml drives both targets from this one file.
#
# Stage layout:
#   base       → runtime OS, non-root user, minimal apt (libpq5, ca-certs)
#   builder    → base + build-essential + poetry; produces /app/.venv
#   ml-assets  → builder + pre-downloaded sentence-transformers cache (worker-only)
#   api        → base + venv + source + git binary (needed for GitPython repo clones)
#   worker     → base + venv + ml cache + source (no git, no build tools)
#
# Non-root (uid 1001) everywhere, including the worker image. BuildKit cache
# mounts speed up rebuilds. Runtime stages don't ship build-essential, git
# (worker), or poetry — they're only present where genuinely needed.

# ---------- base ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH" \
    HF_HOME=/app/.cache/huggingface \
    SENTENCE_TRANSFORMERS_HOME=/app/.cache/sentence-transformers

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

# ---------- builder ------------------------------------------------------
# Has the C toolchain and poetry. Its only output is /app/.venv, which
# later stages COPY --from=builder into slimmer runtime images.
FROM base AS builder

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

# Install runtime deps only (drop the dev group). The committed lock file
# is authoritative — no `poetry lock --no-update` at build time.
RUN --mount=type=cache,target=/home/appuser/.cache/pypoetry,uid=1001,gid=1001 \
    --mount=type=cache,target=/home/appuser/.cache/pip,uid=1001,gid=1001 \
    poetry install --no-interaction --no-ansi --no-root --without dev

# ---------- ml-assets ----------------------------------------------------
# Pre-downloads the embedding model used by the RAG preprocessor. Only the
# worker image copies from this stage; the API doesn't need the model at
# startup.
FROM builder AS ml-assets

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# ---------- api ----------------------------------------------------------
FROM base AS api

# git is needed by GitPython for the repo-clone submission path in
# scan_service.create_scan_from_git.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
USER appuser

COPY --chown=appuser:appuser --from=builder /app/.venv /app/.venv
COPY --chown=appuser:appuser ./src /app/src
COPY --chown=appuser:appuser ./alembic /app/alembic
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------- worker -------------------------------------------------------
FROM base AS worker

USER appuser

COPY --chown=appuser:appuser --from=builder /app/.venv /app/.venv
COPY --chown=appuser:appuser --from=ml-assets /app/.cache /app/.cache
COPY --chown=appuser:appuser ./src /app/src

CMD ["python", "-m", "app.workers.consumer"]
