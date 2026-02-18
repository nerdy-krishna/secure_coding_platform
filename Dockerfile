# Dockerfile
FROM python:3.12-slim-bookworm AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set Poetry version
ENV POETRY_VERSION=1.8.3

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install "poetry==${POETRY_VERSION}"

# Set the working directory
WORKDIR /app

# --- Create a non-root user ---
ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /bin/bash ${APP_USER}

# Copy dependency files first to leverage Docker cache
COPY pyproject.toml poetry.lock ./

# --- START: FIX ---
# Create a project-local configuration. This will be respected by all users (root and appuser).
# This command creates a poetry.toml file in the current directory (/app).
RUN poetry config virtualenvs.create false --local
# --- END: FIX ---

# Install dependencies as root. They will be installed to the system Python,
# which the appuser will have access to.
RUN pip install --upgrade pip setuptools wheel
# Force uninstall conflicting system packages to allow Poetry to install its specific versions
RUN pip uninstall -y idna charset-normalizer || true
RUN poetry install --no-interaction --no-ansi

# Copy the rest of the application source code
COPY ./src /app/src
COPY .env.example /app/.env.example

# Change ownership of the entire /app directory to the new non-root user
RUN chown -R ${APP_USER}:${APP_USER} /app

# Switch to the non-root user for all subsequent commands
USER ${APP_USER}

# Set PYTHONPATH for the non-root user
ENV PYTHONPATH=/app/src

EXPOSE 8000