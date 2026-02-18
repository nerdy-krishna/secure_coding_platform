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

# --- Create a non-root user ---
ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /bin/bash ${APP_USER}

# Set the working directory
WORKDIR /app

# Change ownership of /app to the new user
RUN chown -R ${APP_USER}:${APP_USER} /app

# Switch to the non-root user for all subsequent commands
USER ${APP_USER}

# Copy dependency files first to leverage Docker cache
COPY --chown=${APP_USER}:${APP_USER} pyproject.toml poetry.lock ./

# --- START: FIX ---
# Create a project-local configuration. 
# We enable virtualenvs to avoid conflicts with system packages (PEP 668).
RUN poetry config virtualenvs.create true --local \
    && poetry config virtualenvs.in-project true --local
# --- END: FIX ---

# Install dependencies as user.
RUN poetry install --no-interaction --no-ansi

# Copy the rest of the application source code
COPY --chown=${APP_USER}:${APP_USER} ./src /app/src
COPY --chown=${APP_USER}:${APP_USER} .env.example /app/.env.example

# Set PYTHONPATH for the non-root user
# Set PYTHONPATH for the non-root user
ENV PYTHONPATH=/app/src
# Add the virtual environment to the PATH so we don't need 'poetry run' for everything
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000