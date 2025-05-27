# Dockerfile
FROM python:3.12-slim-bookworm AS base

# Set environment variables to prevent Python from writing .pyc files and to keep Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set Poetry version (align with what you might use or a known good version)
ENV POETRY_VERSION=1.8.3
# Or, if you want to use the version from your pyproject.toml build-system requires:
# ARG POETRY_CORE_VERSION=1.5.0 # Example, adjust if your pyproject.toml differs

# Install system dependencies that might be needed for some Python packages
# build-essential contains compilers like gcc, g++ etc.
# libpq-dev would be for psycopg2 if not using binary, but we use psycopg2-binary
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    # Add other system dependencies here if needed by your Python packages
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install "poetry==${POETRY_VERSION}"
# RUN pip install "poetry-core==${POETRY_CORE_VERSION}" # Alternative if pinning poetry-core

# Set the working directory in the container
WORKDIR /app

# Copy only the files necessary for dependency installation to leverage Docker cache
COPY pyproject.toml poetry.lock ./

# Configure Poetry to not create virtual environments within the project directory inside the container
RUN poetry config virtualenvs.create false && poetry config virtualenvs.in-project false

# Install project dependencies.
# --no-root: Do not install the project itself (as we'll COPY the src later)
# --no-interaction --no-ansi: Good for CI/build environments
# Add --only main if you want to exclude dev dependencies in the final image,
# but for a dev/testing image, including them might be fine or use multi-stage builds.
# For now, let's install all dependencies including dev for easier debugging if needed inside container.
RUN poetry install --no-interaction --no-ansi
# Removed --no-root to ensure the app package itself is known

# Copy the rest of the application source code into the container
COPY ./src /app/src
COPY .env.example /app/.env.example
# COPY .env /app/.env # Generally, .env is not copied into the image; it's provided at runtime.

# The port the application will listen on (for documentation, actual port mapping is in docker-compose.yml)
# Ensure this matches the port Uvicorn will use (from APP_PORT in .env, default 8000)
EXPOSE 8000

# The command to run the application will be specified in docker-compose.yml,
# overriding any CMD here. If you needed a default CMD for running the image directly:
# CMD ["poetry", "run", "uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000"]