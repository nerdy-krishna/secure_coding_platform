---
sidebar_position: 2
title: Configuration
---

# Configuration Guide

The Secure Coding Platform is configured primarily through environment variables defined in a `.env` file located in the project root directory (`secure-code-platform/.env`).

It is crucial to set up this file correctly before running the application. You should copy the `.env.example` file to `.env` and then modify the values as needed.

```bash
cp .env.example .env
```

Below is a list of environment variables used by the platform, their purpose, and example values. **Never commit your actual `.env` file with sensitive credentials to version control.**

## General Application Settings

| Variable          | Description                                                                                                | Example                                  | Notes                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------ |
| `APP_PORT`        | The port on which the backend FastAPI application will listen.                                               | `8000`                                   | Ensure this port is free on your host.                                     |
| `ENVIRONMENT`     | Sets the runtime environment. Affects things like debug mode, logging levels.                                | `development` or `production`            | Defaults to `development` if not set in some contexts.                   |
| `SECRET_KEY`      | **Critical for security.** Used for signing JWTs, session data, password recovery tokens, etc.             | `your-super-strong-random-secret-string` | Must be a long, random, and unique string. Use `openssl rand -hex 32`. |
| `ALLOWED_ORIGINS` | Comma-separated list of frontend origins allowed to make CORS requests to the backend API.                   | `http://localhost:5173,http://127.0.0.1:5173` | No trailing slashes. Important for frontend-backend communication.         |

## PostgreSQL Database

These variables configure the connection to the PostgreSQL database used by the application and Alembic migrations.

| Variable             | Description                                     | Example        | Notes                                   |
| -------------------- | ----------------------------------------------- | -------------- | --------------------------------------- |
| `POSTGRES_HOST`      | Hostname of the PostgreSQL server.              | `db`           | Use `db` when running via Docker Compose. |
| `POSTGRES_PORT`      | Port of the PostgreSQL server.                  | `5432`         | Default PostgreSQL port.                |
| `POSTGRES_USER`      | Username for the PostgreSQL database.           | `devuser`      |                                         |
| `POSTGRES_PASSWORD`  | Password for the PostgreSQL user.               | `yoursecurepassword` | Change from default.                    |
| `POSTGRES_DB`        | Name of the PostgreSQL database to connect to.  | `securecodedb` |                                         |

## RabbitMQ Message Queue

Configuration for the RabbitMQ service used for asynchronous task queuing.

| Variable                   | Description                                          | Example        | Notes                                   |
| -------------------------- | ---------------------------------------------------- | -------------- | --------------------------------------- |
| `RABBITMQ_HOST`            | Hostname of the RabbitMQ server.                     | `rabbitmq`     | Use `rabbitmq` for Docker Compose.      |
| `RABBITMQ_PORT`            | AMQP port for RabbitMQ.                              | `5672`         | Default AMQP port.                      |
| `RABBITMQ_MANAGEMENT_PORT` | Port for the RabbitMQ Management UI on the host.     | `15672`        |                                         |
| `RABBITMQ_DEFAULT_USER`    | Username for RabbitMQ.                               | `devuser`      |                                         |
| `RABBITMQ_DEFAULT_PASS`    | Password for the RabbitMQ user.                      | `yoursecurepassword` | Change from default.                    |
| `CODE_QUEUE`               | Name of the RabbitMQ queue for code analysis tasks.  | `code_review_queue` |                                         |

## ChromaDB Vector Database

Configuration for the ChromaDB service used for Retrieval Augmented Generation (RAG).

| Variable                   | Description                                                        | Example             | Notes                                   |
| -------------------------- | ------------------------------------------------------------------ | ------------------- | --------------------------------------- |
| `CHROMA_SERVER_HOST`       | Hostname for the ChromaDB server within the Docker network.        | `vector_db`         | Service name from `docker-compose.yml`. |
| `CHROMA_SERVER_HTTP_PORT`  | Port on which ChromaDB listens inside its container.               | `8000`              | This is internal to ChromaDB.           |
| `IS_PERSISTENT`            | Enables data persistence for ChromaDB.                             | `TRUE`              | Recommended for production.             |
| `ANONYMIZED_TELEMETRY`     | Enables/disables anonymized telemetry for ChromaDB.                | `FALSE`             | Optional.                               |
| `CHROMA_TENANT`            | Default tenant for ChromaDB (relevant for ChromaDB 0.5.x+).        | `default_tenant`    | Check ChromaDB documentation if needed. |
| `CHROMA_DATABASE`          | Default database for ChromaDB (relevant for ChromaDB 0.5.x+).      | `default_database`  | Check ChromaDB documentation if needed. |

## LLM (Large Language Model) Providers

Configuration for integrating with LLM providers.

| Variable             | Description                                                                | Example                      | Notes                                                       |
| -------------------- | -------------------------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------- |
| `LLM_PROVIDER`       | Specifies the active LLM provider.                                         | `openai` or `google_gemini`  | Currently supported: `openai`, `google_gemini`.             |
| `OPENAI_API_KEY`     | Your API key for OpenAI services.                                          | `sk-xxxxxxxxxxxxxxxxxxxxxx`  | Required if `LLM_PROVIDER=openai`.                          |
| `OPENAI_MODEL_NAME`  | The specific OpenAI model to use (e.g., GPT-4o Mini, GPT-4 Turbo).         | `gpt-4o-mini-2024-07-18`   | Ensure model compatibility.                                 |
| `GOOGLE_API_KEY`     | Your API key for Google AI (Gemini) services.                              | `AIzaSyxxxxxxxxxxxxxxxxxxx`  | Required if `LLM_PROVIDER=google_gemini`.                   |
| `GEMINI_MODEL_NAME`  | The specific Google Gemini model to use.                                   | `gemini-1.5-flash-latest`    | Ensure model availability and compatibility.                |

## Authentication (FastAPI Users & JWT)

Variables related to user authentication and session management.

| Variable                | Description                                                                | Example                      | Notes                                                                   |
| ----------------------- | -------------------------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------- |
| `REFRESH_COOKIE_NAME`   | Name for the HttpOnly refresh token cookie.                                | `mySecureAppRefreshToken`    | Optional. Defaults to `fastapiusersauth` in some FastAPI Users setups. We use `myAppRefreshToken` in our `CustomCookieJWTStrategy`. |
| `ENVIRONMENT`           | (Also listed under General) Used by `CustomCookieJWTStrategy` to set cookie `Secure` flag. | `production` or `development` | `Secure` flag for cookies set to `True` if `ENVIRONMENT=production`. |

Make sure to keep your `.env` file secure and do not commit it to your version control system. Add `.env` to your `.gitignore` file if it's not already there.