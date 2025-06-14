# Configuration Guide

The Secure Coding Platform is configured primarily through environment variables defined in a `.env` file located in the project root.

> ⚠️ It is crucial to set up this file correctly before running the application.

Start by copying the example file to create your own local configuration:

```bash
cp .env.example .env
```

> ❗ **Never commit your actual `.env` file with sensitive credentials to version control.**

---

## 🔐 `ENCRYPTION_KEY` (CRITICAL)

This is the **most important secret** for your installation. It's used to encrypt and decrypt all sensitive data stored in the database — especially the LLM API keys managed via the UI.

Generate it with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then add it to your `.env` file:

```env
ENCRYPTION_KEY=your-super-secret-generated-key-goes-here
```

---

## ⚙️ General Application Settings

| Variable | Description | Example | Notes |
| -------- | ----------- | ------- | ----- |
| `APP_PORT` | Port for the backend FastAPI app | `8000` | Ensure this port is available |
| `SECRET_KEY` | Used to sign JWT tokens | `your-random-secret` | Must be unique and strong |
| `ALLOWED_ORIGINS` | Allowed origins for CORS | `http://localhost:5173` | No trailing slash |
| `ACCESS_TOKEN_LIFETIME_SECONDS` | Access token expiry time | `1800` | 30 minutes |
| `REFRESH_TOKEN_LIFETIME_SECONDS` | Refresh token lifetime | `604800` | 7 days |

---

## 🗄️ PostgreSQL Database

| Variable | Description | Example | Notes |
| -------- | ----------- | ------- | ----- |
| `POSTGRES_USER` | DB username | `devuser_scp` | |
| `POSTGRES_PASSWORD` | DB password | `yoursecurepassword` | |
| `POSTGRES_DB` | DB name | `securecodedb_dev` | |
| `POSTGRES_HOST` | Host (for internal services) | `db` | Should match `docker-compose` service name |
| `POSTGRES_PORT` | Internal container port | `5432` | Default PostgreSQL port |
| `POSTGRES_PORT_HOST` | Local port mapped to PostgreSQL | `5432` | For connecting from local tools |
| `POSTGRES_HOST_ALEMBIC` | Host for Alembic (from CLI) | `localhost` | Always `localhost` for migrations |

---

## 📬 RabbitMQ Message Queue

| Variable | Description | Example |
| -------- | ----------- | ------- |
| `RABBITMQ_DEFAULT_USER` | RabbitMQ username | `devuser_scp` |
| `RABBITMQ_DEFAULT_PASS` | RabbitMQ password | `yoursecurepassword` |
| `RABBITMQ_HOST` | RabbitMQ host (internal) | `rabbitmq` |
| `RABBITMQ_PORT` | AMQP port | `5672` |
| `RABBITMQ_MANAGEMENT_PORT` | Port for RabbitMQ UI | `15672` |
| `CODE_QUEUE` | Queue name for analysis tasks | `code_analysis_queue` |

---

## 🧠 ChromaDB Vector Database

| Variable | Description | Example |
| -------- | ----------- | ------- |
| `CHROMA_PORT_HOST` | Local port mapped to ChromaDB | `8001` |
| `CHROMA_HOST` | Internal hostname | `vector_db` |
| `CHROMA_PORT` | Internal container port | `8000` |

---

## 🤖 LLM Provider Configuration (Major Change)

> **LLM API keys are no longer configured via the `.env` file.**

The platform now includes a secure **dynamic LLM configuration UI**.

After launching the app and logging in as a **superuser**, you can:

- Add/remove LLM providers (e.g., OpenAI, Google, Anthropic)
- Enter API keys securely (encrypted with your `ENCRYPTION_KEY`)
- Manage model-specific settings

This approach ensures greater **security** and **flexibility** — and keeps secrets out of source-controlled config files.

---

Happy configuring! 🎛️
