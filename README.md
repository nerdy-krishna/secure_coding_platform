# Secure Coding Platform

**An open-source, AI-powered platform to build and maintain secure software with confidence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The Secure Coding Platform assists developers and security teams by providing proactive security guidance, generating secure code, and detecting/remediating vulnerabilities across multiple programming languages and compliance frameworks. It leverages a hybrid AI approach, integrating Large Language Models, specialized security tools, and dynamic Tree-sitter queries.

## 📚 Documentation

**For full, detailed documentation, please visit [Docusaurus Documentation Site](./docs/docs/intro.md).**

## 🌟 Key Features

The platform is being built with a "full scope from day one" philosophy and includes:

* **Dynamic LLM Provider Configuration**: Securely manage LLM providers (e.g., OpenAI, Google, Anthropic) and API keys through the admin dashboard instead of `.env` files. Keys are fully encrypted in the database.
* **Interactive Chat Interfaces**:

  * *Guideline Provision*: Get guidance on development policies for specific scenarios based on selectable security frameworks.
  * *Secure Code Generation*: AI-driven code generation adhering to selected security frameworks.
  * *GRC-like Requirement Analysis*: Elicit project details to generate reports on applicable security frameworks and compliance needs.
* **Comprehensive Code Analysis Portal**:

  * Submit single files, multiple files, or entire projects (via upload or Git).
  * Multi-path analysis: Contextual AI (LLM with RAG), integrated security tools (Semgrep, Dependency-Check), and custom Tree-sitter queries.
  * Automated and suggested code remediation with dynamic conflict resolution.
* **Developer-Focused Tools**:

  * Unit test generation for proposed fixes.
  * Management of large codebases via "repomap" context and intelligent chunking.
* **Rich Reporting & Compliance**:

  * Unified, detailed reports mapping findings to code.
  * Explicit mapping of findings to controls from numerous standards (OWASP Top 10, ASVS, NIST SSDF/CSF, PCI DSS, HIPAA, GDPR, ISO, etc.).
  * SARIF output, side-by-side diffs, and agent-inserted comments.

## 🛠️ Core Technology Stack

* **Backend**: Python 3.12+, FastAPI, LangGraph, LangChain
* **Frontend**: React with TypeScript, Vite, Ant Design (AntD)
* **Agent Framework**: LangGraph
* **Databases**: PostgreSQL 16 (primary), ChromaDB (vector DB for RAG)
* **Message Queue**: RabbitMQ
* **Security & Config**: `pydantic-settings`, `cryptography`
* **Parsing**: Tree-sitter
* **Deployment**: Docker, Docker Compose
* **Documentation**: Docusaurus

## 🚀 Getting Started

Follow these steps to get a local instance of the Secure Coding Platform up and running.

### 1. Initial Setup

First, clone the repository and navigate into the project directory.

### 2. Environment Configuration

The platform is configured via a `.env` file.

**a. Create the `.env` file:**
Copy the example file to create your local configuration.

```bash
cp .env.example .env
```

**b. Generate an Encryption Key:**
You must generate a secret key to encrypt sensitive data (like LLM API keys) in the database.

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**c. Update your `.env` file:**
Open the `.env` file and:

1. Paste the key you just generated as the value for `ENCRYPTION_KEY`.
2. Fill in the other required variables like `POSTGRES_USER`, `POSTGRES_PASSWORD`, etc.

> **Note**: You no longer need to add LLM API keys directly to this file. They are now managed via the application's UI after you log in as a superuser.

### 3. Launch the Platform

**a. Build and run all services:**
This command will build the Docker images and start the FastAPI app, the worker, the databases, and the message queue.

```bash
docker-compose up -d --build
```

**b. Run the Database Migration:**
After the containers are running, apply the database schema.

```bash
poetry run alembic upgrade head
```

### 4. Access the Application

You're all set!

* **Frontend UI**: [http://localhost:5173](http://localhost:5173)
* **Backend API**: [http://localhost:8000](http://localhost:8000)
* **API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)

## 📈 Current Status & Progress (Sprint 3: Complete)

This project is being actively developed. Here's a snapshot of recent progress:

**Sprint 1–3: Core Platform, Agent Refactor & LLM Config - COMPLETE**

* ✅ **Full Backend Stability:** Resolved all startup and configuration errors for both the `app` and `worker` services.
* ✅ **Dynamic LLM Configuration:** Implemented a secure API and database backend for managing LLM providers and encrypted API keys through the UI.
* ✅ **Agent & Database Refactor:** Consolidated all ORM models into a single source of truth, resolving all circular dependencies and data model inconsistencies.
* ✅ **Robust Migration System:** The Alembic migration environment is now fully functional and correctly handles the asynchronous, multi-file project structure.
* ✅ **LangChain Provider Model:** The LLM subsystem has been upgraded to a robust, LangChain-based provider model.
* ✅ **Authentication & Core Services:** The project includes a complete authentication backbone using FastAPI Users and a working asynchronous task pipeline via RabbitMQ.

## 🤝 Contributing

We welcome contributions from the community! Whether it's reporting bugs, suggesting features, improving documentation, or writing code — your help is appreciated.

Please see [**CONTRIBUTING.md**](./CONTRIBUTING.md) for guidelines.
We also adhere to a [**CODE\_OF\_CONDUCT.md**](./CODE_OF_CONDUCT.md) to ensure a welcoming and inclusive environment.

## 📄 License

This project is licensed under the MIT License. See the [**LICENSE**](./LICENSE) file for full details.