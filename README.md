# Secure Coding Platform

**An open-source, AI-powered platform to build and maintain secure software with confidence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
The Secure Coding Platform assists developers and security teams by providing proactive security guidance, generating secure code, and detecting/remediating vulnerabilities across multiple programming languages and compliance frameworks. It leverages a hybrid AI approach, integrating Large Language Models, specialized security tools, and dynamic Tree-sitter queries.

## 📚 Documentation

**For full, detailed documentation, please visit our [Docusaurus Documentation Site](./docs/docs/intro.md).** (TODO: Replace this link with your live documentation site URL once deployed. For now, it links to the intro file in the repository).

## 🌟 Key Features

Our platform is being built with a "full scope from day 1" philosophy and includes:

* **Interactive Chat Interfaces**:
    * Guideline Provision: Get guidance on development policies for specific scenarios based on selectable security frameworks.
    * Secure Code Generation: AI-driven code generation adhering to selected security frameworks.
    * GRC-like Requirement Analysis: Elicit project details to generate reports on applicable security frameworks and compliance needs.
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

* **Backend**: Python, FastAPI (REST & WebSockets)
* **Frontend**: React with TypeScript, Ant Design (AntD)
* **Agent Framework**: LangGraph
* **Databases**: PostgreSQL (primary), ChromaDB (vector DB for RAG)
* **Message Queue**: RabbitMQ
* **Parsing**: Tree-sitter
* **Deployment**: Docker, Docker Compose
* **Documentation**: Docusaurus

## 🚀 Getting Started

To get a local instance of the Secure Coding Platform up and running, please follow our detailed **[Installation Guide](./docs/docs/getting-started/installation.md)**.

## 📈 Current Status & Progress (Sprint 1: Largely Complete)

This project is being actively developed. Here's a snapshot of our recent progress:

**Sprint 1: Core Platform & Authentication Backbone - LARGELY COMPLETE**
* ✅ Project Setup (GitHub, Poetry, Vite, Docusaurus, .gitignore)
* ✅ Backend Core - Database (Models, engine, session, CRUD placeholder, Alembic migrations for core tables & users link)
* ✅ Backend Core - Authentication (FastAPI Users: models, schemas, db adapter, manager, JWT backend with cookie refresh, core, main.py integration - tested)
* ✅ LLM Abstraction Layer (providers, client - supporting OpenAI & Gemini)
* ✅ Basic API Endpoints (`/analyze` submission & `/results/{id}` retrieval structure)
* ✅ Basic API Graph (`api_graph.py` for DB save & RabbitMQ publish)
* ✅ Basic Worker & Graph (`consumer.py`, `worker_graph.py` for RabbitMQ consume, dummy report generation & DB save - tested end-to-end)
* ✅ Initial Documentation (Docusaurus file structure, `sidebars.js`, `intro.md`, `installation.md`, `configuration.md` refined)
* ✅ `README.md` updated.
* ✅ Frontend Core (Ant Design basic layout, Login/Register pages - Implemented & Tested)

*(Refer to the project plan document or project board for detailed sprint goals and the full envisioned scope.)*

## 🤝 Contributing

We welcome contributions from the community! Whether it's reporting bugs, suggesting features, improving documentation, or writing code, your help is appreciated.

Please see our [**CONTRIBUTING.md**](./CONTRIBUTING.md) (to be created/fleshed out) for guidelines on how to contribute.
We also adhere to a [**CODE_OF_CONDUCT.md**](./CODE_OF_CONDUCT.md) (to be created/fleshed out) to ensure a welcoming and inclusive environment.

## 📄 License

This project is licensed under the MIT License. See the [**LICENSE**](./LICENSE) file for full details.