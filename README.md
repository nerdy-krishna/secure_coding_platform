# Secure Coding Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
The Secure Coding Platform is an open-source, AI-powered platform designed to assist developers and security teams in building and maintaining secure software by providing proactive security guidance, secure code generation, and vulnerability detection/remediation across multiple programming languages and compliance frameworks.

## ✨ Core Concepts
This platform leverages a hybrid approach:
* **Proactive Security Guidance**: Interactive chat guiding users on development policies for specific scenarios based on selectable security frameworks.
* **Secure Code Generation**: AI-driven code generation adhering to selected security frameworks by default.
* **Comprehensive Vulnerability Detection & Remediation**: A multi-path analysis engine (Contextual AI with RAG, SAST/SCA tools, dynamic Tree-sitter queries) for in-depth code scanning.
* **Multi-Framework Compliance**: Explicit mapping of findings and fixes to controls from numerous standards (OWASP Top 10, ASVS, NIST SSDF/CSF, PCI DSS, HIPAA, GDPR, ISO, etc.).
* **Large Codebase Management**: Strategies for handling large codebases using "repomap" context and intelligent chunking.

## 🚀 Key Features (Full Scope Vision)
* Interactive Chat Interfaces for guideline provision and secure code generation.
* Comprehensive Code Analysis Portal for submitting single files, multiple files, or entire projects (upload/Git).
* Multi-path analysis: Contextual AI (LLM with RAG), integrated security tools (Semgrep, Dependency-Check), and custom Tree-sitter queries.
* Automated and suggested code remediation.
* Dynamic conflict resolution between analysis agents.
* Unit test generation for proposed fixes.
* GRC-like requirement analysis chat.
* Rich reporting: Unified detailed reports, SARIF output, side-by-side diffs, agent-inserted comments.
* Multi-agent system using LangGraph for specialized, framework-aware analysis.

## 🛠️ Technology Stack
* **Backend**: Python, FastAPI (REST & WebSockets)
* **Frontend**: React with TypeScript, Ant Design (AntD)
* **Agent Framework**: LangGraph
* **Databases**: PostgreSQL (primary), ChromaDB (vector DB for RAG)
* **Message Queue**: RabbitMQ
* **Parsing**: Tree-sitter
* **Deployment**: Docker, Docker Compose
* **Documentation**: Docusaurus

## 📈 Current Status & Progress
This project is being developed with a "full scope from day 1" philosophy for open-source release.

**Sprint 1: Core Platform & Authentication Backbone - LARGELY COMPLETE**
* ✅ Project Setup (GitHub, Poetry, Vite, Docusaurus, .gitignore)
* ✅ Backend Core - Database (Models, engine, session, CRUD placeholder, Alembic migrations for core tables & users link)
* ✅ Backend Core - Authentication (FastAPI Users: models, schemas, db adapter, manager, JWT backend with cookie refresh, core, main.py integration - tested)
* ✅ LLM Abstraction Layer (providers, client - supporting OpenAI & Gemini)
* ✅ Basic API Endpoints (`/analyze` submission & `/results/{id}` retrieval structure)
* ✅ Basic API Graph (`api_graph.py` for DB save & RabbitMQ publish)
* ✅ Basic Worker & Graph (`consumer.py`, `worker_graph.py` for RabbitMQ consume, dummy report generation & DB save - tested end-to-end)
* 🚧 **Initial Documentation (Docusaurus `sidebars.js`, initial markdown) - IN PROGRESS**
* 🚧 **Populate README.md - IN PROGRESS**
* 🔜 Frontend Core (Ant Design basic layout, Login/Register pages)

*(Refer to the project plan document for detailed sprint goals and the full envisioned scope.)*

## 🏃 Getting Started
Please refer to the [Installation Guide](./docs/docs/getting-started/installation.md) in our documentation for instructions on how to set up and run the platform locally using Docker Compose.

## 🤝 Contributing
We welcome contributions! Please see `CONTRIBUTING.md` (to be created) for guidelines. Our `CODE_OF_CONDUCT.md` (to be created) outlines our community standards.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.