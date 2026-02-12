# Project Structure

## Directory Tree

```
.
├── .agent/                 # Agent workflows and recovery data
├── .github/                # GitHub specific configurations
├── alembic/                # Database migrations (Versions & Env)
├── docker-compose.yml      # Service Orchestration
├── secure-code-ui/         # Frontend Application (React/Vite)
│   ├── Dockerfile
│   ├── src/
│   │   ├── app/            # App Providers & Styles
│   │   ├── features/       # Auth, Dashboard, Results, Submission
│   │   ├── pages/          # Route Views (Auth, Admin, Analysis)
│   │   ├── shared/         # API, Components, Hooks, Lib, Types
│   │   ├── main.tsx        # Entry Point
│   │   └── vite-env.d.ts
│   └── vite.config.ts
├── src/                    # Backend Application (FastAPI)
│   └── app/
│       ├── api/v1/         # Routers, Models, Dependencies
│       ├── core/           # Config, Logging, Schemas, Services
│       ├── infrastructure/ # Auth, DB, Agents, LLM Clients
│       ├── shared/         # Utility Libraries
│       ├── workers/        # Consumer (RabbitMQ)
│       └── main.py         # App Entry Point
├── poetry.lock             # Backend Lock File
└── pyproject.toml          # Backend Project Config
```

## File Dictionary

### Root
- **docker-compose.yml**: Orchestration for App, DB, RabbitMQ, VectorDB, OpenSearch, Fluentd, and UI.
- **pyproject.toml**: Python backend dependencies and configuration.
- **alembic.ini**: Database migration configuration.
- **.env**: Environment variables for secrets and service configuration.

### Backend (`src/app`)
- **main.py**: FastAPI application entry point, middleware, and router inclusion.
- **api/v1/**:
    - **routers/**: Endpoint definitions (auth, projects, chat, admin).
    - **models.py**: API-specific data models.
    - **dependencies.py**: Dependency injection (e.g., auth, db session).
- **core/**:
    - **config.py**: Application settings loading.
    - **logging_config.py**: Logging setup.
    - **schemas.py**: Pydantic models for request/response validation.
    - **services/**: Business logic (ScanService, ChatService, RAGService).
- **infrastructure/**:
    - **auth/**: Authentication backend (FastAPI Users, JWT).
    - **db/**: Database connection and session management.
    - **llm/**: Clients for LLM providers (OpenAI, Anthropic, etc.).
    - **agents/**: LangChain agents for specific tasks (Analysis, Remediation).
    - **repositories/**: Data access layer.
- **workers/**:
    - **consumer.py**: RabbitMQ consumer for asynchronous scan processing.
- **shared/**:
    - **lib/**: Utility modules (git, encryption, file handling).

### Frontend (`secure-code-ui`)
- **src/**:
    - **main.tsx**: React application entry point.
    - **app/**:
        - **App.tsx**: Main component structure.
        - **providers/**: Context providers (Auth, Theme).
        - **styles/**: Global CSS and theme definitions.
    - **features/**:
        - **auth/**: Login/Register forms and logic.
        - **dashboard/**: Main dashboard widgets and layout.
        - **results-display/**: Scan results visualization (FileTree, CodeViewer).
        - **submission-history/**: List of past scans.
        - **submit-code/**: Forms for submitting code/repos.
    - **pages/**:
        - **auth/**: Login/Register pages.
        - **submission/**: Project submission flow.
        - **analysis/**: Analysis results view.
        - **admin/**: Administration panels.
    - **shared/**:
        - **api/**: Axios client and API service modules.
        - **components/**: Reusable UI components (Buttons, Cards).
        - **hooks/**: Custom React hooks (useAuth, useToast).
        - **lib/**: Utility functions (severityMappings, formatters).
        - **types/**: TypeScript type definitions (API models).
- **Dockerfile**: Docker configuration for the frontend service.
- **vite.config.ts**: Vite build configuration.
