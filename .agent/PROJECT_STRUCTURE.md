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
    - **services/**: Business logic (ScanService, ChatService, RAGService, SecurityStandardsService).
- **infrastructure/**:
    - **auth/**: Authentication backend (FastAPI Users, JWT).
    - **db/**: Database connection and session management.
    - **llm/**: Clients for LLM providers (OpenAI, Anthropic, etc.).
    - **agents/**: LangChain agents for specific tasks (Analysis, Remediation).
    - **repositories/**: Data access layer.
- **workers/**:
    - **consumer.py**: RabbitMQ consumer for synchronous scan processing.
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

## Detailed Scanning Workflow Trace

### 1. Initiation (API Layer)
**Trigger**: User submits a scan request via the UI.
- **File**: `src/app/api/v1/routers/projects.py`
  - **Function**: `create_scan`
  - **Action**: Receives form data (files, repo URL, config) and calls the service.

### 2. Service Layer & Queuing
- **File**: `src/app/core/services/scan_service.py`
  - **Function**: `_process_and_launch_scan` (called by `create_scan_from_*`)
  - **Action**:
    1.  Persists Project, Scan, and CodeSnapshot to DB via `ScanRepository.create_scan`, `ScanRepository.create_code_snapshot`.
    2.  Publishes a message to RabbitMQ (`settings.RABBITMQ_SUBMISSION_QUEUE`) containing the `scan_id`.

### 3. Worker Consumption
- **File**: `src/app/workers/consumer.py`
  - **Function**: `start_worker_consumer` -> `pika_message_callback`
  - **Action**: Listens for messages. Upon receipt, deserializes the `scan_id` and schedules the async workflow.
  - **Function**: `run_graph_task_wrapper`
  - **Action**: Instantiates the LangGraph workflow and invokes it (`worker_workflow.ainvoke`).

### 4. Workflow Execution (The Graph)
**File**: `src/app/infrastructure/workflows/worker_graph.py` defines the state graph.

#### Node A: `retrieve_and_prepare_data_node`
- **Goal**: Build context for the scan.
- **Steps**:
  1.  Fetches `Scan` object from DB.
  2.  **Repo Mapping**: Calls `src/app/shared/analysis_tools/repository_map.py` -> `RepositoryMappingEngine.create_map` to parse files using `tree-sitter` and identify symbols (classes, functions).
  3.  **Dependency Graph**: Calls `src/app/shared/analysis_tools/context_bundler.py` -> `ContextBundlingEngine` to build a NetworkX graph of file dependencies.
  4.  **Agent Resolution**: Queries DB for agents associated with the selected `frameworks`.

#### Node B: `triage_agents_node`
- **Goal**: Efficiently route files to relevant agents.
- **LLM**: **Utility LLM**
- **Action**: For each file, sends a summary (from Repo Map) + Agent Descriptions to the LLM.
- **Output**: `triaged_agents_per_file` (e.g., "auth.py" -> [Python Security Agent, Auth Auditor]).

#### Node C: `dependency_aware_analysis_orchestrator`
- **Goal**: Run the core analysis.
- **Steps**:
  1.  Topological Sort: Determines processing order based on the Dependency Graph.
  2.  **Loop per File**:
      - **Chunking**: Calls `src/app/shared/analysis_tools/chunker.py` -> `semantic_chunker` to split large files by function boundaries.
      - **Agent Execution**: For each chunk, invokes `src/app/infrastructure/agents/generic_specialized_agent.py` -> `analysis_node`.
          - **LLM**: **Reasoning LLM**.
          - Uses RAG (Retrieval Augmented Generation) to fetch security guidelines.
          - Generates `findings` and `fixes`.
  3.  **Hybrid Mode (Remediate)**: If in `REMEDIATE` mode:
      - Calls `consolidation_node` (internal to `worker_graph.py`).
      - **Conflict Resolution**: If multiple agents suggest fixes for the same line, calls `_run_merge_agent` (using **Reasoning LLM**) to merge them.
      - Applies fixes to the file content in-memory.
      - Saves findings as "Applied".

#### Node D: `correlate_findings_node`
- **Goal**: Deduplicate findings.
- **Action**: Groups findings by `(file, cwe, line)`. Merges duplicate reports from different agents into a single high-confidence finding.

#### Node E: `save_results_node`
- **Goal**: Persistence.
- **Action**: Calls `ScanRepository.save_findings` (or `update_correlated_findings`) to write final results to Postgres.

#### Node F: `run_impact_reporting`
- **Goal**: Generate executive summary.
- **File**: `src/app/infrastructure/agents/impact_reporting_agent.py`
- **LLM**: **Reasoning LLM**.
- **Action**:
  - `generate_impact_report_node`: Summarizes findings into an executive report (Risk Score, Categories, Strategy).
  - `generate_sarif_node`: Converts findings to SARIF format for export.

#### Node G: `save_final_report_node`
- **Goal**: Finalize scan.
- **Action**: Calculates final Risk Score and updates Scan status to `COMPLETED` or `REMEDIATION_COMPLETED`.

### 5. LLM Roles Summary
- **Utility LLM**: Used in `triage_agents_node` for routing.
- **Fast LLM**: Currently reserved for future optimization (e.g., initial summarization).
- **Reasoning LLM**: Used in `generic_specialized_agent.py` (Analysis), `worker_graph.py` (Conflict Merging), and `impact_reporting_agent.py` (Executive Summary).
