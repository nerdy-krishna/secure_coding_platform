---
sidebar_position: 1
title: Installation
---

# Installation Guide

The Secure Coding Platform is designed for ease of local setup and deployment using Docker and Docker Compose.

## Prerequisites

* **Docker**: Ensure Docker is installed and running on your system. [Download Docker](https://www.docker.com/products/docker-desktop/).
* **Docker Compose**: Typically included with Docker Desktop. If not, follow the [official installation guide](https://docs.docker.com/compose/install/).
* **Git**: For cloning the repository.
* **A `.env` file**: You will need to create a `.env` file in the project root for configuration.

## Steps

1.  **Clone the Repository**:
    ```bash
    git clone [https://github.com/your-username/secure_coding_platform.git](https://github.com/your-username/secure_coding_platform.git) # Update with your repo URL
    cd secure_coding_platform
    ```

2.  **Create Environment File (`.env`)**:
    Copy the `.env.example` file (if provided, otherwise create a new `.env` file) in the project root:
    ```bash
    cp .env.example .env
    ```
    Then, edit the `.env` file to set your specific configurations, especially for:
    * `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
    * `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS`
    * `SECRET_KEY` (generate a strong random string)
    * `OPENAI_API_KEY` and/or `GOOGLE_API_KEY`
    * `APP_PORT`, `ALLOWED_ORIGINS`
    *(More details on configuration variables will be in the Configuration section).*

3.  **Build and Run Services with Docker Compose**:
    From the project root directory (`secure_coding_platform`), run:
    ```bash
    docker-compose up --build -d
    ```
    This command will:
    * Build the Docker image for the application service (if not already built or if Dockerfile changed).
    * Pull images for PostgreSQL, RabbitMQ, and ChromaDB.
    * Create and start all defined services in detached mode (`-d`).

4.  **Initialize Database Schema (First Time Setup)**:
    After the services (especially the `db` service) are up and running, apply the database migrations:
    ```bash
    poetry run alembic upgrade head
    ```
    *(Ensure you are in the project root and your Poetry environment is active, or use `docker-compose exec app poetry run alembic upgrade head` if running from within a running app container context if direct host execution is problematic).*

5.  **Accessing the Application**:
    * The FastAPI backend should be available at `http://localhost:<APP_PORT>` (e.g., `http://localhost:8000`).
    * The frontend (once developed and served) will be on its configured port (e.g., `http://localhost:5173`).
    * RabbitMQ Management UI: `http://localhost:<RABBITMQ_MANAGEMENT_PORT>` (e.g., `http://localhost:15672`).

## Stopping the Services
```bash
docker-compose down
```

## Troubleshooting
* Check service logs: `docker-compose logs &lt;service_name&gt;` (e.g., `docker-compose logs app`, `docker-compose logs db`).