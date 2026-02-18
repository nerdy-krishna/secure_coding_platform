---
sidebar_position: 1
title: Installation Guide
---

# Installation Guide

The Secure Coding Platform is designed for local setup and deployment using Docker and Docker Compose. This guide will walk you through the process.

## Prerequisites

Before you begin, ensure you have the following installed and configured on your system:

* **Docker Engine**: Make sure Docker is installed and the Docker daemon is running.
    * *Download*: [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose for Mac and Windows).
* **Docker Compose**:
    * Usually included with Docker Desktop.
    * For Linux, if it's not included or you need a specific version, follow the [official Docker Compose installation guide](https://docs.docker.com/compose/install/).
* **Git**: Required for cloning the project repository.
    * *Download*: [Git](https://git-scm.com/downloads).
* **Code Editor**: A code editor like VS Code, Sublime Text, or others for viewing and editing configuration files.
* **(Optional for specific host commands) Python & Poetry**: If you plan to run backend commands (like Alembic migrations) directly on your host machine instead of inside Docker (not recommended for initial setup), you'll need Python (version 3.12+) and Poetry installed.


## Quick Start (Recommended)

The easiest way to get started is by using the automated setup script. This script handles prerequisite checks, environment configuration (generating secure keys), Docker build, database initialization, and UI dependency installation.

### macOS / Linux

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/nerdy-krishna/secure_coding_platform.git
    cd secure_coding_platform
    ```

2.  **Run the Setup Script**:
    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```

### Windows

1.  **Clone the Repository**:
    ```powershell
    git clone https://github.com/nerdy-krishna/secure_coding_platform.git
    cd secure_coding_platform
    ```

2.  **Run the Setup Script**:
    Double-click `setup.bat` or run it from the command line:
    ```cmd
    setup.bat
    ```

Once the script completes, you will see a "Setup Complete!" message with the URLs for the application and Grafana.

---

## Cloud Deployment / Linux VPS (Fresh Install)

If you are deploying to a fresh Linux virtual machine (e.g., AWS EC2, DigitalOcean Droplet, Google Compute Engine) running Ubuntu or Debian, follow these comprehensive steps to prepare the system and install the platform.

### 1. Update System Packages
Ensure your system is up to date:
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Dependencies (Git, Python, Node.js)
The setup script requires Git (to clone), Python 3 (to generate secure secrets), and Node.js (to install frontend dependencies).
```bash
sudo apt install -y git python3 python3-venv curl
# Install Node.js (LTS version recommended)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 3. Install Docker & Docker Compose
We recommend using the official Docker installation script for the latest version.
```bash
# Download and run the Docker installation script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your current user to the 'docker' group (avoids using sudo for docker commands)
sudo usermod -aG docker $USER

# Apply group changes immediately
newgrp docker
```

### 4. Clone and Install
Now that all dependencies are ready, clone the repository and run the setup script.

```bash
git clone https://github.com/nerdy-krishna/secure_coding_platform.git
cd secure_coding_platform
chmod +x setup.sh
./setup.sh
```

---

## Manual Installation Steps


1.  **Clone the Repository**:
    Open your terminal and clone the Secure Coding Platform repository:
    ```bash
    git clone https://github.com/nerdy-krishna/secure_coding_platform.git
    cd secure-code-platform
    ```
    Replace the URL with the actual link to the project's GitHub repository.

2.  **Create and Configure the Environment File (`.env`)**:
    The platform uses a `.env` file in the project root for configuration.
    * Copy the example environment file to a new `.env` file:
        ```bash
        cp .env.example .env
        ```
        If `.env.example` is not available (it should be committed to your repository), you'll need to create `.env` manually based on the requirements below.
    * **Edit the `.env` file** with your preferred text editor. Pay close attention to the following critical variables:
        * `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`: Credentials for the PostgreSQL database.
        * `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS`: Credentials for RabbitMQ.
        * `SECRET_KEY`: **Crucial for security.** Generate a strong, unique random string (e.g., using a password manager or the command `openssl rand -hex 32`).
        * `OPENAI_API_KEY` and/or `GOOGLE_API_KEY`: API keys for the LLM providers you intend to use.
        * `APP_PORT`: The port on your host machine that will map to the backend application (default is usually `8000`).
        * `ALLOWED_ORIGINS`: A comma-separated list of origins allowed for CORS (e.g., `http://localhost:5173` for the default frontend development server).
    * For a detailed explanation of all environment variables, please refer to the [**Configuration**](./configuration.md) page.

3.  **Build and Run Services with Docker Compose**:
    From the project root directory (`secure-code-platform`), execute the following command:
    ```bash
    docker-compose up --build -d
    ```
    This command will:
    * `--build`: Build the Docker image for the application and worker services as defined in the `Dockerfile` (if they haven't been built before or if the `Dockerfile` has changed).
    * Pull the official images for PostgreSQL, RabbitMQ, and ChromaDB if they are not already present locally.
    * Create and start all services (application, worker, database, message queue, vector database) in detached mode (`-d`), meaning they will run in the background.
    * The initial build process might take a few minutes depending on your internet connection and system resources.

4.  **Initialize the Database Schema (First-Time Setup)**:
    Once the services are running (especially the `db` service), you need to apply the database migrations to set up the necessary tables. The recommended way to do this is by executing the command within the running application container:
    ```bash
    docker-compose exec app poetry run alembic upgrade head
    ```
    This ensures the migration runs in the correct environment with all dependencies.
    * Wait for the `db` container to be healthy before running this. You can check its status with `docker-compose ps`.
    * If this command fails, check the logs using `docker-compose logs app` and `docker-compose logs db`.

## Verifying the Installation

After completing the steps above, you can verify that the platform is running correctly:

1.  **Check Docker Containers**:
    Run `docker-compose ps`. All services (`app`, `worker`, `db`, `rabbitmq`, `vector_db`) should have a status of `Up` or `healthy`.

2.  **Access the Backend API**:
    * The FastAPI backend should be available at `http://localhost:<APP_PORT>` (e.g., `http://localhost:8000` if `APP_PORT=8000` in your `.env`).
    * You can access the API documentation (Swagger UI) at `http://localhost:<APP_PORT>/docs` (e.g., `http://localhost:8000/docs`). This page should load and show the available API endpoints.

3.  **Access the Frontend Application**:
    * The React frontend (served by Vite) will be available on its configured port, typically `http://localhost:5173` (check your `secure-code-ui` setup if you changed the port).

4.  **Check RabbitMQ Management UI**:
    * You can monitor RabbitMQ queues and exchanges via its management interface at `http://localhost:<RABBITMQ_MANAGEMENT_PORT>` (e.g., `http://localhost:15672`, using the RabbitMQ credentials from your `.env` file).

## Stopping the Platform Services

To stop all running services defined in `docker-compose.yml`:
```bash
docker-compose down
```
This command stops and removes the containers. Your data stored in Docker volumes (like PostgreSQL data) will persist unless you explicitly remove the volumes.

## Updating the Platform

To update to the latest version of the platform:
1.  Navigate to the project root: `cd secure-code-platform`
2.  Pull the latest changes from the Git repository: `git pull origin main` (or the relevant branch)
3.  Rebuild the images if there have been changes to `Dockerfile` or application dependencies: `docker-compose up --build -d`
4.  Apply any new database migrations: `docker-compose exec app poetry run alembic upgrade head`

## Troubleshooting Common Issues

* **Port Conflicts**: If a service fails to start due to a port already being in use, you can change the host-side port mapping in your `.env` file (e.g., change `APP_PORT` or `RABBITMQ_PORT`) and then restart the services with `docker-compose up -d`.
* **Docker Daemon Not Running**: Ensure the Docker service/daemon is running on your system.
* **Insufficient Resources**: Docker might require a certain amount of RAM/CPU. If services are crashing, check Docker's resource allocation settings.
* **Build Failures**: If `docker-compose build` fails, check the output for specific errors. It could be network issues preventing dependency downloads or errors in the `Dockerfile`.
* **Service Connection Issues** (e.g., `app` can't connect to `db`):
    * Double-check your `.env` file for correct hostnames (usually the service names like `db`, `rabbitmq`), usernames, passwords, and database names.
    * Examine the logs for the affected services: `docker-compose logs app`, `docker-compose logs db`, `docker-compose logs worker`.
* **Alembic Errors**: Ensure the `db` service is fully up and healthy before running `alembic upgrade head`. Check database connection URLs in `.env`. The `env.py` for Alembic should correctly use these values.